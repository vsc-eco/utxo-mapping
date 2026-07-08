package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"bytes"
	"slices"
	"strconv"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// migration.go — S2 fund migration (sweep) builder. Moves a superseded generation's
// UTXOs to the successor (active) generation's vault address, so the old key can later
// be destroyed (S5). The sweep is SIGNED by the retiring generation's keys (per input,
// via addInputsWithWitnesses) but PAYS the SUCCESSOR — the contract is consensus-
// re-executed, so the output-scoping assertion here (NN#1 Layer-1) is consensus-valid.

// getMigrationInputs returns up to MaxMigrationInputs CONFIRMED UTXOs of generation
// `gen`, their total value, and whether MORE confirmed UTXOs of that gen remain beyond
// the cap (so the caller drains it in successive tranches — the C-F brick fix). It is
// confirmed-only (THORChain guard: unconfirmed change from an in-flight tranche is swept
// once it confirms). Deterministic: iterates the registry (cs.UtxoList) in slice order.
func (cs *ContractState) getMigrationInputs(gen uint32) (inputIds []uint16, total int64, moreRemain bool, err error) {
	for i := range cs.UtxoList {
		entry := cs.UtxoList[i]
		if entry.Id < constants.UtxoConfirmedPoolStart {
			continue // confirmed-only
		}
		utxo, lerr := loadUtxo(entry.Id)
		if lerr != nil {
			return nil, 0, false, lerr
		}
		if utxo.Generation != gen {
			continue
		}
		if len(inputIds) >= constants.MaxMigrationInputs {
			moreRemain = true
			break
		}
		// Value cap (money-math lens pre-mortem): keep the tranche total ≤ MaxUtxoAmount so
		// the single consolidated sweep output fits the uint48 registry (matches the L-1
		// change cap). Without this, a tranche summing above MaxUtxoAmount could never
		// index its own output → that generation could never drain (a brick). Each deposit
		// is itself ≤ MaxUtxoAmount, so stopping here always leaves ≥1 input = a buildable
		// tranche; the overflow input drains in the next tranche.
		if len(inputIds) > 0 && total+entry.Amount > constants.MaxUtxoAmount {
			moreRemain = true
			break
		}
		inputIds = append(inputIds, entry.Id)
		total, err = safeAdd64(total, entry.Amount)
		if err != nil {
			return nil, 0, false, ce.WrapContractError(ce.ErrArithmetic, err, "migration input total overflow")
		}
	}
	return inputIds, total, moreRemain, nil
}

// AnyFundedSupersededGen reports whether any RETIRING or DRAINING generation still holds
// a registry UTXO — the NN#3 gate ("no rotation N+1 while gen N is funded", S2-close
// completeness F-1). Loads the vault list + the UTXO registry and scans. Genesis / a
// clean rotation (no superseded gens, or all drained) → false. Registry-based (S5 hardens
// the emptiness check with an SPV zero-L1 proof). Deterministic: slice scans + keyed
// loads, no map ranging.
func AnyFundedSupersededGen() (bool, error) {
	vaults, _, _, err := LoadVaultState()
	if err != nil {
		return false, err
	}
	var superseded []uint32
	for i := range vaults {
		if vaults[i].Status == VaultStatusRetiring || vaults[i].Status == VaultStatusDraining {
			superseded = append(superseded, vaults[i].Generation)
		}
	}
	if len(superseded) == 0 {
		return false, nil
	}
	utxoState := sdk.StateGetObject(constants.UtxoRegistryKey)
	if len(*utxoState) == 0 {
		return false, nil
	}
	utxos, err := UnmarshalUtxoRegistry([]byte(*utxoState))
	if err != nil {
		return false, ce.NewContractError(ce.ErrStateAccess, "error decoding utxo registry: "+err.Error())
	}
	for i := range utxos {
		utxo, lerr := loadUtxo(utxos[i].Id)
		if lerr != nil {
			return false, lerr
		}
		for _, g := range superseded {
			if utxo.Generation == g {
				return true, nil
			}
		}
	}
	return false, nil
}

// assertOutputsPaySuccessor verifies EVERY output of a sweep pays the successor vault's
// script (NN#1 Layer-1). A migration must never route funds anywhere but the successor;
// because the contract is consensus-re-executed, this assertion is consensus-validated
// even before the node-side output-scoped signing (S3) lands.
func assertOutputsPaySuccessor(tx *wire.MsgTx, successorScript []byte) error {
	if len(tx.TxOut) == 0 {
		return ce.NewContractError(ce.ErrTransaction, "migration tx has no outputs")
	}
	for _, out := range tx.TxOut {
		if !bytes.Equal(out.PkScript, successorScript) {
			return ce.NewContractError(ce.ErrTransaction, "migration output does not pay the successor vault (NN#1)")
		}
	}
	return nil
}

// buildMigrationTransaction builds a sweep spending `inputs` (all of the retiring gen)
// and paying the entire value, minus the miner fee, to a single output at
// successorAddress (the active generation's vault address). Does NOT request signing.
func (cs *ContractState) buildMigrationTransaction(inputs []*Utxo, totalInputs int64, successorAddress string) (*wire.MsgTx, map[int][]byte, int64, error) {
	tx := wire.NewMsgTx(wire.TxVersion)
	witnessScripts, err := cs.addInputsWithWitnesses(tx, inputs)
	if err != nil {
		return nil, nil, 0, err
	}

	successorAddr, err := btcutil.DecodeAddress(successorAddress, cs.NetworkParams)
	if err != nil {
		return nil, nil, 0, ce.WrapContractError(ce.ErrInput, err, "error decoding successor address")
	}
	successorScript, err := txscript.PayToAddrScript(successorAddr)
	if err != nil {
		return nil, nil, 0, err
	}

	// Single sweep output. Provisional value = total for size estimation (the value
	// field width is fixed, so setting the final value below does not change tx size).
	sweepOut := wire.NewTxOut(totalInputs, successorScript)
	tx.AddTxOut(sweepOut)

	fee, err := cs.calculateSegwitFee(int64(tx.SerializeSize()), witnessScripts)
	if err != nil {
		return nil, nil, 0, err
	}
	// V5-4 (migration-fee sanity ceiling): a rogue/glitched oracle BaseFeeRate (already
	// clamped to MaxBaseFeeRate) must not burn most of a tranche on miner fees. Reject a
	// sweep whose fee exceeds half the tranche value — fail-safe (the gen keeps these
	// UTXOs, recoverable; abort leaves no state change). A tighter economical-fraction
	// ceiling + a dust-burn / reserve-subsidy escape (V-1) for a genuinely un-sweepable
	// dust residual is deferred (S2.4-refinement / S5).
	if fee > totalInputs/2 {
		return nil, nil, 0, ce.NewContractError(ce.ErrTransaction, "migration fee exceeds half the tranche value — sweep deferred")
	}
	sendAmount, err := safeSubtract64(totalInputs, fee)
	if err != nil || sendAmount <= dustThreshold {
		// V-1 dust residual: a tranche too small to cover its own sweep fee can't be
		// migrated economically — abort (the retiring gen keeps these UTXOs, fully
		// recoverable). Dust-burn / reserve-subsidy handling is deferred (S2.4/S5).
		return nil, nil, 0, ce.NewContractError(ce.ErrBalance, "migration tranche value too small to cover the sweep fee")
	}
	sweepOut.Value = sendAmount

	// NN#1 Layer-1 (consensus-re-executed): the sole output MUST pay the successor.
	if aerr := assertOutputsPaySuccessor(tx, successorScript); aerr != nil {
		return nil, nil, 0, aerr
	}
	return tx, witnessScripts, fee, nil
}

// HandleMigrateVault sweeps ONE tranche of a retiring/draining generation's confirmed
// UTXOs to the active successor vault. Returns a txid (or a benign "nothing to migrate"
// status). Never touches the active vault's funds; never sweeps to anything but the
// consensus-derived successor address (NN#1). Any failure aborts the whole tx, so the
// retiring gen keeps its UTXOs, fully recoverable (never-brick).
func (cs *ContractState) HandleMigrateVault() (string, error) {
	// The generation to drain: a RETIRING gen (first tranche) or a DRAINING gen (a later
	// tranche). NEVER the active vault — funds only ever move OUT of a superseded gen.
	targetIdx := firstVaultWithStatus(cs.Vaults, VaultStatusRetiring)
	if targetIdx < 0 {
		targetIdx = firstVaultWithStatus(cs.Vaults, VaultStatusDraining)
	}
	if targetIdx < 0 {
		return "", ce.NewContractError(ce.ErrTransaction, "no retiring or draining vault to migrate")
	}
	targetGen := cs.Vaults[targetIdx].Generation

	// The successor is the single ACTIVE vault — never sweep to nowhere (never-brick).
	activeIdx := firstVaultWithStatus(cs.Vaults, VaultStatusActive)
	if activeIdx < 0 {
		return "", ce.NewContractError(ce.ErrTransaction, "no active successor vault to migrate into")
	}
	successorGen := cs.Vaults[activeIdx].Generation
	successorAddress, _, err := createP2WSHAddressWithBackup(
		cs.Vaults[activeIdx].Primary, cs.Vaults[activeIdx].Backup, nil, cs.NetworkParams,
	)
	if err != nil {
		return "", ce.WrapContractError(ce.ErrTransaction, err, "error deriving successor vault address")
	}

	inputIds, total, moreRemain, err := cs.getMigrationInputs(targetGen)
	if err != nil {
		return "", err
	}
	if len(inputIds) == 0 {
		// No confirmed UTXOs to sweep for this gen. It STAYS retiring/draining — still
		// fund-holding, so its address stays matchable for late deposits and its key keeps
		// renewing (never-brick). The draining→inactive→purged finalization is S5's job:
		// it needs the SPV zero-L1 proof + grace≥reorg AND the match-until-purged /
		// revert-on-late-deposit handling (S1-DESIGN §5a). Producing INACTIVE here (in S2,
		// before that consumer exists) would drop the gen out of isFundHoldingStatus and
		// reopen the C-2/NR-4 late-deposit loss — the S2-close council F-1 (fail-safe +
		// state-machine + trust-boundary). NN#3 (enforced in createKey) gates the next
		// rotation on every superseded gen being drained, so an empty draining gen never
		// blocks progress even though it is not marked inactive here.
		return "nothing to migrate for generation " + strconv.FormatUint(uint64(targetGen), 10), nil
	}

	inputUtxos, err := getInputUtxos(inputIds)
	if err != nil {
		return "", err
	}
	tx, witnessScripts, btcFee, err := cs.buildMigrationTransaction(inputUtxos, total, successorAddress)
	if err != nil {
		return "", err
	}

	// Sign each input with its (retiring) generation's keyId.
	signingData, err := signSpendTransaction(tx, inputUtxos, witnessScripts)
	if err != nil {
		return "", ce.WrapContractError(ce.ErrTransaction, err, "error signing migration sweep")
	}

	// Index the sweep output as an UNCONFIRMED UTXO tagged the SUCCESSOR gen, so once it
	// confirms it lands in the successor's registry (the C-B fix: a sweep pays the
	// successor P2WSH, which the withdrawal-change indexer would otherwise never see).
	sweepOutputs, err := indexUnconfimedOutputs(tx, successorAddress, cs.NetworkParams, successorGen)
	if err != nil {
		return "", err
	}
	for _, utxo := range sweepOutputs {
		if utxo == nil {
			continue
		}
		internalId, aerr := cs.allocateUnconfirmedId()
		if aerr != nil {
			return "", aerr
		}
		cs.UtxoList = append(cs.UtxoList, UtxoRegistryEntry{Id: internalId, Amount: utxo.Amount})
		saveUtxo(internalId, utxo)
	}

	// Remove the swept input UTXOs from the registry + state.
	for _, inputId := range inputIds {
		cs.UtxoList = slices.DeleteFunc(cs.UtxoList, func(e UtxoRegistryEntry) bool { return e.Id == inputId })
		sdk.StateDeleteObject(getUtxoKey(inputId))
	}

	// Record the pending sweep so confirmSpend can promote its output on confirmation.
	signingBytes, err := MarshalSigningData(signingData)
	if err != nil {
		return "", ce.WrapContractError(ce.ErrJson, err, "error marshalling migration signing data")
	}
	txId := tx.TxID()
	sdk.StateSetObject(constants.TxSpendsPrefix+txId, string(signingBytes))
	cs.TxSpendsList = append(cs.TxSpendsList, txId)

	// X-2 fix (S2-close money-math + trust-boundary): fund the migration miner fee from
	// FeeSupply (the protocol reserve accrued from unmap vscFees), NOT from ActiveSupply,
	// so the internal sweep is exactly Supply-neutral to USER backing and can NEVER erode
	// the solvency relation ActiveSupply ≥ UserSupply. The invariant Σ(UTXO) == ActiveSupply
	// + FeeSupply is preserved (Σ(UTXO) drops by btcFee via the sweep; FeeSupply drops by
	// btcFee here). If the reserve can't cover the fee, ABORT (fail-safe: the gen keeps its
	// UTXOs, recoverable) rather than socialize a principal loss onto the last withdrawer —
	// accumulate fees / subsidize the reserve first. safeSubtract64 catches int64 wrap; the
	// explicit < 0 check catches below-zero (money-math F-2). (A rotation fee charged to
	// users, or an explicit reserve subsidy, is the fuller coverage model; this is the
	// minimal solvency-PRESERVING version — it never lets the books lie.)
	newFee, err := safeSubtract64(cs.Supply.FeeSupply, btcFee)
	if err != nil {
		return "", ce.WrapContractError(ce.ErrArithmetic, err, "migration fee arithmetic")
	}
	if newFee < 0 {
		return "", ce.NewContractError(ce.ErrBalance, "insufficient fee reserve to fund the migration sweep")
	}
	cs.Supply.FeeSupply = newFee

	// First tranche: retiring → draining (a sweep is now in flight). Idempotent for a gen
	// already draining. Never touches keys or any other generation.
	if cs.Vaults[targetIdx].Status == VaultStatusRetiring {
		cs.Vaults[targetIdx].Status = VaultStatusDraining
	}

	sdk.Log("migrate|src=" + strconv.FormatUint(uint64(targetGen), 10) +
		"|dst=" + strconv.FormatUint(uint64(successorGen), 10) +
		"|id=" + txId +
		"|swept=" + strconv.FormatInt(total, 10) +
		"|fee=" + strconv.FormatInt(btcFee, 10) +
		"|more=" + strconv.FormatBool(moreRemain))
	return txId, nil
}
