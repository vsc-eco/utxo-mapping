package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"bytes"
	"strconv"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// constants in sats
const dustThreshold = 546

const splitThreshold = 1000000 // 0.01 BTC
const maxChangeOutputs = 4

// VscFeeMinSats is the minimum VSC protocol fee in satoshis.
const VscFeeMinSats int64 = 0

// VscFeeRateBps is the VSC protocol fee as basis points (1 bps = 0.01%).
const VscFeeRateBps int64 = 0

func calcVscFee(amount int64) (int64, error) {
	if VscFeeMinSats == 0 && VscFeeRateBps == 0 {
		return 0, nil
	}
	// divide first to avoid overflow on large amounts, then compensate for remainder
	percentageFee := (amount/10000)*VscFeeRateBps + (amount%10000)*VscFeeRateBps/10000
	finalFee := VscFeeMinSats
	if percentageFee > VscFeeMinSats {
		finalFee = percentageFee
	}
	if finalFee >= amount {
		return 0, ce.NewContractError(ce.ErrBalance, "transaction too small to cover fee")
	}
	return finalFee, nil
}

func getInputUtxos(registryEntries []uint16) ([]*Utxo, error) {
	result := make([]*Utxo, len(registryEntries))
	for i, internalId := range registryEntries {
		utxo, err := loadUtxo(internalId)
		if err != nil {
			return nil, ce.WrapContractError(ce.ErrStateAccess, err, "error loading saved utxo")
		}
		result[i] = utxo
	}
	return result, nil
}

// estimateVSize returns the estimated vSize for given non-witness and witness data sizes.
func estimateVSize(nonWitnessSize, witnessDataSize int64) int64 {
	totalSize := nonWitnessSize + witnessDataSize
	return (nonWitnessSize*3+totalSize+3)/4 + 2
}

// clampedFeeRate returns the base fee rate clamped to MaxBaseFeeRate.
func clampedFeeRate(rate int64) int64 {
	if rate > constants.MaxBaseFeeRate {
		return constants.MaxBaseFeeRate
	}
	if rate < 1 {
		return 1
	}
	return rate
}

// Helper function to estimate fee for a given number of inputs and outputs.
// Accounts for the base fee before deciding how many change outputs to include,
// and only adds change outputs that remain above dust after fee adjustment.
func (cs *ContractState) estimateFee(numInputs int64, amount, inputAmount int64) (int64, error) {
	feeRate := clampedFeeRate(cs.Supply.BaseFeeRate)
	totalChange := inputAmount - amount

	// Base transaction overhead (version, locktime, etc.)
	baseSize := int64(10)
	// Input size: outpoint (36) + script sig length (1) + sequence (4)
	inputSize := numInputs * 41
	// Output size: value (8) + script length (1) + P2WSH script (34)
	outputSize := int64(43) // 1 destination output

	// Witness stack per input: <sig> <branch_selector> <witness_script>
	// Serialized: item_count(1) + sig_len(1) + sig(72) + branch_len(1) + branch(1) + script_len(1) + script(N)
	// Witness script is ~79 bytes for change UTXOs (no tag) or ~112 bytes for
	// deposit UTXOs (with 32-byte tag). Use 112 as conservative upper bound
	// to ensure fee estimate >= actual fee from calculateSegwitFee.
	witnessDataSize := numInputs * (72 + 112 + 5)

	// Compute base fee (no change outputs) first
	nonWitnessSize := baseSize + inputSize + outputSize
	baseFee, err := safeMultiply64(estimateVSize(nonWitnessSize, witnessDataSize), feeRate)
	if err != nil {
		return 0, ce.WrapContractError(ce.ErrArithmetic, err, "fee estimation overflow")
	}

	availableChange := totalChange - baseFee
	if availableChange < 0 {
		availableChange = 0
	}

	if availableChange > dustThreshold {
		numChangeOutputs := min(max(availableChange/splitThreshold, 1), maxChangeOutputs)

		// Add change outputs one at a time, stopping when per-output amount is dust
		addedOutputs := int64(0)
		for i := int64(0); i < numChangeOutputs; i++ {
			newNonWitness := nonWitnessSize + (addedOutputs+1)*43
			newFee, err := safeMultiply64(estimateVSize(newNonWitness, witnessDataSize), feeRate)
			if err != nil {
				return 0, ce.WrapContractError(ce.ErrArithmetic, err, "fee estimation overflow")
			}
			newAvailable := totalChange - newFee
			if newAvailable < 0 {
				newAvailable = 0
			}
			if newAvailable/(addedOutputs+1) <= dustThreshold {
				break
			}
			addedOutputs++
			nonWitnessSize = newNonWitness
		}
	}

	fee, err := safeMultiply64(estimateVSize(nonWitnessSize, witnessDataSize), feeRate)
	if err != nil {
		return 0, ce.WrapContractError(ce.ErrArithmetic, err, "fee estimation overflow")
	}
	return fee, nil
}

// returns a list of internal ids of inputs for making a tx
func (cs *ContractState) getInputUtxoIds(amount int64) ([]uint16, int64, error) {
	inputs := []uint16{}

	// accumulates amount of all inputs
	accAmount := int64(0)

	// D-1 (S3): a user unmap must select ONLY active-generation UTXOs. A
	// retiring/draining generation's UTXOs leave the vault ONLY via a migration
	// sweep (getMigrationInputs); dragging one into an ordinary unmap makes the
	// retiring gen's key sign a user-address output, which the node's
	// output-scoped signing gate refuses — stranding the already-debited
	// withdrawal (silent debit-without-delivery). The filter engages ONLY while a
	// superseded fund-holding generation exists (mid-rotation); the common
	// pre/post-rotation case (single active gen) skips it, so the hot path and
	// pre-vault (gen-0-only, no Vaults) behaviour are byte-identical.
	activeIdx := firstVaultWithStatus(cs.Vaults, VaultStatusActive)
	// This set MUST equal isFundHoldingStatus MINUS Active — every non-active
	// fund-holding generation whose UTXOs a user unmap must NOT select (its key is
	// output-scoped to migration sweeps only, S3/D-1). S5 added INACTIVE to
	// isFundHoldingStatus (a late deposit keeps an emptied gen matchable); the S5
	// council found this predicate had NOT moved with it — reopening the D-1 silent
	// debit-without-delivery hole for an INACTIVE gen in the normal post-rotation
	// state (active + inactive, no retiring/draining). If you add a status to
	// isFundHoldingStatus, add it here AND in AnyFundedSupersededGen (NN#3).
	hasSuperseded := countVaultsWithStatus(cs.Vaults, VaultStatusRetiring)+
		countVaultsWithStatus(cs.Vaults, VaultStatusDraining)+
		countVaultsWithStatus(cs.Vaults, VaultStatusInactive) > 0
	// The filter must engage whenever a superseded fund-holding generation
	// exists, INDEPENDENT of whether an Active gen is present. The earlier
	// `activeIdx >= 0 && ...` silently disabled it in a corrupt 0-Active state,
	// reopening the silent-debit hole (methodology money-math MED). And if
	// superseded gens exist with NO active successor to serve the unmap from,
	// we cannot safely select any UTXO → hard-refuse (fail closed, no debit).
	if hasSuperseded && activeIdx < 0 {
		return nil, 0, ce.NewContractError(ce.ErrBalance, "no active generation available to serve unmap during rotation")
	}
	filterGen := hasSuperseded
	activeGen := uint32(0)
	if activeIdx >= 0 {
		activeGen = cs.Vaults[activeIdx].Generation
	}
	isSelectable := func(id uint16) bool {
		// Guard 1 (delete-at-confirm): never select a UTXO already committed to an in-flight
		// unmap (kept registered + reserved until settleUnmap). UNCONDITIONAL — checked even in
		// the common single-active-gen case where the generation filter is off — else two
		// concurrent unmaps would both select the same still-registered input and double-spend
		// it (one confirms, the other strands the debited withdrawal). This gates the fast path,
		// the confirmed-accumulation loop, and the unconfirmed fallback (all route through here).
		if isUtxoReserved(id) {
			return false
		}
		// C-3 (council LOW, load-bearing seam): in-flight MIGRATION inputs are excluded from an
		// unmap by the generation filter below (a sweep's inputs sit on a retiring/draining gen, so
		// u.Generation != activeGen), NOT by the reservation check above — migration keeps its
		// inputs registered via its "ms-" record rather than an "ru-" marker. So the double-spend
		// safety for the unmap-vs-migration seam lives in filterGen; keep it in lock-step with
		// isFundHoldingStatus / hasSuperseded (a superseded gen must always fail u.Generation==activeGen).
		if !filterGen {
			return true
		}
		u, err := loadUtxo(id)
		if err != nil || u == nil {
			return false // fail closed: cannot confirm generation → do not select
		}
		return u.Generation == activeGen
	}

	// first loop: find single confirmed UTXO sufficient to cover spend
	for _, entry := range cs.UtxoList {
		if entry.Id < constants.UtxoConfirmedPoolStart {
			continue
		}
		if !isSelectable(entry.Id) {
			continue
		}
		fee, err := cs.estimateFee(1, amount, entry.Amount)
		if err != nil {
			return nil, 0, err
		}
		requiredAmount := amount + fee
		if entry.Amount >= requiredAmount {
			return []uint16{entry.Id}, entry.Amount, nil
		}
	}

	// second loop: accumulate confirmed UTXOs, fall back to unconfirmed if needed
	type unconfirmedEntry struct {
		id     uint16
		amount int64
	}
	unconfirmedTxs := []unconfirmedEntry{}

	var err error
	for _, entry := range cs.UtxoList {
		if !isSelectable(entry.Id) {
			continue
		}
		if entry.Id >= constants.UtxoConfirmedPoolStart {
			inputs = append(inputs, entry.Id)
			accAmount, err = safeAdd64(accAmount, entry.Amount)
			if err != nil {
				return nil, 0, ce.WrapContractError(ce.ErrArithmetic, err, "error gathering utxos")
			}

			fee, err := cs.estimateFee(int64(len(inputs)), amount, accAmount)
			if err != nil {
				return nil, 0, err
			}
			requiredAmount := amount + fee

			if accAmount >= requiredAmount {
				return inputs, accAmount, nil
			}
		} else {
			unconfirmedTxs = append(unconfirmedTxs, unconfirmedEntry{
				id:     entry.Id,
				amount: entry.Amount,
			})
		}
	}

	// uses unconfirmed txs only if all confirmed txs are insufficient
	for _, u := range unconfirmedTxs {
		inputs = append(inputs, u.id)
		accAmount, err = safeAdd64(accAmount, u.amount)
		if err != nil {
			return nil, 0, ce.WrapContractError(ce.ErrArithmetic, err, "error gathering utxos")
		}

		fee, err := cs.estimateFee(int64(len(inputs)), amount, accAmount)
		if err != nil {
			return nil, 0, err
		}
		requiredAmount := amount + fee

		if accAmount >= requiredAmount {
			return inputs, accAmount, nil
		}
	}
	// this really should never happen
	return nil, 0, ce.NewContractError(ce.ErrBalance, "total available balance insufficient to complete transaction")
}

func (cs *ContractState) calculateSegwitFee(baseSize int64, witnessScripts map[int][]byte) (int64, error) {
	feeRate := clampedFeeRate(cs.Supply.BaseFeeRate)
	// Witness stack per input: <sig> <branch_selector> <witness_script>
	// Serialized: item_count(1) + sig_len(1) + sig(72) + branch_len(1) + branch(1) + script_len(1) + script(N)
	witnessDataSize := int64(0)
	for _, witnessScript := range witnessScripts {
		witnessDataSize += 72 + int64(len(witnessScript)) + 5
	}
	totalSize := baseSize + witnessDataSize
	// +3 to round up, + 2 for has witness data flag
	vSize := (baseSize*3+totalSize+3)/4 + 2
	fee, err := safeMultiply64(vSize, feeRate)
	if err != nil {
		return 0, ce.WrapContractError(ce.ErrArithmetic, err, "fee calculation overflow")
	}
	return fee, nil
}

// addInputsWithWitnesses adds each UTXO as an input on tx and returns the per-input
// witness script built from THAT input's generation keys (S1.2), so a mixed-generation
// spend or a migration sweep signs each input against its OWN vault's script. Shared by
// the withdrawal builder (buildSpendTransaction) and the migration sweep builder
// (buildMigrationTransaction) so the two can NEVER diverge. Aborts if a UTXO's
// generation is absent from a POPULATED vault list — the keys fall back but the keyId
// (VaultKeyId) does NOT, so a wrong-gen witness + a "mainv<N>" signature would be an
// unsatisfiable/unspendable tx (council F2). Fallback is only safe when the vault list
// is empty (pre-fold — every UTXO is gen-0/legacy).
func (cs *ContractState) addInputsWithWitnesses(tx *wire.MsgTx, inputs []*Utxo) (map[int][]byte, error) {
	witnessScripts := make(map[int][]byte)
	for index, utxo := range inputs {
		txHash, err := chainhash.NewHashFromStr(utxo.TxId)
		if err != nil {
			return nil, err
		}
		txIn := wire.NewTxIn(wire.NewOutPoint(txHash, utxo.Vout), nil, nil)
		// L7-01: signal BIP-125 opt-in RBF on every input so a stuck spend can be
		// fee-bumped (re-drive) instead of wedging rotation. BIP-68-inert (bit 31 set),
		// so no interaction with the OP_CSV backup path. Shared by unmap + migration sweep.
		txIn.Sequence = constants.RbfSequence
		tx.AddTxIn(txIn)

		inPrimary, inBackup, genFound := cs.vaultKeysForGeneration(utxo.Generation)
		if !genFound && len(cs.Vaults) > 0 {
			return nil, ce.NewContractError(ce.ErrTransaction, "utxo references a vault generation not in the vault list")
		}
		_, witnessScript, err := createP2WSHAddressWithBackup(inPrimary, inBackup, utxo.Tag, cs.NetworkParams)
		if err != nil {
			return nil, err
		}
		witnessScripts[index] = witnessScript
	}
	return witnessScripts, nil
}

// buildSpendTransaction constructs the Bitcoin withdrawal transaction and
// computes the miner fee, but does NOT request TSS signing. Call
// signSpendTransaction after all validation checks pass.
func (cs *ContractState) buildSpendTransaction(
	inputs []*Utxo,
	totalInputsAmount int64,
	destAddress string,
	changeAddress string,
	sendAmount int64,
) (*wire.MsgTx, map[int][]byte, int64, error) {
	tx := wire.NewMsgTx(wire.TxVersion)

	// create all witness scripts now for better size estimation (per-input generation
	// keys — shared with the migration sweep builder via addInputsWithWitnesses)
	witnessScripts, err := cs.addInputsWithWitnesses(tx, inputs)
	if err != nil {
		return nil, nil, 0, err
	}

	destAddr, err := btcutil.DecodeAddress(destAddress, cs.NetworkParams)
	if err != nil {
		return nil, nil, 0, ce.WrapContractError(
			ce.ErrInput,
			err,
			"error decoding destination btc address ["+destAddress+"]",
		)
	}

	// Create output script for destination
	destScript, err := txscript.PayToAddrScript(destAddr)
	if err != nil {
		return nil, nil, 0, err
	}

	destTxOut := wire.NewTxOut(sendAmount, destScript)
	tx.AddTxOut(destTxOut)

	baseSize := int64(tx.SerializeSize())
	fee, err := cs.calculateSegwitFee(baseSize, witnessScripts)
	if err != nil {
		return nil, nil, 0, err
	}

	totalChange := totalInputsAmount - sendAmount

	// Account for the base fee before computing available change
	availableChange := totalChange - fee
	if availableChange < 0 {
		availableChange = 0
	}

	// Add change outputs if above dust, splitting across multiple outputs
	if availableChange > dustThreshold {
		changeAddressObj, err := btcutil.DecodeAddress(changeAddress, cs.NetworkParams)
		if err != nil {
			return nil, nil, 0, err
		}
		changeScript, err := txscript.PayToAddrScript(changeAddressObj)
		if err != nil {
			return nil, nil, 0, err
		}
		changeOutputSize := int64(wire.NewTxOut(int64(0), changeScript).SerializeSize())

		numChangeOuputs := min(max(availableChange/splitThreshold, 1), maxChangeOutputs)

		// Add change outputs one at a time, recalculating fee after each
		addedOutputs := int64(0)
		for range numChangeOuputs {
			newBaseSize := baseSize + (addedOutputs+1)*changeOutputSize
			newFee, err := cs.calculateSegwitFee(newBaseSize, witnessScripts)
			if err != nil {
				return nil, nil, 0, err
			}
			newAvailable := totalChange - newFee
			if newAvailable < 0 {
				newAvailable = 0
			}

			// Check if adding this output still leaves enough for all outputs to be above dust
			perOutput := newAvailable / (addedOutputs + 1)
			if perOutput <= dustThreshold {
				break
			}

			addedOutputs++
			baseSize = newBaseSize
			fee = newFee
			availableChange = newAvailable
		}

		if addedOutputs > 0 {
			eachChangeAmount := availableChange / addedOutputs
			remainder := availableChange - eachChangeAmount*addedOutputs

			txOutChange := wire.NewTxOut(eachChangeAmount+remainder, changeScript)
			tx.AddTxOut(txOutChange)

			for range addedOutputs - 1 {
				txOutChange := wire.NewTxOut(eachChangeAmount, changeScript)
				tx.AddTxOut(txOutChange)
			}
		}
	}

	// L1-1 (FULL-PRUNED): return the TRUE miner fee = inputs − outputs, not the size-based
	// estimate. When leftover change is sub-dust it is NOT added as an output (loop above),
	// so that residual is burned to the miner and the real fee EXCEEDS `fee`. Debiting only
	// the size fee at HandleUnmap under-collateralizes the vault (Σ(UTXO) drops MORE than
	// ActiveSupply at settle → I1 breaks in the unsafe direction). Charging inputs−outputs
	// makes the balance debit match the BTC that actually leaves → conservation holds exactly
	// (add-fee) and stays over-collateralized (deduct-fee, safe). Equals `fee` whenever a
	// change output IS added. `fee` above still drives the change calc, so the tx is byte-identical.
	var outputTotal int64
	for _, o := range tx.TxOut {
		outputTotal += o.Value
	}
	trueFee := totalInputsAmount - outputTotal
	if trueFee < 0 {
		return nil, nil, 0, ce.NewContractError(ce.ErrTransaction, "spend outputs exceed inputs")
	}
	return tx, witnessScripts, trueFee, nil
}

// assertInputsSignable is the BRK-2 contract-side defense-in-depth guard: never
// REQUEST a real spend-signature for a generation that is not fund-holding (e.g.
// a Pending gen — which holds no UTXOs and whose key is only permitted to sign
// the check-message M; the node's scopeCheckSig would refuse a real sighash for
// it anyway). Inputs are always selected from fund-holding gens (unmap:
// active-only per D-1; migration: retiring/draining), so this only ever fires on
// a bug/corruption. Inert-safe: an ABSENT vault registry (pre-fold / pre-v2,
// legacy gen-0-only) is a no-op; a gen NOT present in a populated registry is
// left to the node gate (not aborted here, to avoid bricking on an
// unexpected-but-benign state); ONLY an input whose gen IS present AND NOT
// fund-holding aborts the spend.
func assertInputsSignable(inputs []*Utxo) error {
	vaults, _, _, err := LoadVaultState()
	if err != nil {
		return err
	}
	if len(vaults) == 0 {
		return nil // legacy pre-fold path — unchanged
	}
	statusByGen := make(map[uint32]VaultStatus, len(vaults))
	for i := range vaults {
		statusByGen[vaults[i].Generation] = vaults[i].Status
	}
	for _, u := range inputs {
		if st, ok := statusByGen[u.Generation]; ok && !isFundHoldingStatus(st) {
			return ce.NewContractError(ce.ErrTransaction,
				"refusing to sign a spend for a non-fund-holding generation (BRK-2 defense-in-depth)")
		}
	}
	return nil
}

// signSpendTransaction computes witness sighashes and requests TSS signing
// for each input. Call this only after all validation checks have passed.
// HandleRedrive (L7-01) dispatches a stuck-spend re-drive to the sweep or unmap path by the
// record type. Owner-gated + pause-gated at the entrypoint.
func (cs *ContractState) HandleRedrive(txId string) (string, error) {
	if ms := sdk.StateGetObject(constants.MigrationSweepPrefix + txId); ms != nil && *ms != "" {
		return cs.HandleRedriveSweep(txId)
	}
	if us := sdk.StateGetObject(constants.PendingUnmapPrefix + txId); us != nil && *us != "" {
		return cs.HandleRedriveUnmap(txId)
	}
	return "", ce.NewContractError(ce.ErrInput, "no in-flight spend for that txid (already settled, or not a vault spend)")
}

// HandleRedriveUnmap re-drives a STUCK, never-confirming withdrawal (L7-01). Unlike a sweep
// (one successor output), an unmap has a USER destination output that must be preserved
// byte-for-byte plus a change output — so it CLONES the original tx's outputs and reduces
// ONLY the change (spec v2 RBF-2/H4), re-signing over the IDENTICAL inputs with a higher fee.
// A stuck unmap strands only that user's own withdrawal (its inputs are active-gen, never
// superseded → NN#3 is not triggered), so this is user-liveness, not the network freeze.
//
// Fee model (differs from the sweep): the unmap's original fee was DEBITED from the user at
// build, so the bump is real vault BTC the operator covers — CHARGE FeeSupply the incremental
// bump here (fail-closed), and REFUND the unused portion at settle if a cheaper member
// confirms (H1/P2). Same identical-inputs ⇒ ≤1 confirms ⇒ no double-spend; group settle
// clears all members (A2/H2).
func (cs *ContractState) HandleRedriveUnmap(txId string) (string, error) {
	raw := sdk.StateGetObject(constants.PendingUnmapPrefix + txId)
	if raw == nil || *raw == "" {
		return "", ce.NewContractError(ce.ErrInput, "no in-flight unmap for that txid")
	}
	rec, err := UnmarshalPendingUnmap([]byte(*raw))
	if err != nil {
		return "", ce.NewContractError(ce.ErrStateAccess, "error decoding pending unmap record: "+err.Error())
	}

	// Staleness gate (D3).
	nowH := currentLastHeight()
	if rec.BuildHeight == 0 || nowH < rec.BuildHeight || nowH-rec.BuildHeight < constants.RedriveStaleBlocks {
		return "", ce.NewContractError(ce.ErrTransaction, "unmap not yet stale enough to re-drive")
	}

	// Fee to out-bid = the group's current highest committed fee (BIP-125 rule 3).
	gk := spendGroupKey(rec.InputIds)
	prevHighestFee := rec.BtcFee
	var group *SpendGroup
	if graw := sdk.StateGetObject(gk); graw != nil && *graw != "" {
		g, gerr := UnmarshalSpendGroup([]byte(*graw))
		if gerr != nil {
			// Fail CLOSED (build-council LOW): re-seeding here would DROP prior members → H2.
			return "", ce.NewContractError(ce.ErrStateAccess, "corrupt spend-group object — refusing unmap re-drive")
		}
		group = g
		if g.HighestFee > prevHighestFee {
			prevHighestFee = g.HighestFee
		}
	}
	if group != nil && len(group.Members) >= constants.MaxSpendGroupMembers {
		return "", ce.NewContractError(ce.ErrTransaction, "unmap spend group has reached the re-drive member cap (cold-scan B)")
	}

	// Read the ORIGINAL tx (its user-destination output is not in the "us-" record).
	sdRaw := sdk.StateGetObject(constants.TxSpendsPrefix + txId)
	if sdRaw == nil || *sdRaw == "" {
		return "", ce.NewContractError(ce.ErrStateAccess, "missing signing data for the stuck unmap")
	}
	sd, err := UnmarshalSigningData([]byte(*sdRaw))
	if err != nil {
		return "", ce.NewContractError(ce.ErrStateAccess, "error decoding unmap signing data: "+err.Error())
	}
	var origTx wire.MsgTx
	if derr := origTx.Deserialize(bytes.NewReader(sd.Tx)); derr != nil {
		return "", ce.WrapContractError(ce.ErrTransaction, derr, "error deserializing stuck unmap tx")
	}

	inputUtxos, err := getInputUtxos(rec.InputIds)
	if err != nil {
		return "", err
	}
	var total int64
	for _, u := range inputUtxos {
		total, err = safeAdd64(total, u.Amount)
		if err != nil {
			return "", ce.WrapContractError(ce.ErrArithmetic, err, "unmap re-drive input total overflow")
		}
		// D-1 mirror (cold-scan A): an unmap re-drive re-signs the inputs for the USER
		// destination, which only an ACTIVE-gen key may do — the node output-scopes a
		// retiring/draining gen's keysign to its successor. If the active gen rotated while this
		// unmap was pending, the inputs are now superseded → the replacement could never be
		// signed. Refuse BEFORE charging/signing (else a wasted re-drive + transient over-charge).
		if u.Generation != cs.ActiveGen {
			return "", ce.NewContractError(ce.ErrTransaction, "stuck unmap's inputs are no longer on the active generation (rotated) — cannot re-drive as a withdrawal")
		}
	}

	// Rebuild: RBF inputs (addInputsWithWitnesses) + a byte-for-byte CLONE of every original
	// output. Identify the change output by its pkScript so ONLY it is reduced.
	changeAddrObj, err := btcutil.DecodeAddress(rec.ChangeAddress, cs.NetworkParams)
	if err != nil {
		return "", ce.WrapContractError(ce.ErrInput, err, "error decoding change address")
	}
	changeScript, err := txscript.PayToAddrScript(changeAddrObj)
	if err != nil {
		return "", err
	}
	newTx := wire.NewMsgTx(wire.TxVersion)
	witnessScripts, err := cs.addInputsWithWitnesses(newTx, inputUtxos)
	if err != nil {
		return "", err
	}
	changeIdx := -1
	var origOutTotal int64
	for _, out := range origTx.TxOut {
		if changeIdx < 0 && bytes.Equal(out.PkScript, changeScript) {
			changeIdx = len(newTx.TxOut)
		}
		script := make([]byte, len(out.PkScript))
		copy(script, out.PkScript)
		newTx.AddTxOut(wire.NewTxOut(out.Value, script))
		origOutTotal, err = safeAdd64(origOutTotal, out.Value)
		if err != nil {
			return "", ce.WrapContractError(ce.ErrArithmetic, err, "unmap re-drive output total overflow")
		}
	}
	if changeIdx < 0 {
		// No change output to fund the bump (the original already burned its residual as fee) —
		// un-re-drivable this way; the user output cannot be touched. Recoverable only if the
		// original eventually confirms; not a network freeze (active-gen inputs).
		return "", ce.NewContractError(ce.ErrTransaction, "stuck unmap has no change output to fund a fee bump — cannot re-drive")
	}

	// Target fee = max(current oracle fee, prevHighest + BIP-125 minBump).
	oracleFee, err := cs.calculateSegwitFee(int64(newTx.SerializeSize()), witnessScripts)
	if err != nil {
		return "", err
	}
	rate := clampedFeeRate(cs.Supply.BaseFeeRate)
	minBump, mErr := safeMultiply64(constants.RedriveIncRelayFeeRate, oracleFee/rate) // cold-scan F
	if mErr != nil {
		return "", ce.WrapContractError(ce.ErrArithmetic, mErr, "unmap re-drive minBump overflow")
	}
	if minBump < 1 {
		minBump = 1
	}
	targetFee, err := safeAdd64(prevHighestFee, minBump)
	if err != nil {
		return "", ce.WrapContractError(ce.ErrArithmetic, err, "unmap re-drive target fee overflow")
	}
	if oracleFee > targetFee {
		targetFee = oracleFee
	}
	origFee, err := safeSubtract64(total, origOutTotal)
	if err != nil || origFee < 0 {
		return "", ce.NewContractError(ce.ErrTransaction, "unmap re-drive: corrupt original fee")
	}
	deltaFee, err := safeSubtract64(targetFee, origFee)
	if err != nil || deltaFee <= 0 {
		return "", ce.NewContractError(ce.ErrTransaction, "unmap re-drive: no positive fee bump")
	}

	// Reduce ONLY the change output by deltaFee; if that takes it to/under dust, OMIT it (the
	// residual becomes extra fee — RBF-3a, no loss). Never touch the user destination.
	changeVal := newTx.TxOut[changeIdx].Value
	newChangeVal, err := safeSubtract64(changeVal, deltaFee)
	if err != nil {
		return "", ce.WrapContractError(ce.ErrArithmetic, err, "unmap re-drive change arithmetic")
	}
	if newChangeVal > dustThreshold {
		newTx.TxOut[changeIdx].Value = newChangeVal
	} else {
		newTx.TxOut = append(newTx.TxOut[:changeIdx], newTx.TxOut[changeIdx+1:]...)
	}

	// The ACTUAL fee this replacement pays = total inputs − remaining outputs (may exceed
	// targetFee if the change was omitted). It MUST out-fee the group's highest by minBump.
	var newOutTotal int64
	for _, out := range newTx.TxOut {
		newOutTotal, err = safeAdd64(newOutTotal, out.Value)
		if err != nil {
			return "", ce.WrapContractError(ce.ErrArithmetic, err, "unmap re-drive new output total overflow")
		}
	}
	actualFee, err := safeSubtract64(total, newOutTotal)
	if err != nil || actualFee < 0 {
		return "", ce.NewContractError(ce.ErrTransaction, "unmap re-drive: negative actual fee")
	}
	// Fee ceiling (cold-scan C, mirrors the sweep's V5-4): a re-drive must not burn more than
	// half the inputs on miner fee — bounds a rogue-owner change-burn and a runaway bump.
	if actualFee > total/2 {
		return "", ce.NewContractError(ce.ErrTransaction, "unmap re-drive fee would exceed half the inputs — refused")
	}
	minAcceptable, err := safeAdd64(prevHighestFee, minBump)
	if err != nil {
		return "", ce.WrapContractError(ce.ErrArithmetic, err, "unmap re-drive min-acceptable overflow")
	}
	if actualFee < minAcceptable {
		return "", ce.NewContractError(ce.ErrBalance, "stuck unmap change too small to fund a sufficient fee bump — cannot re-drive")
	}

	// CHARGE FeeSupply the incremental bump above the group's prior highest (H1/P2); settle
	// refunds the difference if a cheaper member confirms. Fail-safe: abort BEFORE signing.
	charge, err := safeSubtract64(actualFee, prevHighestFee)
	if err != nil {
		return "", ce.WrapContractError(ce.ErrArithmetic, err, "unmap re-drive charge arithmetic")
	}
	// The charge must come from the FREE reserve — FeeSupply ABOVE what's already committed to
	// pending migration-sweep fees — NOT the whole FeeSupply (build-council MEDIUM). Charging
	// into the sweep reserve would later underflow settleMigrationSweep's deferred debit → a
	// confirmed sweep can't settle → the superseded gen never drains → NN#3 freeze re-armed
	// (the exact post-L1 brick the sweep reserve prevents). FeeSupply already nets prior unmap
	// charges (they are debits), so freeReserve = FeeSupply − pendingSweepReserve.
	_, pendingSweepReserve, perr := cs.pendingMigrationState()
	if perr != nil {
		return "", perr
	}
	freeReserve, ferr := safeSubtract64(cs.Supply.FeeSupply, pendingSweepReserve)
	if ferr != nil || freeReserve < charge {
		return "", ce.NewContractError(ce.ErrBalance, "insufficient FREE fee reserve to cover the unmap re-drive fee bump (migration-sweep reserve is protected)")
	}

	signingData, err := signSpendTransaction(newTx, inputUtxos, witnessScripts)
	if err != nil {
		return "", ce.WrapContractError(ce.ErrTransaction, err, "error signing unmap re-drive")
	}
	signingBytes, err := MarshalSigningData(signingData)
	if err != nil {
		return "", ce.WrapContractError(ce.ErrJson, err, "error marshalling unmap re-drive signing data")
	}
	newTxId := newTx.TxID()
	if newTxId == txId {
		return "", ce.NewContractError(ce.ErrTransaction, "unmap re-drive produced an identical txid")
	}

	// Commit: charge the reserve, write the replacement records + group, node side unchanged.
	cs.Supply.FeeSupply -= charge
	sdk.StateSetObject(constants.TxSpendsPrefix+newTxId, string(signingBytes))
	cs.TxSpendsList = append(cs.TxSpendsList, newTxId)
	replRecord := &PendingUnmap{
		InputIds:      rec.InputIds,
		ChangeAddress: rec.ChangeAddress,
		ChangeGen:     rec.ChangeGen,
		BtcFee:        actualFee,
		BuildHeight:   nowH,
	}
	sdk.StateSetObject(constants.PendingUnmapPrefix+newTxId, string(MarshalPendingUnmap(replRecord)))
	if group == nil {
		group = &SpendGroup{Members: []string{txId}}
	}
	group.Members = append(group.Members, newTxId)
	group.HighestFee = actualFee
	sdk.StateSetObject(gk, string(MarshalSpendGroup(group)))

	return "redrive-unmap: old=" + txId + " new=" + newTxId + " fee=" + strconv.FormatInt(actualFee, 10), nil
}

func signSpendTransaction(tx *wire.MsgTx, inputs []*Utxo, witnessScripts map[int][]byte) (*SigningData, error) {
	// BRK-2 defense-in-depth: never request a real spend-sign for a
	// non-fund-holding (e.g. Pending) generation. See assertInputsSignable.
	if err := assertInputsSignable(inputs); err != nil {
		return nil, err
	}
	unsignedSigHashes := make([]UnsignedSigHash, len(inputs))
	for i, utxo := range inputs {
		witnessScript := witnessScripts[i]

		sigHashes := txscript.NewTxSigHashes(tx, txscript.NewCannedPrevOutputFetcher(utxo.PkScript, utxo.Amount))

		sigHash, err := txscript.CalcWitnessSigHash(
			witnessScript,
			sigHashes,
			txscript.SigHashAll,
			tx,
			i,
			utxo.Amount,
		)

		if err != nil {
			return nil, err
		}

		// S1.2: sign each input with the keyId of the generation that locked it
		// (gen 0 → "main", gen N → "mainv<N>"), so the retiring-gen inputs of a
		// migration sweep are signed by the retiring gen's key.
		sdk.TssSignKey(VaultKeyId(utxo.Generation), sigHash)

		unsignedSigHashes[i] = UnsignedSigHash{
			Index:         uint32(i),
			SigHash:       sigHash,
			WitnessScript: witnessScript,
			// S3: carry the spent input's value so the node can independently
			// recompute this input's BIP143 sighash for output-scoped signing.
			Amount: utxo.Amount,
		}
	}

	var buf bytes.Buffer
	err := tx.Serialize(&buf)
	if err != nil {
		return nil, err
	}

	return &SigningData{
		Tx:                buf.Bytes(),
		UnsignedSigHashes: unsignedSigHashes,
	}, nil
}

func indexUnconfimedOutputs(tx *wire.MsgTx, changeAddress string, network *chaincfg.Params, activeGen uint32) ([]*Utxo, error) {
	// 1 output will be to the destination, the others will be to change address
	utxos := make([]*Utxo, len(tx.TxOut)-1)

	i := 0
	for index, txOut := range tx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, network)
		if err != nil {
			return nil, err
		}
		// must be 1 because it's P2WSH
		if len(addrs) != 1 {
			return nil, ce.NewContractError(ce.ErrTransaction, "incorrect number of addresses for transaction output")
		}
		if addrs[0].EncodeAddress() == changeAddress {
			// Money-math L-1 (S1-close): cap change like the deposit path (mapping.go). The
			// registry stores Amount as uint48 while the blob stores int64; an uncapped
			// change ≥ 2^48 (reachable once S2 consolidates many inputs into one output)
			// would truncate the registry and diverge from the blob → reject.
			if txOut.Value > constants.MaxUtxoAmount {
				return nil, ce.NewContractError(ce.ErrTransaction, "change output amount exceeds maximum utxo amount")
			}
			utxo := Utxo{
				TxId:     tx.TxID(),
				Vout:     uint32(index),
				Amount:   txOut.Value,
				PkScript: txOut.PkScript,
				Tag:      nil, // change outputs have no tag
				// Council F1/F5 (3-lens, HIGH→CRIT at S1.3): tag change with the ACTIVE
				// generation. changeAddress is derived from the active gen's keys
				// (HandleUnmap), so the change UTXO must resolve to the active gen at
				// spend — else post-rotation change is locked (Generation=0 → gen-0 keys).
				Generation: activeGen,
			}
			if i < len(utxos) {
				utxos[i] = &utxo
				i++
			} else {
				utxos = append(utxos, &utxo)
			}
		}
	}

	return utxos, nil
}

// indexMigrationOutputs returns the confirmed migration sweep's output UTXO(s) that pay
// the successor vault address, each tagged with the successor generation (BRK-1
// delete-at-confirm). Unlike indexUnconfimedOutputs — which reserves the FIRST output as
// a withdrawal destination and indexes only change — EVERY output of a migration sweep
// pays the successor (assertOutputsPaySuccessor at build), so this indexes all matching
// outputs and makes no destination-output/len-1 assumption. Caps each output at
// MaxUtxoAmount (the uint48 registry width) exactly like the change path. The caller
// (settleMigrationSweep) allocates CONFIRMED ids for the returned UTXOs and asserts
// conservation (Σ outputs == Σ inputs − fee), so a mis-addressed or empty result is
// caught rather than silently dropped.
func indexMigrationOutputs(tx *wire.MsgTx, successorAddress string, network *chaincfg.Params, successorGen uint32) ([]*Utxo, error) {
	var utxos []*Utxo
	for index, txOut := range tx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, network)
		if err != nil {
			return nil, err
		}
		if len(addrs) != 1 {
			return nil, ce.NewContractError(ce.ErrTransaction, "incorrect number of addresses for migration output")
		}
		if addrs[0].EncodeAddress() != successorAddress {
			continue
		}
		if txOut.Value > constants.MaxUtxoAmount {
			return nil, ce.NewContractError(ce.ErrTransaction, "migration output amount exceeds maximum utxo amount")
		}
		utxos = append(utxos, &Utxo{
			TxId:       tx.TxID(),
			Vout:       uint32(index),
			Amount:     txOut.Value,
			PkScript:   txOut.PkScript,
			Tag:        nil,
			Generation: successorGen,
		})
	}
	return utxos, nil
}
