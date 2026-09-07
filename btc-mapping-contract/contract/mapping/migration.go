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
func (cs *ContractState) getMigrationInputs(gen uint32, excluded map[uint16]struct{}, maxTrancheValue int64) (inputIds []uint16, total int64, moreRemain bool, err error) {
	for i := range cs.UtxoList {
		entry := cs.UtxoList[i]
		if entry.Id < constants.UtxoConfirmedPoolStart {
			continue // confirmed-only
		}
		// BRK-1 (delete-at-confirm): the swept inputs of an in-flight sweep STAY in the
		// registry until that sweep confirms, so they must be EXCLUDED here — otherwise a
		// later tranche or a retry would re-select and double-sweep an input already
		// committed to a pending sweep (an unsatisfiable double-spend that could never
		// confirm, stranding the tranche). The exclusion set is the union of every
		// pending "ms-" record's InputIds (built once in pendingMigrationState).
		if _, inflight := excluded[entry.Id]; inflight {
			continue
		}
		// Guard 1 cross-path exclusion: also skip a UTXO reserved by an in-flight UNMAP. An
		// unmap selects ACTIVE-gen inputs (D-1); if that generation RETIRES while the unmap is
		// still unconfirmed, this now-superseded gen's migration must NOT sweep the reserved
		// input — else the sweep and the still-pending unmap double-spend it (one confirms, the
		// other strands: a user debit-without-delivery if the sweep wins, or a wedged sweep if
		// the unmap wins). A per-candidate marker read (NOT a PendingUnmaps scan) keeps this
		// O(tranche candidates) so an unprivileged unmap flood can never gas-DoS rotation
		// (preserves the BRK-1 council A-1 bounded-scan property). settleUnmap clears it.
		if isUtxoReserved(entry.Id) {
			continue
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
		// Value cap: MaxUtxoAmount for a normal tranche (so the consolidated output fits the
		// uint48 registry), OR MigrationCanaryValue for a gen's FIRST (canary) tranche. The
		// first input is always included (the len>0 guard) so a single UTXO above the cap
		// still forms a buildable tranche; the overflow drains next.
		if len(inputIds) > 0 && total+entry.Amount > maxTrancheValue {
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
		// Every non-active fund-holding status (Retiring/Draining/INACTIVE). S5 added
		// INACTIVE to the matchable set, so a late deposit can re-fund an emptied gen;
		// the NN#3 "no new rotation while a superseded gen is funded" gate must SEE that
		// gen (S5 council MED — else the owner could rotate while an INACTIVE gen holds
		// funds, piling up funded old keys = the reconstruction surface NN#3 exists to
		// prevent). Keep in lock-step with isFundHoldingStatus and the unmap hasSuperseded.
		if vaults[i].Status == VaultStatusRetiring || vaults[i].Status == VaultStatusDraining ||
			vaults[i].Status == VaultStatusInactive {
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
func (cs *ContractState) buildMigrationTransaction(inputs []*Utxo, totalInputs int64, successorAddress string, prevFee int64) (*wire.MsgTx, map[int][]byte, int64, error) {
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
	// L7-01 re-drive floor: when re-building a STUCK sweep (prevFee>0), the replacement must
	// out-fee the original by at least the BIP-125 rule-4 incremental relay fee, else mempools
	// reject the replacement. minBump = RedriveIncRelayFeeRate * vSize (vSize = fee/rate, exact
	// since calculateSegwitFee returns vSize*rate). newFee = max(current oracle fee, prevFee +
	// minBump) so it works whether the fee spike persists (oracle fee already high) or eased
	// (floor forces the bump). Normal migrate passes prevFee=0 → no floor → byte-identical.
	if prevFee > 0 {
		rate := clampedFeeRate(cs.Supply.BaseFeeRate)
		minBump, mErr := safeMultiply64(constants.RedriveIncRelayFeeRate, fee/rate) // cold-scan F
		if mErr != nil {
			return nil, nil, 0, ce.WrapContractError(ce.ErrArithmetic, mErr, "re-drive minBump overflow")
		}
		if minBump < 1 {
			minBump = 1
		}
		minReplaceFee, aerr := safeAdd64(prevFee, minBump)
		if aerr != nil {
			return nil, nil, 0, ce.WrapContractError(ce.ErrArithmetic, aerr, "re-drive min replacement fee overflow")
		}
		if fee < minReplaceFee {
			fee = minReplaceFee
		}
	}
	// V5-4 (migration-fee sanity ceiling): a rogue/glitched oracle BaseFeeRate (already
	// clamped to MaxBaseFeeRate) must not burn most of a tranche on miner fees. Reject a
	// sweep whose fee exceeds half the tranche value — fail-safe (the gen keeps these
	// UTXOs, recoverable; abort leaves no state change). For a re-drive this is ALSO the
	// affordability gate: a bump that can't fit under the ceiling routes to the dust residual.
	if fee > totalInputs/2 {
		// VR2-11: rather than deferring indefinitely, retry at the highest rate the
		// ceiling actually allows.
		//
		// The old behaviour deadlocked a whole class of residuals. A tranche whose
		// sweep is affordable at the protocol minimum but not at a spiked oracle rate
		// was deferred here, while write-off correctly declined to touch it (it IS
		// sweepable at the minimum), so nothing moved until fees happened to fall —
		// and meanwhile NN#3 blocked every rotation and the committee's bond stayed
		// locked. Nobody had to attack anything; a fee spike was enough.
		//
		// The rate is DERIVED, never chosen: the largest rate whose fee fits under the
		// same ceiling. So this does not weaken V5-4 — the fee still never exceeds
		// half the tranche, which is exactly the protection V5-4 exists to give. It
		// only stops the contract insisting on the oracle's rate when a lower one
		// would clear the same bar. Paying under the going rate means slower
		// confirmation, which is what the re-drive path is for.
		//
		// Redrives are excluded: a replacement must out-fee its original, so lowering
		// the rate there is meaningless, and the existing defer is the right answer.
		if prevFee > 0 {
			return nil, nil, 0, ce.NewContractError(ce.ErrTransaction, "migration fee exceeds half the tranche value — sweep deferred")
		}
		oracleRate := clampedFeeRate(cs.Supply.BaseFeeRate)
		vSize := fee / oracleRate // exact: calculateSegwitFee returns vSize*rate
		affordableRate := int64(0)
		if vSize > 0 {
			affordableRate = (totalInputs / 2) / vSize
		}
		if affordableRate < 1 {
			// Unaffordable even at the protocol minimum. This is the genuinely stuck
			// residual, and it is write-off's to judge, not this builder's.
			return nil, nil, 0, ce.NewContractError(ce.ErrTransaction, "migration fee exceeds half the tranche value even at the minimum rate — sweep deferred")
		}
		reducedFee, rErr := calculateSegwitFeeAt(affordableRate, int64(tx.SerializeSize()), witnessScripts)
		if rErr != nil {
			return nil, nil, 0, rErr
		}
		if reducedFee > totalInputs/2 {
			// Belt and braces: the ceiling is the invariant, not the arithmetic above.
			return nil, nil, 0, ce.NewContractError(ce.ErrTransaction, "migration fee exceeds half the tranche value — sweep deferred")
		}
		sdk.Log("migrate-fee-reduced|rate=" + strconv.FormatInt(affordableRate, 10) +
			"|oracle=" + strconv.FormatInt(oracleRate, 10))
		fee = reducedFee
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

	// BRK-1 (delete-at-confirm): scan the in-flight migration sweeps ONCE — their
	// committed inputs must be EXCLUDED from this tranche's selection (an input stays in
	// the registry until its sweep confirms, so without this a retry/tranche re-selects and
	// double-sweeps it), and the SUM of their reserved fees feeds the build-time fee-reserve
	// check below.
	excluded, pendingFeeSum, err := cs.pendingMigrationState()
	if err != nil {
		return "", err
	}

	// CANARY (THORChain small-first-then-ramp): a gen's FIRST tranche is taken while it is
	// still RETIRING (this call transitions RETIRING→DRAINING below); cap it to
	// MigrationCanaryValue so only a small "test" amount moves to the new successor vault
	// first, bounding the exposure of the first move. Subsequent (DRAINING) tranches drain
	// the bulk at MaxUtxoAmount. Defense-in-depth atop BRK-2's pre-activation sign proof + NN#1
	// output-scoping. NOTE (canary council F2): the bulk is NOT contract-gated on the canary
	// CONFIRMING — BRK-1 only excludes the canary's own inputs from later tranches; "wait for
	// the canary to confirm before the bulk" is operator/driver discipline, not enforced here.
	// A confirm-gate (serialise the canary before any DRAINING tranche) is a tracked stronger
	// variant.
	maxTrancheValue := constants.MaxUtxoAmount
	usingCanary := false
	if cs.Vaults[targetIdx].Status == VaultStatusRetiring && constants.MigrationCanaryValue < constants.MaxUtxoAmount {
		maxTrancheValue = constants.MigrationCanaryValue
		usingCanary = true
	}
	inputIds, total, moreRemain, err := cs.getMigrationInputs(targetGen, excluded, maxTrancheValue)
	if err != nil {
		return "", err
	}
	if len(inputIds) == 0 {
		// No selectable confirmed UTXOs for this gen — either it holds none, or every one
		// it holds is already committed to a pending sweep (delete-at-confirm keeps them in
		// the registry until confirmation). It STAYS retiring/draining — still fund-holding,
		// so its address stays matchable for late deposits and its key keeps renewing
		// (never-brick). The draining→inactive→purged finalization is S5's job: it needs the
		// SPV zero-L1 proof + grace≥reorg AND the match-until-purged / revert-on-late-deposit
		// handling (S1-DESIGN §5a). Producing INACTIVE here (in S2, before that consumer
		// exists) would drop the gen out of isFundHoldingStatus and reopen the C-2/NR-4
		// late-deposit loss — the S2-close council F-1. NN#3 (enforced in createKey) gates
		// the next rotation on every superseded gen being drained, so an empty draining gen
		// never blocks progress even though it is not marked inactive here.
		return "nothing to migrate for generation " + strconv.FormatUint(uint64(targetGen), 10), nil
	}

	inputUtxos, err := getInputUtxos(inputIds)
	if err != nil {
		return "", err
	}
	tx, witnessScripts, btcFee, err := cs.buildMigrationTransaction(inputUtxos, total, successorAddress, 0)
	if err != nil && usingCanary {
		// F1 (canary council, MEDIUM): the small canary cap can make the FIRST tranche too
		// small to cover its own sweep fee (fee>half, or below the dust floor) at a high fee
		// rate — a full tranche amortizes the fixed overhead and would build fine. Left
		// unfixed, the gen would wedge RETIRING forever (re-selected + re-aborted every call →
		// NN#3 blocks all future rotation). The canary is pure defense-in-depth and must NEVER
		// block migration → FALL BACK to a normal full-cap tranche. If the full tranche ALSO
		// can't build, that is the genuine V-1 dust residual → abort as before (unchanged).
		inputIds, total, moreRemain, err = cs.getMigrationInputs(targetGen, excluded, constants.MaxUtxoAmount)
		if err == nil && len(inputIds) > 0 {
			inputUtxos, err = getInputUtxos(inputIds)
			if err == nil {
				tx, witnessScripts, btcFee, err = cs.buildMigrationTransaction(inputUtxos, total, successorAddress, 0)
			}
		}
	}
	if err != nil {
		return "", err
	}

	// BRK-1 fee RESERVE CHECK (pre-mortem F-FEE/C-1 — all 3 lenses HIGH): the FeeSupply
	// debit is DEFERRED to confirmSpend's atomic swap. A debit at BUILD would settle a fee
	// for a sweep that may never confirm; a debit at CONFIRM *without* this guarantee could
	// abort a sweep that already moved on L1 → permanent registry⇔L1 divergence + a wedged
	// sweep that re-aborts forever. Instead CHECK here that the reserve covers every
	// already-pending sweep's fee PLUS this one. Because each confirm debits exactly its
	// recorded fee and this check runs at every build, it maintains the invariant
	// FeeSupply >= Σ(pending sweep fees) — so every deferred confirm-side debit is
	// GUARANTEED to succeed (never a post-L1 brick). Fail-safe: an insufficient reserve
	// aborts BEFORE signing/broadcast (the gen keeps its UTXOs, fully recoverable). This
	// preserves the X-2 solvency property (migration fees never erode user principal /
	// ActiveSupply ≥ UserSupply) as a can't-START gate rather than the old can't-finish
	// debit. NOTE: FeeSupply is NOT mutated here — the invariant Σ(UTXO) == ActiveSupply +
	// FeeSupply therefore holds trivially at build (nothing settled).
	feeNeeded, err := safeAdd64(pendingFeeSum, btcFee)
	if err != nil {
		return "", ce.WrapContractError(ce.ErrArithmetic, err, "migration pending-fee sum overflow")
	}
	if cs.Supply.FeeSupply < feeNeeded {
		return "", ce.NewContractError(ce.ErrBalance, "insufficient fee reserve to cover pending and current migration sweeps")
	}

	// Sign each input with its (retiring) generation's keyId.
	signingData, err := signSpendTransaction(tx, inputUtxos, witnessScripts)
	if err != nil {
		return "", ce.WrapContractError(ce.ErrTransaction, err, "error signing migration sweep")
	}

	// Record the pending sweep. Under BRK-1 (delete-at-confirm) BUILD settles NOTHING: the
	// sweep output is NOT indexed, the swept inputs are NOT deleted, and FeeSupply is NOT
	// debited here — all three happen ATOMICALLY in HandleConfirmSpend (settleMigrationSweep)
	// under the sweep's SPV proof. Keeping the inputs in the registry keeps
	// AnyFundedSupersededGen true, so NN#3 blocks the next rotation until this sweep
	// confirms (guard-5 fix + A-F2 closed for FREE — the successor stays the active gen for
	// the whole pending window, matching the node's output-scoped signing check). The "d-"
	// signing record + TxSpendsList entry are written exactly as before, so the node side is
	// UNCHANGED (it reads only "p"/"d-", never "ms-").
	signingBytes, err := MarshalSigningData(signingData)
	if err != nil {
		return "", ce.WrapContractError(ce.ErrJson, err, "error marshalling migration signing data")
	}
	txId := tx.TxID()
	sdk.StateSetObject(constants.TxSpendsPrefix+txId, string(signingBytes))
	cs.TxSpendsList = append(cs.TxSpendsList, txId)
	sweepRecord := &MigrationSweep{
		InputIds:         inputIds,
		BtcFee:           btcFee,
		SuccessorAddress: successorAddress,
		SuccessorGen:     successorGen,
		BuildHeight:      currentLastHeight(), // L7-01: re-drive staleness clock
	}
	sdk.StateSetObject(constants.MigrationSweepPrefix+txId, string(MarshalMigrationSweep(sweepRecord)))
	// Dedicated migration-sweep index (BRK-1 council A-1): paired 1:1 with the "ms-"
	// record — appended here, removed at confirm — so pendingMigrationState scans only
	// in-flight sweeps, never the unprivileged-inflatable TxSpendsList.
	cs.MigrationSweeps = append(cs.MigrationSweeps, txId)

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

// pendingMigrationState scans the in-flight migration sweeps and returns (1) the set of
// input UTXO ids already committed to a pending sweep and (2) the SUM of those sweeps'
// reserved miner fees. The exclusion set stops a later tranche/retry from re-selecting an
// in-flight input (a double-sweep); the fee sum feeds the build-time reserve check so
// every deferred confirm-side fee debit is guaranteed to succeed. It iterates the
// DEDICATED cs.MigrationSweeps list (BRK-1 council A-1), NOT the general cs.TxSpendsList:
// MigrationSweeps is written only by the owner-only migrateVault path and is bounded by
// the handful of concurrent draining sweeps, so an unprivileged unmap flood that inflates
// TxSpendsList can never gas-DoS this scan into freezing rotation. FAIL-CLOSED: a record
// that cannot be decoded aborts the whole scan (never silently drop an exclusion or
// under-count the reserved fee). Deterministic: iterates the slice in order + keyed
// loads, no map ranging.
// HandleRedriveSweep re-drives a STUCK, never-confirming migration sweep (L7-01): it
// re-signs a REPLACEMENT over the sweep's EXACT reserved inputs (spec v2 H4) with a higher
// BIP-125 fee, so a fee-spiked / mempool-evicted sweep can finally confirm instead of
// wedging rotation forever (NN#3). Owner-gated + pause-gated at the entrypoint (D2/D5).
//
// Fund-safety: the replacement spends the IDENTICAL inputs, so Bitcoin confirms AT MOST ONE
// of {original, replacements} — no double-spend is physically possible. The replacement and
// original form one SPEND GROUP; a settle of EITHER clears the whole group atomically
// (clearSpendGroup, H2). The bumped fee is covered by the FeeSupply reserve checked here and
// debited only at settle for whichever member confirms (per-txid BtcFee → H3/P1).
func (cs *ContractState) HandleRedriveSweep(txId string) (string, error) {
	raw := sdk.StateGetObject(constants.MigrationSweepPrefix + txId)
	if raw == nil || *raw == "" {
		return "", ce.NewContractError(ce.ErrInput, "no in-flight migration sweep for that txid (already settled, or not a sweep)")
	}
	rec, err := UnmarshalMigrationSweep([]byte(*raw))
	if err != nil {
		return "", ce.NewContractError(ce.ErrStateAccess, "error decoding migration sweep record: "+err.Error())
	}

	// Staleness gate (D3): only re-drive a sweep that has genuinely failed to confirm for
	// RedriveStaleBlocks, so we never race a tx about to confirm. Hygiene, not safety.
	nowH := currentLastHeight()
	if rec.BuildHeight == 0 || nowH < rec.BuildHeight || nowH-rec.BuildHeight < constants.RedriveStaleBlocks {
		return "", ce.NewContractError(ce.ErrTransaction, "sweep not yet stale enough to re-drive")
	}

	// Fee to out-bid = the group's current HIGHEST committed fee (BIP-125 rule 3 must beat
	// every live mempool version, not only the passed txid). Group-of-one ⇒ this record's fee.
	gk := spendGroupKey(rec.InputIds)
	prevHighestFee := rec.BtcFee
	var group *SpendGroup
	if graw := sdk.StateGetObject(gk); graw != nil && *graw != "" {
		g, gerr := UnmarshalSpendGroup([]byte(*graw))
		if gerr != nil {
			// Fail CLOSED (build-council LOW): re-seeding a fresh group here would DROP the
			// prior members, leaving them dangling → H2. Refuse rather than corrupt the group.
			return "", ce.NewContractError(ce.ErrStateAccess, "corrupt spend-group object — refusing sweep re-drive")
		}
		group = g
		if g.HighestFee > prevHighestFee {
			prevHighestFee = g.HighestFee
		}
	}
	if group != nil && len(group.Members) >= constants.MaxSpendGroupMembers {
		return "", ce.NewContractError(ce.ErrTransaction, "sweep spend group has reached the re-drive member cap (cold-scan B)")
	}

	// Rebuild over EXACTLY the recorded inputs (never the selectors — those exclude reserved
	// inputs → a non-conflicting tx → real double-spend) reusing the recorded successor (H4).
	inputUtxos, err := getInputUtxos(rec.InputIds)
	if err != nil {
		return "", err
	}
	var total int64
	for _, u := range inputUtxos {
		total, err = safeAdd64(total, u.Amount)
		if err != nil {
			return "", ce.WrapContractError(ce.ErrArithmetic, err, "re-drive input total overflow")
		}
	}
	tx, witnessScripts, newFee, err := cs.buildMigrationTransaction(inputUtxos, total, rec.SuccessorAddress, prevHighestFee)
	if err != nil {
		// fee ceiling / dust: the bumped fee cannot fit under totalInputs/2 — the genuinely
		// un-re-drivable dust residual (spec v2 §3f) is a separate owner op; surface it here.
		return "", ce.Prepend(err, "cannot re-drive sweep (bumped fee exceeds the ceiling or leaves dust)")
	}

	// Reserve check (H1/D6): raising THIS group's reserve from prevHighestFee to newFee must
	// keep FeeSupply >= Σ(per-group max fees), so settleMigrationSweep's DEFERRED debit of the
	// confirmed member's newFee can never underflow (a post-L1 brick). pendingMigrationState
	// already counts this group at prevHighestFee; add only the delta. Fail-safe: abort BEFORE
	// signing (no state change; the gen keeps its UTXOs, the original stays settle-able).
	_, pendingFeeSum, err := cs.pendingMigrationState()
	if err != nil {
		return "", err
	}
	feeDelta, err := safeSubtract64(newFee, prevHighestFee)
	if err != nil {
		return "", ce.WrapContractError(ce.ErrArithmetic, err, "re-drive fee delta arithmetic")
	}
	feeNeeded, err := safeAdd64(pendingFeeSum, feeDelta)
	if err != nil {
		return "", ce.WrapContractError(ce.ErrArithmetic, err, "re-drive pending-fee sum overflow")
	}
	if cs.Supply.FeeSupply < feeNeeded {
		return "", ce.NewContractError(ce.ErrBalance, "insufficient fee reserve to cover the re-drive fee bump")
	}

	signingData, err := signSpendTransaction(tx, inputUtxos, witnessScripts)
	if err != nil {
		return "", ce.WrapContractError(ce.ErrTransaction, err, "error signing re-drive sweep")
	}
	signingBytes, err := MarshalSigningData(signingData)
	if err != nil {
		return "", ce.WrapContractError(ce.ErrJson, err, "error marshalling re-drive signing data")
	}
	newTxId := tx.TxID()
	if newTxId == txId {
		// The higher fee lowers the sweep output → a different txid; identical would alias the
		// original's records. Structurally unreachable, fail-closed anyway.
		return "", ce.NewContractError(ce.ErrTransaction, "re-drive produced an identical txid")
	}

	// Node side UNCHANGED (BRK-1): the "d-"/TxSpends entry drives signing + broadcast.
	sdk.StateSetObject(constants.TxSpendsPrefix+newTxId, string(signingBytes))
	cs.TxSpendsList = append(cs.TxSpendsList, newTxId)

	replRecord := &MigrationSweep{
		InputIds:         rec.InputIds,
		BtcFee:           newFee,
		SuccessorAddress: rec.SuccessorAddress,
		SuccessorGen:     rec.SuccessorGen,
		BuildHeight:      nowH,
	}
	sdk.StateSetObject(constants.MigrationSweepPrefix+newTxId, string(MarshalMigrationSweep(replRecord)))
	cs.MigrationSweeps = append(cs.MigrationSweeps, newTxId)

	// Spend group (D1-B): a first re-drive seeds it with {original, replacement}; a subsequent
	// one appends. HighestFee is the FeeSupply charge basis. O(1) — one group-object write, no
	// sibling rewrites, so an incomplete cleanup can never re-arm the freeze (H2).
	if group == nil {
		group = &SpendGroup{Members: []string{txId}}
	}
	group.Members = append(group.Members, newTxId)
	group.HighestFee = newFee
	sdk.StateSetObject(gk, string(MarshalSpendGroup(group)))

	return "redrive: old=" + txId + " new=" + newTxId + " fee=" + strconv.FormatInt(newFee, 10), nil
}

func (cs *ContractState) pendingMigrationState() (map[uint16]struct{}, int64, error) {
	excluded := make(map[uint16]struct{})
	// L7-01 D6: a re-driven sweep and its stuck original are DIFFERENT txids over the SAME
	// inputs (one spend group), each with its own "ms-" record + BtcFee — but only ONE can
	// ever confirm. Reserve ONE fee per group (the MAX committed, since a later member always
	// bumps higher), not the sum of members, else the reserve double-counts and over-holds
	// FeeSupply → wedges other migrations. Keyed by the shared spend-group key (min input id);
	// a group-of-one (no re-drive) reserves exactly its own fee, unchanged.
	groupMaxFee := make(map[string]int64)
	for _, txId := range cs.MigrationSweeps {
		raw := sdk.StateGetObject(constants.MigrationSweepPrefix + txId)
		if raw == nil || *raw == "" {
			continue // record already settled/cleared; nothing to exclude
		}
		rec, err := UnmarshalMigrationSweep([]byte(*raw))
		if err != nil {
			return nil, 0, ce.NewContractError(ce.ErrStateAccess, "error decoding migration sweep record: "+err.Error())
		}
		for _, id := range rec.InputIds {
			excluded[id] = struct{}{}
		}
		gk := spendGroupKey(rec.InputIds)
		if rec.BtcFee > groupMaxFee[gk] {
			groupMaxFee[gk] = rec.BtcFee
		}
	}
	var feeSum int64
	for _, f := range groupMaxFee {
		var err error
		feeSum, err = safeAdd64(feeSum, f) // order-independent: sum of bounded non-negatives
		if err != nil {
			return nil, 0, ce.WrapContractError(ce.ErrArithmetic, err, "pending migration fee sum overflow")
		}
	}
	return excluded, feeSum, nil
}

// settleMigrationSweep performs the atomic swap that HandleMigrateVault deferred (BRK-1
// delete-at-confirm), called from HandleConfirmSpend under the sweep's already-verified
// SPV proof: index the confirmed sweep's output(s) to the successor, delete the swept
// inputs, and debit the reserved miner fee. Conservation holds at this SINGLE committed
// step — Σ(UTXO) drops by (Σ inputs − Σ outputs) == BtcFee and FeeSupply drops by BtcFee,
// so Σ(UTXO) == ActiveSupply + FeeSupply is preserved. The record is TRUSTED, not
// re-derived (the SPV-proven txid commits to the outputs → the tx provably pays
// rec.SuccessorAddress and its output must carry the build-time rec.SuccessorGen to be
// spendable); a conservation ASSERT (>=1 output AND Σ outputs == Σ inputs − fee) guards a
// corrupt record. Fail-closed throughout. Idempotency is enforced ONE LAYER UP by the
// "ms-" absence gate in HandleConfirmSpend: a replay of an already-settled sweep finds no
// "ms-" record and skips this call entirely. The "input missing from registry" guard
// below is defense-in-depth for a CORRUPT state (an "ms-" record whose inputs were already
// removed) — it fails closed before any mutation rather than double-settling.
func (cs *ContractState) settleMigrationSweep(msgTx *wire.MsgTx, rec *MigrationSweep, blockHeight uint32) error {
	// Sum the swept input amounts from the registry (still present — delete-at-confirm).
	// A missing input means the sweep already settled (idempotent replay) or the record is
	// corrupt → fail closed BEFORE any mutation, never double-settle.
	var inputTotal int64
	for _, id := range rec.InputIds {
		found := false
		for i := range cs.UtxoList {
			if cs.UtxoList[i].Id == id {
				var aerr error
				inputTotal, aerr = safeAdd64(inputTotal, cs.UtxoList[i].Amount)
				if aerr != nil {
					return ce.WrapContractError(ce.ErrArithmetic, aerr, "migration input total overflow")
				}
				found = true
				break
			}
		}
		if !found {
			return ce.NewContractError(ce.ErrStateAccess, "migration sweep input missing from registry")
		}
	}

	// Index the sweep output(s) to the successor (trusting the recorded successor).
	outUtxos, err := indexMigrationOutputs(msgTx, rec.SuccessorAddress, cs.NetworkParams, rec.SuccessorGen)
	if err != nil {
		return err
	}
	if len(outUtxos) == 0 {
		return ce.NewContractError(ce.ErrTransaction, "migration sweep confirmed with no output to the successor")
	}
	var outputTotal int64
	for _, u := range outUtxos {
		outputTotal, err = safeAdd64(outputTotal, u.Amount)
		if err != nil {
			return ce.WrapContractError(ce.ErrArithmetic, err, "migration output total overflow")
		}
	}
	// Conservation ASSERT (adversarial pre-mortem): outputs == inputs − recorded fee.
	expected, err := safeSubtract64(inputTotal, rec.BtcFee)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "migration conservation arithmetic")
	}
	if outputTotal != expected {
		return ce.NewContractError(ce.ErrTransaction, "migration sweep conservation mismatch (outputs != inputs - fee)")
	}

	// Index the sweep output(s) as CONFIRMED.
	observedVouts := make([]uint32, 0, len(outUtxos))
	for _, u := range outUtxos {
		newId, aerr := cs.allocateConfirmedId()
		if aerr != nil {
			return aerr
		}
		cs.UtxoList = append(cs.UtxoList, UtxoRegistryEntry{Id: newId, Amount: u.Amount})
		saveUtxo(newId, u)
		observedVouts = append(observedVouts, u.Vout)
	}
	// D-1/C-1 (council HIGH): record the swept output(s) in the observed list so a later
	// topUpFeeReserve of the same outpoint cannot double-credit it (the sweep pays the successor's
	// untagged vault address, byte-identical to a fee-reserve deposit once that gen is active).
	if err := markOutpointsObserved(blockHeight, msgTx.TxID(), observedVouts); err != nil {
		return err
	}

	// Delete the swept inputs from the registry + state.
	for _, id := range rec.InputIds {
		cs.UtxoList = slices.DeleteFunc(cs.UtxoList, func(e UtxoRegistryEntry) bool { return e.Id == id })
		sdk.StateDeleteObject(getUtxoKey(id))
	}

	// Debit the reserved miner fee. Guaranteed >= 0 by the build-time reserve invariant
	// (FeeSupply >= Σ(pending fees)); the checks below are defense-in-depth for a corrupt
	// state, fail-closed rather than letting FeeSupply go negative.
	newFee, err := safeSubtract64(cs.Supply.FeeSupply, rec.BtcFee)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "migration fee debit arithmetic")
	}
	if newFee < 0 {
		return ce.NewContractError(ce.ErrBalance, "migration fee debit would underflow the fee reserve")
	}
	cs.Supply.FeeSupply = newFee

	return nil
}
