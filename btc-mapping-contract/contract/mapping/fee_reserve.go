package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"bytes"
	"strconv"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// fee_reserve.go — operator-funded migration fee reserve top-up.
//
// PROBLEM (council FeeSupply lens, verified at source). FeeSupply is credited ONLY by
// unmap vscFee (handlers.go), and vscFee is hard-coded to 0 (unmapping.go
// VscFeeMinSats/VscFeeRateBps). So FeeSupply is structurally 0, and the migration
// reserve gate (migration.go: FeeSupply < feeNeeded) fails on the FIRST tranche of the
// FIRST rotation → migration can never build → NN#3 permanently wedges rotation with no
// runtime recovery.
//
// WHY NOT DRAW THE FEE FROM THE SWEPT VALUE. map/unmap keep ActiveSupply == UserSupply
// in lock-step (no surplus), so netting the miner fee out of the swept value would push
// ActiveSupply < UserSupply — a fractional vault where the last withdrawer cannot be
// paid. The reserve MUST be funded from a source outside user principal.
//
// FIX (user decision, 2026-07-09): the OPERATOR funds it. HandleTopUpFeeReserve
// SPV-proves a real BTC deposit to the active vault's own address and credits FeeSupply
// by the deposited value, indexing the deposit as a normal confirmed active-gen UTXO so
// conservation is preserved exactly: Σ(UTXO) += value AND FeeSupply += value ⇒
// Σ(UTXO) == ActiveSupply + FeeSupply still holds, and ActiveSupply (== UserSupply) is
// untouched, so users stay fully backed. Over time migration draws FeeSupply DOWN (each
// settle debits btcFee while the swept output is btcFee smaller) and the operator tops it
// back UP — the operator's BTC is what absorbs the rotation's miner fees, never user
// principal. Solvency after a sweep: Σ' = A + (F − btcFee) = A + F' ≥ A == UserSupply
// (F' ≥ 0 by the reserve gate), so the users the vault owes are never diluted.
//
// ★ NEVER-TERMINAL (user requirement, 2026-07-09: "adding more btc should continue the
// migration automatically, never a situation where it can't be continued"). The
// migration fee-shortage abort writes NO state — the reserve gate in HandleMigrateVault
// sits BEFORE signing, the "d-"/"ms-" records, and the status transition, and a returned
// error reverts the whole tx — so a fee-starved migration leaves the retiring gen fully
// intact (same UTXOs, same status). A top-up simply lets the NEXT migrateVault tranche
// re-select the identical inputs and proceed. Migration ALWAYS continues; it can never
// terminally brick on fees. This op is therefore PERMISSIONLESS (a valid SPV proof of a
// real deposit is self-authorising — anyone may fund the reserve to un-wedge a rotation)
// and NOT pause-gated (it moves no funds OUT and can only help; the operator must be able
// to fund even during a pause so migration flows the instant it unpauses).
// InitTopUpProvenanceFloor pins the TOPUP-REPLAY-1 floor the first time it is
// called and is a no-op afterwards. Called from the addBlocks and seedBlocks
// exports, so it self-initialises from the oracle's ordinary header relay
// within one block of this code going live -- no migration and no operator
// step, which matters because an owner-driven step would leave the window open
// for however long the owner took.
//
// `height` is the FIRST height the relay adds, not the batch tip. Pinning at the
// tip stranded a deposit mined AFTER activation whenever the first relay carried
// more than one header: tip 1000, deposit at 1001, relay adds 1001-1003, floor
// 1003, and the deposit is refused as predating the floor -- permanently, since
// nothing else credits it (lordbutterfly, reviewing #39). The first added height
// is the earliest height this code could not already have seen, which is exactly
// the bound wanted.
//
// Still no grace window below that: any grace is exactly the replay window this
// closes. The remaining cost is that a deposit confirmed at or below the tip when
// the update goes live cannot fund the reserve, so the reserve should not be
// funded shortly before activation -- FeeSupply is 0 at that point, so no
// legitimate top-up is in flight, and funding it again costs a new deposit
// rather than a stuck rotation.
func InitTopUpProvenanceFloor(height uint32) {
	if v := sdk.StateGetObject(constants.V2TopUpFeeReserveFloorKey); v != nil && *v != "" {
		return
	}
	sdk.StateSetObject(constants.V2TopUpFeeReserveFloorKey, strconv.FormatUint(uint64(height), 10))
	sdk.Log("feereserve|floor-init|height=" + strconv.FormatUint(uint64(height), 10))
}

// topUpProvenanceFloor returns the pinned floor, and false when it is unset or
// unparseable.
//
// An unset floor REJECTS, and callers must treat !ok that way. This reverses an
// earlier decision in this file; the original argument is kept below because it
// is instructive about how it was wrong.
//
// Pinning still CANNOT be done lazily on the first top-up: a legitimate deposit
// always sits some confirmations BELOW the tip (requireConfirmationDepth insists
// on it), so a floor pinned at that moment would reject the very deposit that
// triggered it. The floor is pinned by the first addBlocks after activation, so
// "unset" means "this code is live and the oracle has not relayed yet".
//
// The original argument for ALLOWING during that window was that it is at most
// one relay, that rejecting would dent the NEVER-TERMINAL guarantee this file is
// built around, and that a replay is "an accounting fault, not a theft" because
// outpointRegistered stops a coin being re-indexed. Two of those three premises
// do not survive contact with mainnet (lordbutterfly, reviewing #39):
//
//   - The window is not short and needs no race won. Mainnet addBlocks gaps over
//     the last 100 relays run a 10-minute median and a 74-minute maximum, and
//     the activation height of a timelocked update is PUBLIC. An attacker picks
//     the moment; it is not a race.
//   - It is not merely an accounting fault. Replaying a real, already-spent coin
//     (426a54eb:1, against mainnet state at activation, on a contract test
//     harness) produces a phantom coin, FeeSupply 24,998, and trips the THEFT
//     HALT -- which re-arms after a clear. That is a liveness denial on the
//     vault, not a rounding error.
//   - And refusing during the window costs nothing real: anything provable
//     before the first relay is below the floor that relay pins, so it would be
//     refused a moment later anyway. The NEVER-TERMINAL guarantee is preserved
//     by a NEW deposit, which is what the refusal message asks for.
//
// constants.go's own comment on V2TopUpFeeReserveFloorKey already said "an unset
// floor REJECTS" -- the code and the constant disagreed, and the constant was
// right.
func topUpProvenanceFloor() (uint32, bool) {
	raw := sdk.StateGetObject(constants.V2TopUpFeeReserveFloorKey)
	if raw == nil || *raw == "" {
		return 0, false
	}
	h, err := strconv.ParseUint(*raw, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(h), true
}

func (cs *ContractState) HandleTopUpFeeReserve(txData *VerificationRequest) error {
	if txData == nil {
		return ce.NewContractError(ce.ErrInput, "tx_data required")
	}
	rawTx, err := txData.rawTx()
	if err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "invalid raw tx")
	}
	// VR2-25: this is the THIRD permissionless SPV-crediting path, and it needs the same
	// maturity gate as its two siblings (HandleMap's deposit gate, HandleConfirmSpend's
	// spend gate — both call requireConfirmationDepth). A top-up both indexes a new
	// confirmed UTXO and credits FeeSupply, so a reorg that orphans the top-up's block
	// leaves a phantom UTXO in the registry and an inflated reserve: Σ(UTXO) then claims
	// coins Bitcoin does not hold, the reserve gate passes on backing that does not exist,
	// and a migration that selects the phantom input builds a sweep L1 will not accept.
	// Merkle inclusion alone proves the tx was in A block, never that the block survived.
	// Same helper, same number, so the three gates cannot drift apart.
	if err := cs.requireConfirmationDepth(txData.BlockHeight, "fee-reserve deposit"); err != nil {
		return err
	}
	if err := verifyTransaction(txData, rawTx); err != nil {
		return ce.Prepend(err, "error verifying fee-reserve deposit")
	}
	var msgTx wire.MsgTx
	if err := msgTx.Deserialize(bytes.NewReader(rawTx)); err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "could not deserialize fee-reserve deposit tx")
	}
	txId := msgTx.TxID()

	// D-1/C-1 (council HIGH): a fee-reserve top-up must be an EXTERNAL deposit, NEVER a
	// vault-authored spend. An unmap change output and a migration sweep output pay the SAME
	// untagged vault address a top-up matches; without this guard anyone could point topUp at an
	// already-broadcast change/sweep tx and double-credit FeeSupply + double-index the outpoint
	// (a phantom UTXO — Σ==Active+Fee stays balanced because both sides inflate, so no assert
	// catches it → masked insolvency / eventual double-spend). This closes the PRE-settle window
	// (L1-confirmed, not-yet-settled): the vault spend still holds a live "us-"/"ms-" record or a
	// TxSpendsList entry. The POST-settle window is closed by the settle paths recording their
	// outputs in the observed list (isObserved, below).
	if v := sdk.StateGetObject(constants.PendingUnmapPrefix + txId); v != nil && *v != "" {
		return ce.NewContractError(ce.ErrInput, "fee-reserve tx is an in-flight unmap, not a deposit")
	}
	if v := sdk.StateGetObject(constants.MigrationSweepPrefix + txId); v != nil && *v != "" {
		return ce.NewContractError(ce.ErrInput, "fee-reserve tx is an in-flight migration sweep, not a deposit")
	}
	// L10-1 (FULL-PRUNED 2026-07-09): O(1) keyed membership instead of an O(N) scan of
	// the permissionless-inflatable TxSpendsList. A pending vault spend ALWAYS has a
	// "d-<txid>" signing-data record written in lockstep with its TxSpendsList entry
	// (handlers.go / migration.go add both; the settle paths delete both), so the record
	// IS the pending-spend membership — a flood of pending unmaps can no longer make this
	// per-deposit check O(N).
	if d := sdk.StateGetObject(constants.TxSpendsPrefix + txId); d != nil && *d != "" {
		return ce.NewContractError(ce.ErrInput, "fee-reserve tx is a pending vault spend, not a deposit")
	}
	// AB-1: an ABANDONED migration sweep is also a vault-authored spend, but abandoning it
	// deletes its "ms-"/"d-" records and TxSpends entry (clearSpendGroup) and leaves only an
	// "sa-<txid>" record - so the three guards above no longer catch it. Without this guard,
	// a top-up pointed at an abandoned-but-not-yet-settled sweep would credit FeeSupply now,
	// and settleAbandonedSweep would index + credit the SAME output again when it confirms
	// (double credit, phantom outpoint). An abandoned sweep that confirms settles through
	// confirmSpend, never through a top-up; fund the reserve with a real external deposit.
	if v := sdk.StateGetObject(constants.AbandonedSweepPrefix + txId); v != nil && *v != "" {
		return ce.NewContractError(ce.ErrInput, "fee-reserve tx is an abandoned migration sweep, not a deposit")
	}

	// TOPUP-REPLAY-1: the deposit must be confirmed at or above the provenance
	// floor. Placed after the four vault-spend guards above deliberately -- they
	// identify exactly WHY a tx is not a deposit, and a provenance refusal in
	// front of them would mask that with a less useful message.
	floor, haveFloor := topUpProvenanceFloor()
	if !haveFloor {
		// The floor is pinned by the first addBlocks after activation, so this
		// is the window between the code going live and the oracle's next
		// relay -- a 10-minute median on mainnet but up to 74, at a publicly
		// known activation height. Refusing costs nothing real: a deposit
		// provable now is below the floor that relay will pin, so it would be
		// refused a moment later anyway.
		return ce.NewContractError(ce.ErrInput,
			"fee-reserve provenance floor is not pinned yet (no header relayed since activation); "+
				"retry after the next addBlocks")
	}
	if txData.BlockHeight < floor {
		return ce.NewContractError(ce.ErrInput,
			"fee-reserve deposit at height "+strconv.FormatUint(uint64(txData.BlockHeight), 10)+
				" predates the provenance floor "+strconv.FormatUint(uint64(floor), 10)+
				"; fund the reserve with a new deposit")
	}

	// Derive the untagged address of every generation that can still hold funds (the same
	// set the deposit path matches: depositAddressGenerations, active first) and tag each
	// matched output with the generation it paid, so it is a normal, spendable UTXO of that
	// generation: an active-gen output is fungible backing, a retiring/draining-gen output is
	// swept to the successor by the migration like any other. STRAND-1: this used to match
	// the ACTIVE generation only, so a top-up paid to a retiring generation's address was
	// refused and its BTC sat unindexed. THORChain credits an inbound to a retiring vault and
	// migrates it (only an inactive vault's inbound is refunded); Chainflip consolidates the
	// previous key's UTXOs. A pre-fold / keyless deploy derives an address nothing pays → the
	// "no matching output" abort below (can't fund a vault that doesn't exist).
	reserveGens := make(map[string]uint32)
	for _, gk := range cs.depositAddressGenerations() {
		addr, _, aerr := createP2WSHAddressWithBackup(gk.primary, gk.backup, nil, cs.NetworkParams)
		if aerr != nil {
			return ce.WrapContractError(ce.ErrTransaction, aerr, "error deriving fee-reserve vault address")
		}
		if _, dup := reserveGens[addr]; !dup {
			reserveGens[addr] = gk.generation
		}
	}

	// Dedup via the shared observed list (the exact mechanism the map deposit path uses), so
	// a replay of topUpFeeReserve — or a normal map of the same tx — can never double-credit
	// the same output. Consistent with pruning: once the block header is pruned the deposit
	// can no longer be SPV-verified at all (verifyTransaction above fails first), so a replay
	// outside the retention window is blocked even without the observed entry.
	observedList := loadObservedList(txData.BlockHeight)
	var credited int64
	changed := false
	dustSkipped := false
	// 18o: the V-1 dust floor applies here too. The deposit path (mapping.go
	// indexOutputs) skips a sub-MinDepositSats output once a superseded
	// generation exists, because such an output can never be swept economically
	// and, sitting on a superseded generation, permanently deadlocks rotation
	// (NN#3 - AnyFundedSupersededGen never sees that generation empty). This
	// path had no floor at all, and it is strictly MORE exposed than the
	// deposit path: STRAND-1 made it tag outputs with whichever generation
	// they paid, retiring and draining included, so dust routed through a
	// top-up lands precisely on the generations where it wedges the drain.
	// Same gate as the deposit path, so a pre-rotation deploy is unaffected.
	enforceDustFloor := hasSupersededGen(cs.Vaults)
	for index, txOut := range msgTx.TxOut {
		_, addrs, _, aerr := txscript.ExtractPkScriptAddrs(txOut.PkScript, cs.NetworkParams)
		if aerr != nil {
			return ce.WrapContractError(ce.ErrInput, aerr, "error extracting fee-reserve output address")
		}
		if len(addrs) != 1 {
			continue
		}
		gen, isReserve := reserveGens[addrs[0].EncodeAddress()]
		if !isReserve {
			continue
		}
		// Cap at the uint48 registry width exactly like the deposit/change/migration paths.
		if txOut.Value > constants.MaxUtxoAmount {
			return ce.NewContractError(ce.ErrInput, "fee-reserve deposit output exceeds maximum utxo amount")
		}
		// 18o: per-output SKIP, not a tx abort - mirroring the deposit path, so a
		// top-up carrying one fundable and one dust output still credits the
		// fundable one. That keeps this op NEVER-TERMINAL: funding the reserve
		// above the floor always works, so dust can never brick a rotation here
		// either by being indexed or by being rejected.
		if enforceDustFloor && txOut.Value < constants.MinDepositSats {
			sdk.Log("feereserve|dust-skip|txid=" + txId + "|vout=" + strconv.Itoa(index) +
				"|sats=" + strconv.FormatInt(txOut.Value, 10))
			dustSkipped = true
			continue
		}
		entry, eerr := makeObservedEntry(txId, uint32(index))
		if eerr != nil {
			return ce.WrapContractError(ce.ErrInput, eerr, "error creating observed entry")
		}
		if isObserved(observedList, entry) {
			continue // already credited by a prior top-up (or map) of this same output
		}
		// UPG-1/UPG-2: an output already registered as a live vault UTXO must never be indexed
		// again. A v2 settle records its output in the observed list (caught just above), but an
		// output indexed before that discipline existed - a legacy "main"-era unmap change or
		// migration sweep carried over by an IN-PLACE #29 upgrade - has no observed entry, so
		// without this check a top-up pointed at that already-held outpoint would index it a
		// SECOND time (phantom duplicate UTXO, FeeSupply inflated, false theft-halt, first sweep
		// double-spends). Deploy-mode-agnostic: correct whether #29 deploys fresh or in place.
		if cs.outpointRegistered(txId, uint32(index)) {
			continue
		}
		internalId, ierr := cs.allocateConfirmedId()
		if ierr != nil {
			return ierr
		}
		utxo := &Utxo{
			TxId:       txId,
			Vout:       uint32(index),
			Amount:     txOut.Value,
			PkScript:   txOut.PkScript,
			Tag:        nil, // untagged vault address, exactly like an unmap change output
			Generation: gen,
		}
		cs.UtxoList = append(cs.UtxoList, UtxoRegistryEntry{Id: internalId, Amount: txOut.Value})
		saveUtxo(internalId, utxo)
		observedList = append(observedList, entry)
		credited, err = safeAdd64(credited, txOut.Value)
		if err != nil {
			return ce.WrapContractError(ce.ErrArithmetic, err, "fee-reserve credit overflow")
		}
		changed = true
	}
	if !changed {
		if dustSkipped {
			// Distinguish "wrong address" from "right address, below the floor",
			// or the operator cannot tell why a real deposit credited nothing.
			return ce.NewContractError(ce.ErrInput,
				"fee-reserve output(s) pay a vault address but are below the minimum deposit of "+
					strconv.FormatInt(constants.MinDepositSats, 10)+" sats")
		}
		return ce.NewContractError(ce.ErrInput, "no output pays a vault fee-reserve address")
	}
	saveObservedList(txData.BlockHeight, observedList)

	// Credit FeeSupply (the ONLY mutation to Supply — ActiveSupply/UserSupply untouched).
	// Σ(UTXO) rose by `credited` above; FeeSupply rises by the same, preserving conservation.
	newFee, err := safeAdd64(cs.Supply.FeeSupply, credited)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "fee supply overflow")
	}
	cs.Supply.FeeSupply = newFee
	sdk.Log("feereserve|topup|txid=" + txId + "|credited=" + strconv.FormatInt(credited, 10) +
		"|feeSupply=" + strconv.FormatInt(newFee, 10))
	return nil
}

// outpointRegistered reports whether a confirmed UTXO for (txId, vout) already exists in
// the registry (UPG-1/UPG-2 guard for HandleTopUpFeeReserve). O(live UTXOs) and only on
// the cold, operator-driven top-up path - not the hot permissionless deposit path - so it
// does not reintroduce the L10-1 scan concern. Fail-open on an unreadable blob (continue):
// a top-up is NEVER-TERMINAL (it can only add funds and must always be able to un-wedge a
// rotation), so one corrupt unrelated UTXO must not brick it; the main-era change output
// this guards against is itself a normally-indexed, readable UTXO.
func (cs *ContractState) outpointRegistered(txId string, vout uint32) bool {
	for _, e := range cs.UtxoList {
		u, err := loadUtxo(e.Id)
		if err != nil || u == nil {
			continue
		}
		if u.TxId == txId && u.Vout == vout {
			return true
		}
	}
	return false
}
