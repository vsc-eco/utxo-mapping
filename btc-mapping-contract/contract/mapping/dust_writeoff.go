package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// dust_writeoff.go — V-1 dust-escape fix. A ~600-sat (or smaller) deposit landed on a
// SUPERSEDED (retiring/draining/inactive) generation's still-matchable address is
// un-sweepable at ANY fee rate (below the L1 dust floor once the sweep's own miner fee is
// subtracted) — buildMigrationTransaction (migration.go:186, :189-195) aborts every time,
// the gen never reaches registry-empty, AnyFundedSupersededGen (NN#3, migration.go:87)
// stays true, and the next createKey is permanently blocked (main.go CreateKey). This is
// the PRIMARILY prevention half's escape hatch: the min-deposit floor (mapping.go
// indexOutputs) stops any FUTURE dust deposit from ever being credited once rotation is
// live, so writeOffDust only ever has legacy (pre-floor / pre-rotation) dust to clean up —
// see BUILD-MAP §3.
//
// HandleWriteOffDust force-retires such a provably-un-sweepable residual: it deletes the
// dust UTXO(s) from the registry and debits the operator's FEE RESERVE by the same amount,
// so the gen can then drain via the existing DRAINING→INACTIVE→PURGED reconciler
// (ReconcileRetiringVaults, vault_lifecycle.go, left UNCHANGED) and NN#3 releases.
//
// VR2-15 — WHY THE RESERVE AND NOT USER SUPPLY. The write-off used to debit
// ActiveSupply+UserSupply in lock-step. That held I1 (Σ(UTXO)==ActiveSupply+FeeSupply) and
// I2 (ActiveSupply==UserSupply), but it broke I3 (Σ(balances)==UserSupply): the dust
// depositor's own balance was never debited, because the Utxo blob carries no recipient
// (only AddressMetadata.Recipient does, consumed once at credit time and never persisted
// per-UTXO). The resulting slack is NOT a reporting artifact — HandleUnmap decrements
// UserSupply with safeSubtract64 on every withdrawal, so once the aggregate ran short of
// the balances it stood for, the LAST withdrawers hit the underflow and their withdrawals
// reverted permanently, with no in-band way to clear it. The victims were whichever users
// withdrew last, not the depositor whose dust caused it.
//
// Clawing the credit back per-account was the other candidate and is strictly worse: it
// needs a per-UTXO recipient in the blob, and it can still FAIL when the depositor has
// already transferred the phantom credit away — at which point the write-off either
// reverts (NN#3 stays wedged: the V-1 deadlock this whole file exists to break) or forces a
// negative balance. A fix that can re-open the bug it was written for is not a fix.
//
// So the residual is charged where this contract already charges every other rotation cost
// that must not touch principal: the operator-funded reserve (fee_reserve.go, whose own doc
// names this exact failure — "a fractional vault where the last withdrawer cannot be
// paid"). Σ(UTXO) and FeeSupply fall by the identical amount, so I1 still holds, while
// ActiveSupply and UserSupply are untouched and I2 and I3 stay EXACT rather than acquiring
// slack. The depositor keeps the credit the protocol genuinely still owes them; the
// operator's BTC absorbs sats that were never economically recoverable by anyone.

// isResidualUnsweepableAtMinFee reports whether sweeping a generation's residual (total
// value `total` across `n` confirmed inputs) in a single tranche would abort EVEN AT the
// fixed protocol-minimum fee rate (1 sat/vbyte) — i.e. it is provably un-sweepable at
// EVERY rate ≥ 1, since the real sweep fee only grows with the oracle's live rate (rate
// is monotonic in fee). Mirrors buildMigrationTransaction's two abort conditions
// (migration.go:186 fee>total/2, :189-195 sendAmount<=dustThreshold) exactly, but priced
// at the FIXED floor rather than cs.Supply.BaseFeeRate.
//
// Deliberately NEVER reads the oracle's live BaseFeeRate: reusing it here would let a
// high/rogue BaseFeeRate inflate the "dust" ceiling and force write-off (destruction) of
// large legitimate UTXOs — the subtle bug this design specifically avoids (BUILD-MAP §1).
// The ONLY rate this predicate ever references is the fixed protocol minimum, the floor of
// clampedFeeRate (unmapping.go).
//
// count-aware by design: a flat `total <= dustThreshold` constant alone cannot distinguish
// "100 dust inputs summing 9000 sats (un-sweepable: rate-1 fee ~8800)" from "1 input of
// 9000 (sweepable: 9000-144)" — only pricing the ACTUAL sweep at the fixed minimum rate is
// both complete (catches every genuinely stuck residual) and false-positive-free (never
// writes off a residual that could still be swept).
//
// total and n are always non-negative, bounded well within int64 (individual UTXO amounts
// are capped at MaxUtxoAmount = 2^48-1, and the caller accumulates `total` via safeAdd64
// before calling this), so the arithmetic here needs no additional overflow guards.
func isResidualUnsweepableAtMinFee(amounts []int64) bool {
	if len(amounts) == 0 {
		return false
	}

	// VR2-16: judge the residual on the best tranche a sweep could actually BUILD,
	// not on the whole pile priced as one transaction.
	//
	// The old form took (total, n) and priced every input together. That is not how
	// sweeping works, and the difference destroys money: a generation holding one
	// meaningful output among a pile of dust prices as hopeless on the aggregate —
	// the dust drags the combined fee above half the combined value — while the
	// meaningful output on its own clears both abort conditions comfortably. Write-off
	// deletes everything it condemns, so that output was burned. Aggregate pricing
	// also overstates the fee for any residual larger than one tranche, since a real
	// sweep is capped at MaxMigrationInputs and drains in successive passes.
	//
	// Sorting descending and testing every prefix finds the best tranche exactly.
	// Each additional input adds a fixed ~88 sats of fee at the minimum rate, so a
	// low-value input can only worsen both conditions; taking the largest inputs
	// first and stopping wherever it stops helping is therefore optimal, and testing
	// all prefixes needs no reasoning about where that point is. Deterministic: a
	// total order on (amount desc, then value) gives every node the same sequence.
	sorted := make([]int64, 0, len(amounts))
	for _, a := range amounts {
		if a > 0 {
			sorted = append(sorted, a)
		}
	}
	if len(sorted) == 0 {
		return false // nothing to sweep is not the same as provably stuck
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] > sorted[j] })

	limit := len(sorted)
	if limit > constants.MaxMigrationInputs {
		limit = constants.MaxMigrationInputs
	}

	var trancheTotal int64
	for k := 1; k <= limit; k++ {
		trancheTotal += sorted[k-1]
		// Same sizing as estimateFee/estimateVSize (unmapping.go): k inputs (41B each,
		// 72+112+5B witness stack) + 1 consolidated output (43B) + 10B base tx
		// overhead. At the fixed minimum rate (1 sat/vbyte) fee == vsize.
		fee1 := estimateVSize(10+int64(k)*41+43, int64(k)*(72+112+5))
		if fee1 <= trancheTotal/2 && trancheTotal-fee1 > dustThreshold {
			return false // this tranche is buildable, so the residual is not stuck
		}
	}
	return true
}

// HandleWriteOffDust scans every SUPERSEDED (retiring/draining/inactive) generation's
// confirmed residual and force-retires (deletes + debits Supply for) any generation whose
// TOTAL residual is provably un-sweepable at the fixed minimum fee rate
// (isResidualUnsweepableAtMinFee) — the V-1 dust-escape fix. Never touches the ACTIVE
// generation (only Retiring/Draining/Inactive vaults are ever considered) and never a
// residual the predicate says IS still sweepable (false-positive-free — that residual is
// left for the normal migrateVault sweep). Excludes any UTXO already committed to an
// in-flight migration sweep ("ms-" record, via pendingMigrationState) or an in-flight
// unmap reservation ("ru-" marker, via isUtxoReserved) — deleting either would strand that
// pending spend at settle ("input missing from registry", migration.go:444 /
// handlers.go:484). Owner-only + pause-gated by the caller (main.go, mirroring
// retireVault/migrateVault) — a write-off deletes UTXOs and debits supply, so it must not
// run during an emergency pause.
//
// height is threaded through for signature parity with the sibling lifecycle op
// (ReconcileRetiringVaults) and so the caller's abort-on-unavailable-height guard
// (main.go, mirroring retireVault) fires before any state is touched; this op needs no
// height-based logic of its own — it never sets InactiveHeight (that stays
// ReconcileRetiringVaults' job; a written-off Retiring gen is flipped to Draining so the
// existing reconciler carries it Draining→Inactive→Purged unchanged).
//
// Deterministic: slice-order scans (cs.UtxoList, cs.Vaults) + keyed loads; the
// per-generation accumulator is a map used ONLY for keyed lookups (by generation number),
// never ranged — every consensus-re-executing node reaches the identical deletions and the
// identical supply debit.
func (cs *ContractState) HandleWriteOffDust(height uint32) (string, error) {
	_ = height // signature parity with ReconcileRetiringVaults — see doc comment above

	FoldLegacyGen0IfNeeded()
	vaults, nextGen, activeGen, err := LoadVaultState()
	if err != nil {
		return "", err
	}
	// Refresh from state (mirrors every other key-ceremony op) so SaveToState persists a
	// consistent list even if FoldLegacyGen0IfNeeded just populated it this call.
	cs.Vaults, cs.NextGen, cs.ActiveGen = vaults, nextGen, activeGen

	// The exclusion set: every UTXO id already committed to an in-flight migration sweep,
	// and the fees those sweeps have already reserved.
	//
	// The fee sum is NOT irrelevant here even though this op never builds a sweep. The
	// migration design defers each sweep's FeeSupply debit to its confirm, and keeps that
	// debit safe by maintaining FeeSupply >= Σ(pending sweep fees) at every build — which
	// is what makes a confirm-side debit "GUARANTEED to succeed (never a post-L1 brick)"
	// (migration.go). A write-off that spent the reserve down without respecting that sum
	// could leave an ALREADY-BROADCAST sweep unable to settle: exactly the "permanent
	// registry <-> L1 divergence + a wedged sweep that re-aborts forever" the deferred
	// debit was designed to avoid. So the write-off may only ever spend the reserve
	// SURPLUS over what in-flight sweeps have already claimed.
	excluded, pendingFeeSum, err := cs.pendingMigrationState()
	if err != nil {
		return "", err
	}
	// Never negative in practice (the build-time gate maintains the invariant), but a
	// corrupt or partially-migrated state must not wrap into a huge positive budget.
	availableReserve := cs.Supply.FeeSupply - pendingFeeSum
	if availableReserve < 0 {
		availableReserve = 0
	}

	type genAccum struct {
		sum int64
		n   int64
		ids []uint16
		// VR2-16: the individual amounts, because whether a residual is genuinely
		// stuck depends on the best tranche that could be built from it, not on the
		// aggregate. Pricing the sum alone condemned — and deleted — residuals that
		// ordinary migration could still drain.
		amounts []int64
	}
	accum := make(map[uint32]*genAccum)
	for _, entry := range cs.UtxoList {
		if _, inflight := excluded[entry.Id]; inflight {
			continue
		}
		if isUtxoReserved(entry.Id) {
			continue
		}
		u, lerr := loadUtxo(entry.Id)
		if lerr != nil {
			return "", lerr
		}
		a := accum[u.Generation]
		if a == nil {
			a = &genAccum{}
			accum[u.Generation] = a
		}
		newSum, aerr := safeAdd64(a.sum, u.Amount)
		if aerr != nil {
			return "", ce.WrapContractError(ce.ErrArithmetic, aerr, "dust write-off generation total overflow")
		}
		a.sum = newSum
		a.n++
		a.ids = append(a.ids, entry.Id)
		a.amounts = append(a.amounts, u.Amount)
	}

	var writtenOff []string
	for i := range cs.Vaults {
		v := &cs.Vaults[i]
		if v.Status != VaultStatusRetiring && v.Status != VaultStatusDraining && v.Status != VaultStatusInactive {
			continue // never the Active generation (nor Pending/Purged)
		}
		a, ok := accum[v.Generation]
		if !ok || a.sum <= 0 {
			continue // nothing held by this generation (after exclusions)
		}
		if !isResidualUnsweepableAtMinFee(a.amounts) {
			continue // genuinely sweepable — leave it for the normal migrateVault sweep
		}

		// VR2-15: the write-off is a ROTATION COST, so it is charged to the operator's
		// fee reserve — never to user principal. Charge the whole residual or none of
		// it; a partial write-off would delete UTXOs whose value no reserve covered and
		// re-open exactly the solvency break this gate exists to prevent.
		//
		// Reserve-short is a LIVENESS stall, not a terminal state, and it is cleared the
		// same way every other reserve shortage in this contract is: HandleTopUpFeeReserve
		// is permissionless and not pause-gated, so anyone may fund the reserve and the
		// NEXT writeOffDust call picks this generation up unchanged. Mirrors the migration
		// reserve gate (migration.go) exactly: the check sits BEFORE any mutation, the
		// skip writes no state, and the generation is left fully intact.
		if availableReserve < a.sum {
			sdk.Log("dust-writeoff|skip|gen=" + strconv.FormatUint(uint64(v.Generation), 10) +
				"|sats=" + strconv.FormatInt(a.sum, 10) +
				"|feeSupply=" + strconv.FormatInt(cs.Supply.FeeSupply, 10) +
				"|pendingSweepFees=" + strconv.FormatInt(pendingFeeSum, 10) +
				"|available=" + strconv.FormatInt(availableReserve, 10) +
				"|reason=reserve-short")
			continue
		}

		for _, id := range a.ids {
			cs.UtxoList = slices.DeleteFunc(cs.UtxoList, func(e UtxoRegistryEntry) bool { return e.Id == id })
			sdk.StateDeleteObject(getUtxoKey(id))
		}

		// Debit the RESERVE, not user principal (VR2-15). Conservation, exactly:
		// Sigma(UTXO) fell by a.sum when the ids above were deleted, and FeeSupply falls by
		// the same a.sum, so I1 (Sigma(UTXO) == ActiveSupply + FeeSupply) holds. ActiveSupply
		// and UserSupply are untouched, so I2 (ActiveSupply == UserSupply) and I3
		// (Sigma(balances) == UserSupply) both stay EXACT rather than acquiring slack.
		//
		// The old form debited ActiveSupply+UserSupply. That held I1 and I2 but silently
		// broke I3: the dust depositor's balance was never debited (the Utxo blob carries no
		// recipient), so Sigma(balances) exceeded UserSupply by a.sum forever. UserSupply is
		// not merely a report — HandleUnmap decrements it with safeSubtract64 on every
		// withdrawal, so once the aggregate ran short, the LAST withdrawers underflowed and
		// their withdrawals reverted permanently. The victims were whichever users happened
		// to withdraw last, not the depositor whose dust caused it. Charging the reserve
		// removes the discrepancy at its source instead of trying to claw back a credit that
		// may already have been transferred away.
		newFee, serr := safeSubtract64(cs.Supply.FeeSupply, a.sum)
		if serr != nil {
			return "", ce.WrapContractError(ce.ErrArithmetic, serr, "dust write-off fee supply underflow")
		}
		cs.Supply.FeeSupply = newFee
		// Keep the running budget in step, so writing off a SECOND generation in the same
		// call cannot spend the same surplus twice.
		availableReserve -= a.sum

		// A Retiring gen that was carrying ONLY unsweepable dust has never transitioned to
		// Draining (HandleMigrateVault's build aborts before that flip). Flip it here so the
		// now-empty gen enters the existing DRAINING→INACTIVE→PURGED reconciler unchanged.
		// A Draining or Inactive gen is left as-is — both already flow through
		// ReconcileRetiringVaults from here.
		if v.Status == VaultStatusRetiring {
			v.Status = VaultStatusDraining
		}

		genStr := strconv.FormatUint(uint64(v.Generation), 10)
		satsStr := strconv.FormatInt(a.sum, 10)
		writtenOff = append(writtenOff, "gen="+genStr+":sats="+satsStr)
		sdk.Log("dust-writeoff|gen=" + genStr + "|sats=" + satsStr +
			"|chargedTo=feeReserve|feeSupply=" + strconv.FormatInt(newFee, 10))
	}

	if len(writtenOff) == 0 {
		return "write-off: nothing to write off", nil
	}
	return "write-off: " + strings.Join(writtenOff, ","), nil
}

