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
// dust UTXO(s) from the registry and debits ActiveSupply+UserSupply in lock-step (I1
// Σ(UTXO)==ActiveSupply+FeeSupply and I2 ActiveSupply==UserSupply both held EXACT), so the
// gen can then drain via the existing DRAINING→INACTIVE→PURGED reconciler
// (ReconcileRetiringVaults, vault_lifecycle.go, left UNCHANGED) and NN#3 releases. The
// depositor's own VSC balance is deliberately NOT touched: the Utxo blob carries no
// recipient (only AddressMetadata.Recipient does, consumed once at credit time and never
// persisted per-UTXO), so an exact per-account claw-back of an ALREADY-credited legacy
// dust UTXO is infeasible without a schema change. This accepts a bounded, sub-floor-
// unrealizable I3 (Σ(balances)==UserSupply) slack for the rare legacy case — see the
// doc comment on isResidualUnsweepableAtMinFee and BUILD-MAP §3 option (b). Magi has no
// Reserve to fabricate backing from, so protocol solvency (I1) is what is protected, not
// I3 exactness.

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

	// The exclusion set: every UTXO id already committed to an in-flight migration sweep.
	// The fee sum (second return) is irrelevant here — this op never builds a sweep.
	excluded, _, err := cs.pendingMigrationState()
	if err != nil {
		return "", err
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

		for _, id := range a.ids {
			cs.UtxoList = slices.DeleteFunc(cs.UtxoList, func(e UtxoRegistryEntry) bool { return e.Id == id })
			sdk.StateDeleteObject(getUtxoKey(id))
		}

		newActive, serr := safeSubtract64(cs.Supply.ActiveSupply, a.sum)
		if serr != nil {
			return "", ce.WrapContractError(ce.ErrArithmetic, serr, "dust write-off active supply underflow")
		}
		cs.Supply.ActiveSupply = newActive
		newUser, serr := safeSubtract64(cs.Supply.UserSupply, a.sum)
		if serr != nil {
			return "", ce.WrapContractError(ce.ErrArithmetic, serr, "dust write-off user supply underflow")
		}
		cs.Supply.UserSupply = newUser

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
		sdk.Log("dust-writeoff|gen=" + genStr + "|sats=" + satsStr)
	}

	if len(writtenOff) == 0 {
		return "write-off: nothing to write off", nil
	}
	return "write-off: " + strings.Join(writtenOff, ","), nil
}
