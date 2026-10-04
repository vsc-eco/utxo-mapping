package mapping

import "testing"

// VR2-16: write-off must never destroy a residual that an ordinary migration
// could still drain.
//
// isResidualUnsweepableAtMinFee decides whether a superseded generation's
// remaining coins are provably stuck, and HandleWriteOffDust DELETES everything it
// says yes to. It priced the whole generation as ONE sweep of all n inputs. Real
// sweeps do not work that way: getMigrationInputs caps a tranche at
// MaxMigrationInputs, and more importantly a sweep may take the VALUABLE inputs
// and leave the dust behind.
//
// So a generation holding one meaningful UTXO among a pile of dust priced as
// "unsweepable" on the aggregate — the dust dragged the whole-set fee above half
// the total — and the meaningful UTXO was destroyed along with it, even though
// sweeping it alone comfortably clears both abort conditions.
//
// The predicate now asks the question that actually matters: is there ANY tranche
// the migration could build that would succeed? Only if none exists is the
// residual genuinely stuck.
func TestVR216_ResidualWithOneSweepableUtxoIsNotWrittenOff(t *testing.T) {
	// Nine 1-sat outputs and one worth 1800. The dust is what makes the aggregate
	// look hopeless.
	amounts := []int64{1800, 1, 1, 1, 1, 1, 1, 1, 1, 1}

	var total, n int64
	for _, a := range amounts {
		total += a
		n++
	}

	// The old aggregate pricing: fee for all ten inputs against the combined value.
	aggregateFee := estimateVSize(10+n*41+43, n*(72+112+5))
	if aggregateFee <= total/2 {
		t.Fatalf("fixture no longer exercises the bug: aggregate fee %d must exceed "+
			"half of %d for the old predicate to call this unsweepable", aggregateFee, total)
	}

	// But the 1800-sat output on its own is plainly sweepable, and that is real
	// money the write-off would have burned.
	singleFee := estimateVSize(10+1*41+43, 1*(72+112+5))
	if singleFee > 1800/2 || 1800-singleFee <= dustThreshold {
		t.Fatalf("fixture is wrong: a lone 1800-sat output should be sweepable "+
			"(fee %d)", singleFee)
	}

	if isResidualUnsweepableAtMinFee(amounts) {
		t.Errorf("a residual containing a sweepable %d-sat output must NOT be written "+
			"off: doing so destroys recoverable funds", amounts[0])
	}
}

// The predicate must still catch a genuine dust pile, or the V-1 escape it exists
// to close re-opens: sub-minimum deposits landing on a superseded generation would
// pin it funded forever and deadlock every future rotation.
func TestVR216_GenuineDustPileIsStillUnsweepable(t *testing.T) {
	amounts := make([]int64, 0, 50)
	for i := 0; i < 50; i++ {
		amounts = append(amounts, 100) // far below the ~177/input break-even
	}
	if !isResidualUnsweepableAtMinFee(amounts) {
		t.Error("a pile of 100-sat outputs is genuinely unsweepable at any rate and " +
			"must still be written off, or NN#3 wedges rotation forever")
	}
}

// A residual larger than one tranche must be judged on the tranche a sweep could
// actually build, not on the whole pile. MaxMigrationInputs caps a tranche at 100,
// so pricing 300 inputs as a single sweep overstates the fee threefold and can
// condemn a residual that would drain in three ordinary passes.
func TestVR216_ResidualLargerThanOneTrancheIsPricedPerTranche(t *testing.T) {
	amounts := make([]int64, 0, 300)
	for i := 0; i < 300; i++ {
		amounts = append(amounts, 400) // individually below break-even, but 100 of them are not
	}

	var total, n int64
	for _, a := range amounts {
		total += a
		n++
	}
	aggregateFee := estimateVSize(10+n*41+43, n*(72+112+5))

	// Sanity: a 100-input tranche of these IS buildable, which is the whole point.
	trancheFee := estimateVSize(10+100*41+43, 100*(72+112+5))
	if trancheFee > (100*400)/2 || 100*400-trancheFee <= dustThreshold {
		t.Fatalf("fixture is wrong: a 100-input tranche of 400-sat outputs should be "+
			"sweepable (fee %d)", trancheFee)
	}
	t.Logf("aggregate fee over %d inputs = %d; one tranche of 100 = %d", n, aggregateFee, trancheFee)

	if isResidualUnsweepableAtMinFee(amounts) {
		t.Error("a residual that drains in successive tranches must not be written off")
	}
}

// Degenerate inputs must fail safe: nothing to sweep is not the same as
// provably stuck, and write-off must not act on an empty or nonsensical residual.
func TestVR216_DegenerateResidualsAreNotWrittenOff(t *testing.T) {
	for name, amounts := range map[string][]int64{
		"empty":     {},
		"all zero":  {0, 0},
		"negative":  {-5},
	} {
		if isResidualUnsweepableAtMinFee(amounts) {
			t.Errorf("%s: must not be treated as a write-off-able residual", name)
		}
	}
}
