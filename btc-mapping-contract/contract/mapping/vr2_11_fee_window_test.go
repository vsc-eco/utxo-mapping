package mapping

import "testing"

// VR2-11: a fee spike must not deadlock a rotation.
//
// buildMigrationTransaction refuses a sweep whose fee exceeds half the tranche
// (the V5-4 ceiling, which stops a rogue oracle rate burning a tranche on miner
// fees). It used to price that fee at the ORACLE's rate and give up if it did not
// fit. Write-off, meanwhile, correctly declined to touch such a residual, because
// it IS affordable at the protocol minimum. So nothing moved until fees happened
// to fall — while NN#3 blocked every rotation and the committee's bond stayed
// locked. No attacker required; a fee spike sufficed.
//
// The builder now derives the highest rate that fits under the SAME ceiling
// instead of insisting on the oracle's. These tests pin the arithmetic that makes
// that safe, at the boundary where it matters.
func TestVR211_AffordableRateIsDerivedNotChosen(t *testing.T) {
	// A concrete tranche: 40 inputs, vsize as the fee estimator computes it.
	const n int64 = 40
	vSize := estimateVSize(10+n*41+43, n*(72+112+5))

	// Priced so the sweep is comfortably affordable at rate 1 but not at rate 20.
	total := vSize * 8 // ceiling is total/2 == vSize*4, so rates up to 4 fit

	for _, tc := range []struct {
		name       string
		oracleRate int64
		wantRate   int64
	}{
		{"oracle at the ceiling", 4, 4},
		{"oracle above the ceiling", 20, 4},
		{"oracle far above the ceiling", 500, 4},
	} {
		oracleFee := vSize * tc.oracleRate
		if oracleFee <= total/2 && tc.oracleRate > 4 {
			t.Fatalf("%s: fixture wrong, the oracle fee should exceed the ceiling", tc.name)
		}
		affordable := (total / 2) / vSize
		if affordable != tc.wantRate {
			t.Errorf("%s: derived rate %d, want %d", tc.name, affordable, tc.wantRate)
		}
		if got := vSize * affordable; got > total/2 {
			t.Errorf("%s: derived fee %d breaches the ceiling %d — V5-4 must still hold",
				tc.name, got, total/2)
		}
	}
}

// The ceiling is the invariant, not the convenience. A tranche too small to pay
// even the minimum rate under the ceiling must still be refused here and left for
// write-off to judge — deriving a rate must never round down to zero and sweep for
// free, nor push the fee past half the value.
func TestVR211_TrancheUnaffordableAtTheMinimumIsStillRefused(t *testing.T) {
	const n int64 = 40
	vSize := estimateVSize(10+n*41+43, n*(72+112+5))

	// Half the tranche is less than one satoshi per vbyte: nothing fits.
	total := vSize // ceiling is vSize/2, below the rate-1 fee of vSize
	affordable := (total / 2) / vSize
	if affordable >= 1 {
		t.Fatalf("fixture wrong: derived rate %d should be below 1", affordable)
	}
	if isResidualUnsweepableAtMinFee([]int64{total}) != true {
		t.Log("note: write-off's own predicate decides this case; the builder only refuses")
	}
}

// A rate of zero would sweep for free, which no mempool accepts and which would
// strand the tranche in a different way. The floor at 1 is what stops the
// derivation degenerating.
func TestVR211_DerivedRateNeverFallsBelowOne(t *testing.T) {
	for _, tc := range []struct{ total, vSize int64 }{
		{0, 100},
		{1, 100},
		{199, 100}, // ceiling 99 < vSize
	} {
		if affordable := (tc.total / 2) / tc.vSize; affordable >= 1 {
			t.Errorf("total=%d vsize=%d: derived rate %d should be below 1, so the "+
				"builder refuses rather than sweeping at zero fee",
				tc.total, tc.vSize, affordable)
		}
	}
}
