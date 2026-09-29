package mapping

import (
	"reflect"
	"strings"
	"testing"
)

// H-2: the write-off judges a residual the way migration builds tranches. Confirmed
// inputs are batched; legacy entries go one per tranche, so a legacy entry counts as
// sweepable only on its own.
func TestResidualStuckAtMinFee(t *testing.T) {
	single := estimateVSize(10+41+43, 72+112+5) // one input at 1 sat/vbyte
	small := single + dustThreshold             // sweepable only together with another like it
	if trancheBuildableAtMinFee([]int64{small}) {
		t.Fatalf("setup: %d must not be sweepable alone", small)
	}
	if !trancheBuildableAtMinFee([]int64{small, small}) {
		t.Fatalf("setup: two of %d must be sweepable together", small)
	}
	cases := []struct {
		name              string
		batchable, legacy []int64
		stuck             bool
	}{
		{"nothing", nil, nil, false},
		{"two small legacy entries: migration sweeps them one at a time, so stuck", nil, []int64{small, small}, true},
		{"the same two as confirmed inputs are batched, so not stuck", []int64{small, small}, nil, false},
		{"one legacy entry sweepable alone", nil, []int64{small, 100_000}, false},
		{"confirmed dust but a sweepable legacy entry", []int64{300}, []int64{100_000}, false},
		{"confirmed dust and a small legacy entry", []int64{300}, []int64{small}, true},
		{"mainnet's smallest legacy entry (587 sats) alone", nil, []int64{587}, true},
	}
	for _, tc := range cases {
		if got := residualStuckAtMinFee(tc.batchable, tc.legacy); got != tc.stuck {
			t.Errorf("%s: stuck=%v, want %v", tc.name, got, tc.stuck)
		}
	}
}

func TestAbandonedSweepRoundTrip(t *testing.T) {
	in := &AbandonedSweep{
		Sweep: MigrationSweep{
			InputIds:         []uint16{7},
			BtcFee:           321,
			SuccessorAddress: "bcrt1qexamplesuccessoraddress",
			SuccessorGen:     2,
			BuildHeight:      900,
		},
		WrittenOff: 45_000,
		Members:    []string{strings.Repeat("a", 64), strings.Repeat("b", 64)},
	}
	out, err := UnmarshalAbandonedSweep(MarshalAbandonedSweep(in))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip changed the record:\n in  %+v\n out %+v", in, out)
	}
	if _, err := UnmarshalAbandonedSweep([]byte{1, 2, 3}); err == nil {
		t.Fatal("a truncated record must be refused")
	}
}
