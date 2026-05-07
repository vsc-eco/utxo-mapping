package mapping

import (
	"testing"

	"btc-mapping-contract/contract/constants"
)

// Pentest finding BTC-C6: clampedFeeRate previously allowed up to
// 1000 sat/vbyte, which only acts as an overflow guard — within that
// range the oracle can drive withdrawal fees to ~$200 per typical
// 200-vbyte tx. BTC mainnet historical peaks (2017 bull run, 2023
// inscription mania) topped out near 500–750 sat/vbyte for short
// windows; anything above 500 represents either an oracle bug or
// active griefing.
//
// Pin the new ceiling so a future change loosening it trips this
// test.

func TestBTCC6_ClampedFeeRateCeilingTightened(t *testing.T) {
	// Constant pin — flag any change that re-loosens the ceiling
	// above the audit-recommended value.
	if constants.MaxBaseFeeRate > 500 {
		t.Errorf("BTC-C6 leak: MaxBaseFeeRate %d > 500 sat/vbyte ceiling; oracle griefing range too wide",
			constants.MaxBaseFeeRate)
	}
}

func TestBTCC6_ClampHonoursCeiling(t *testing.T) {
	// Behavioural pin — anything well above the ceiling clamps down
	// to MaxBaseFeeRate, not the legacy 1000.
	cases := []struct {
		input    int64
		expected int64
	}{
		{0, 1},                                  // legacy floor still in place
		{1, 1},                                  // boundary: ≥1 is fine
		{50, 50},                                // ordinary fee passes through
		{constants.MaxBaseFeeRate, constants.MaxBaseFeeRate}, // exactly at ceiling
		{constants.MaxBaseFeeRate + 1, constants.MaxBaseFeeRate},
		{1_000_000, constants.MaxBaseFeeRate}, // adversarial overflow
	}
	for _, tc := range cases {
		got := clampedFeeRate(tc.input)
		if got != tc.expected {
			t.Errorf("clampedFeeRate(%d) = %d, want %d", tc.input, got, tc.expected)
		}
	}
}
