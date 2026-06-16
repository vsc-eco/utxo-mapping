package mapping

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEstimateP2SHTxBytes_NoSegwitDiscount pins the corrected P2SH
// byte-count math. Audit R16-OPS-calculate-segwit-fee-p2sh-underpay-
// mainnet (HIGH): every on-wire byte of a Dash spend counts at full
// weight; no ÷4 discount applies. This test pre-computes the
// expected total for a representative tx shape and asserts the
// helper returns exactly that.
func TestEstimateP2SHTxBytes_NoSegwitDiscount(t *testing.T) {
	cases := []struct {
		name           string
		nonScriptSize  int64
		scriptDataSize int64
		want           int64
	}{
		{
			// 1-input 1-output skeleton + the per-input scriptSig
			// content for a 112-byte redeem script (deposit UTXO).
			//   nonScriptSize = 10 + 41 + 43 = 94
			//   scriptDataSize = 72 + 112 + 5 = 189
			//   want = 94 + 189 = 283
			name:           "1-in-1-out, 112B redeem script",
			nonScriptSize:  94,
			scriptDataSize: 72 + 112 + 5,
			want:           94 + 72 + 112 + 5,
		},
		{
			// 3-input 2-output skeleton with the same per-input shape.
			//   nonScriptSize = 10 + 41*3 + 43*2 = 219
			//   scriptDataSize = 3 * (72 + 112 + 5) = 567
			//   want = 219 + 567 = 786
			name:           "3-in-2-out, 112B redeem script",
			nonScriptSize:  10 + 41*3 + 43*2,
			scriptDataSize: 3 * (72 + 112 + 5),
			want:           10 + 41*3 + 43*2 + 3*(72+112+5),
		},
		{
			// Zero inputs / zero script data — pathological but the
			// helper must handle it without panic + return base only.
			name:           "no inputs, base only",
			nonScriptSize:  10,
			scriptDataSize: 0,
			want:           10,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := estimateP2SHTxBytes(tc.nonScriptSize, tc.scriptDataSize)
			assert.Equal(t, tc.want, got,
				"P2SH byte count must equal nonScriptSize + scriptDataSize; "+
					"no /4 discount because Dash has no SegWit (audit R16)")
		})
	}
}

// TestEstimateP2SHTxBytes_RegressionVsOldSegwitFormula proves the new
// formula returns a STRICTLY LARGER value than the old SegWit-style
// formula on every realistic input — i.e. the pre-fix code under-paid.
//
// Old formula (calculateSegwitFee at HEAD~):
//
//	vSize = (nonScriptSize*3 + (nonScriptSize+scriptDataSize) + 3)/4 + 2
//	      = nonScriptSize + (scriptDataSize+3)/4 + 2
//
// New formula: nonScriptSize + scriptDataSize.
//
// Difference: scriptDataSize - (scriptDataSize+3)/4 - 2 ≈ 0.75 ·
// scriptDataSize - 2. For any realistic spend (scriptDataSize > ~3
// bytes) the new formula is materially larger. Regression-pin that
// difference so a future "optimisation" can't silently reinstate the
// discount.
func TestEstimateP2SHTxBytes_RegressionVsOldSegwitFormula(t *testing.T) {
	oldVSize := func(nonScript, scriptData int64) int64 {
		total := nonScript + scriptData
		return (nonScript*3+total+3)/4 + 2
	}
	cases := []struct {
		name           string
		nonScriptSize  int64
		scriptDataSize int64
	}{
		{"1-in-1-out", 94, 189},
		{"3-in-2-out", 10 + 41*3 + 43*2, 3 * (72 + 112 + 5)},
		{"10-in-5-out", 10 + 41*10 + 43*5, 10 * (72 + 112 + 5)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldFee := oldVSize(tc.nonScriptSize, tc.scriptDataSize)
			newBytes := estimateP2SHTxBytes(tc.nonScriptSize, tc.scriptDataSize)
			assert.Greater(t, newBytes, oldFee,
				"new P2SH formula must exceed the old SegWit-discounted "+
					"vsize — otherwise the audit fix wouldn't actually "+
					"raise fees and Dash mainnet would keep under-paying")
			// And by the expected margin: new − old ≈ 0.75·scriptData − 2.
			minMargin := (3*tc.scriptDataSize)/4 - 4 // small fudge for /4 rounding
			assert.GreaterOrEqual(t, newBytes-oldFee, minMargin,
				"new formula must charge at least ~0.75 · scriptDataSize "+
					"more than the old; got delta=%d, expected >= %d",
				newBytes-oldFee, minMargin)
		})
	}
}

// TestCalculateP2SHFee_EndToEnd covers audit R17-OPS-p2sh-fee-test-
// only-pins-formula-not-callsite (LOW). The byte-count helper is
// already pinned via TestEstimateP2SHTxBytes_* but those don't catch
// regressions in the fee math at calculateP2SHFee + estimateFee
// callsites (e.g. someone swaps the multiply order, drops the
// per-input loop, or pre-multiplies somewhere wrong). End-to-end
// pinning: construct a representative redeemScripts map, call
// calculateP2SHFee with a known baseSize + known fee rate, and
// assert the fee value matches a hand-computed expected number.
func TestCalculateP2SHFee_EndToEnd(t *testing.T) {
	// Two inputs, deposit-shape (112-byte redeem script).
	redeemScripts := map[int][]byte{
		0: make([]byte, 112),
		1: make([]byte, 112),
	}
	// Per-input scriptSig content under calculateP2SHFee's
	// formula (72 + len(redeemScript) + 5): 72-byte sig + 112-byte
	// redeem script + 5 bytes of push-opcode + branch-selector
	// framing = 189 bytes per input. Two inputs → scriptDataSize =
	// 378. (Audit R18-OPS-p2sh-fee-test-comment-arithmetic-off-by-2-
	// bytes-per-input + R18-CONS-p2sh-fee-test-arithmetic-comment-
	// 378-vs-380 corrected the off-by-one from the prior "190/380"
	// comment.) nonScriptSize = baseSize from caller; pin at 200
	// (representative of a 2-in 1-out skeleton).
	const nonScriptSize int64 = 200
	const wantScriptData int64 = 2 * (72 + 112 + 5) // = 378
	const wantTotalBytes int64 = nonScriptSize + wantScriptData // = 578

	// ContractState with feeRate=10 sats/byte → expected fee 5780.
	cs := &ContractState{
		Supply: SystemSupply{BaseFeeRate: 10},
	}
	fee, err := cs.calculateP2SHFee(nonScriptSize, redeemScripts)
	if err != nil {
		t.Fatalf("calculateP2SHFee: %v", err)
	}
	if fee != wantTotalBytes*10 {
		t.Errorf("calculateP2SHFee = %d, want %d (= %d bytes × 10 sat/byte)",
			fee, wantTotalBytes*10, wantTotalBytes)
	}

	// Sanity: zero inputs / empty map → just base × feeRate. Caller
	// must not get tripped by an empty redeemScripts map.
	feeEmpty, err := cs.calculateP2SHFee(nonScriptSize, map[int][]byte{})
	if err != nil {
		t.Fatalf("calculateP2SHFee empty: %v", err)
	}
	if feeEmpty != nonScriptSize*10 {
		t.Errorf("calculateP2SHFee with empty redeemScripts = %d, want %d",
			feeEmpty, nonScriptSize*10)
	}

	// clampedFeeRate guard: BaseFeeRate=0 should clamp UP to 1 (the
	// floor), not produce zero fee. Otherwise a misconfigured oracle
	// could publish 0 fee → miners reject the tx as zero-fee.
	cs.Supply.BaseFeeRate = 0
	feeClamped, err := cs.calculateP2SHFee(nonScriptSize, redeemScripts)
	if err != nil {
		t.Fatalf("calculateP2SHFee clamped: %v", err)
	}
	if feeClamped != wantTotalBytes*1 {
		t.Errorf("clampedFeeRate floor: expected %d × 1, got %d",
			wantTotalBytes, feeClamped)
	}
}
