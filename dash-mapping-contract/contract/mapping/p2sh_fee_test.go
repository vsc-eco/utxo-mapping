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
