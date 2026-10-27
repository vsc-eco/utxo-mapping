package mapping

import (
	"testing"

	"btc-mapping-contract/contract/constants"
)

// SWEEP-SPLIT: a sweep pays the successor in at most MaxMigrationOutputs coins, never
// more coins than it spends, and none planned below MinMigrationOutputValue.
func TestMigrationOutputCount(t *testing.T) {
	min := constants.MinMigrationOutputValue
	cases := []struct {
		inputs int
		total  int64
		want   int
	}{
		{1, 50 * min, 1}, // one coin in, one coin out (a legacy tranche)
		{2, 34 * min, 2}, // one coin per input
		{5, 20 * min, 5}, //
		{70, 14 * min, constants.MaxMigrationOutputs}, // capped
		{70, 3 * min, 3},      // value-bound
		{5, 2*min + min/2, 2}, //
		{9, min - 1, 1},       // too small to split: one coin
		{0, 0, 1},             // degenerate: never zero outputs
	}
	for _, c := range cases {
		if got := migrationOutputCount(c.inputs, c.total); got != c.want {
			t.Errorf("migrationOutputCount(%d, %d) = %d, want %d", c.inputs, c.total, got, c.want)
		}
	}
}
