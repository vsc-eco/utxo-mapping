package current_test

// MIG-LEGACY-DUST-2: a tranche whose output clears the dust floor at a lower fee rate
// than the oracle's is swept at that lower rate (VR2-11's derived rate, applied to the
// dust floor) instead of refusing every migrateVault call until fees fall. Mainnet case:
// legacy coin id 5 (931 sats) at >= 3 sat/vB blocked the 34 legacy coins behind it.
// Grief case: a 1,080-1,086 sat deposit to a superseded generation wedged its drain at
// every rate >= 4.

import (
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"github.com/stretchr/testify/require"
)

func TestMigLegacyDust2_SmallTrancheSweptAtLowerRate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		id     uint16
		amount int64
		rate   int64
	}{
		{"legacy 931 at 3 sat/vB", 5, 931, 3},
		{"legacy 931 at 50 sat/vB", 5, 931, 50},
		{"confirmed 1080 at 10 sat/vB", 1100, 1080, 10},
		{"confirmed 1086 at 100 sat/vB", 1100, 1086, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct, cid, owner := newOneRotationCT(t, []utxoSeed{{tc.id, tc.amount}})
			s := loadSupply(t, ct, cid)
			s.BaseFeeRate = tc.rate
			ct.StateSet(cid, constants.SupplyKey, string(mapping.MarshalSupply(&s)))
			before := loadSupply(t, ct, cid)

			r := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
			require.Empty(t, r.Err, r.ErrMsg)
			sweeps, err := mapping.UnmarshalTxSpendsRegistry([]byte(ct.StateGet(cid, constants.MigrationSweepRegistryKey)))
			require.NoError(t, err)
			require.Len(t, sweeps, 1)
			rec := readSweepRecord(t, ct, cid, sweeps[0])
			require.Equal(t, []uint16{tc.id}, rec.InputIds)
			require.Greater(t, rec.BtcFee, int64(0))
			require.Greater(t, tc.amount-rec.BtcFee, int64(546), "the output clears the dust floor")
			require.LessOrEqual(t, rec.BtcFee, tc.amount/2, "V5-4 ceiling still holds")

			c := confirmMigrationSweep(t, ct, cid, owner, sweeps[0], 200)
			require.True(t, c.Success, c.ErrMsg)
			_, left := registryIds(t, ct, cid)[tc.id]
			require.False(t, left, "the coin left the old generation")
			after := loadSupply(t, ct, cid)
			require.Equal(t, before.UserSupply, after.UserSupply, "user balances untouched")
			require.Equal(t, before.ActiveSupply, after.ActiveSupply)
		})
	}
}

// Unchanged: a coin that cannot clear the dust floor even at 1 sat/vB is still refused
// by migrateVault and left to writeOffDust, which takes it.
func TestMigLegacyDust2_UnsweepableAtMinimumStillWrittenOff(t *testing.T) {
	ct, cid, owner := newOneRotationCT(t, []utxoSeed{{1100, 600}})
	s := loadSupply(t, ct, cid)
	s.BaseFeeRate = 10
	ct.StateSet(cid, constants.SupplyKey, string(mapping.MarshalSupply(&s)))
	r := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
	require.NotEmpty(t, r.Err, "600 sats cannot clear 546 after even a 1 sat/vB fee")
	w := callKeyAction(t, ct, cid, owner, "writeOffDust", []byte(""))
	require.Empty(t, w.Err, w.ErrMsg)
	_, left := registryIds(t, ct, cid)[1100]
	require.False(t, left, "writeOffDust took the unsweepable coin")
}
