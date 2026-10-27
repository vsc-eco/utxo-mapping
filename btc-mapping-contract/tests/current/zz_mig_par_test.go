package current_test

import (
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"github.com/stretchr/testify/require"
)

// MIG-PAR on the shape of the live mainnet vault (2026-10-17 snapshot): 9 small
// confirmed-pool coins and 35 legacy (unconfirmed-pool) entries holding ~98% of the value,
// one of them dust. Legacy entries still go one per tranche (H-2), but one migrateVault call
// now builds up to MaxTranchesPerMigrate of them, so the bot (which waits for every
// in-flight sweep before calling again) drains the gen in a few rounds, not one
// confirmation per entry (~36 rounds, about 1.5 days on mainnet).
func TestMigPar_MainnetShapedDrainInFewRounds(t *testing.T) {
	var seeds []utxoSeed
	for i := 0; i < 9; i++ {
		seeds = append(seeds, utxoSeed{uint16(constants.UtxoConfirmedPoolStart + 10 + i), 10_846})
	}
	for i := 0; i < 35; i++ {
		amt := int64(161_000 + i*1_000)
		if i == 29 {
			amt = 587 // mainnet's dust entry, 30th in registry order
		}
		seeds = append(seeds, utxoSeed{uint16(20 + i), amt})
	}
	ct, cid, owner := newOneRotationCT(t, seeds)

	rounds := 0
	h := uint32(200)
	var confirmRC int64
	for ; rounds < 10; rounds++ {
		r := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
		if r.Err != "" {
			require.Contains(t, r.ErrMsg, "too small to cover the sweep fee", "only the dust may be refused")
			break
		}
		sweeps, err := mapping.UnmarshalTxSpendsRegistry([]byte(ct.StateGet(cid, constants.MigrationSweepRegistryKey)))
		require.NoError(t, err)
		if len(sweeps) == 0 {
			break
		}
		require.LessOrEqual(t, len(sweeps), constants.MaxTranchesPerMigrate)
		t.Logf("round %d: %d sweeps in one call, rc=%d gas=%d", rounds+1, len(sweeps), r.RcUsed, r.GasUsed)
		require.Less(t, r.RcUsed, int64(300_000), "a call stays well inside the bot account's ~466k RC")
		for _, s := range sweeps {
			rec := readSweepRecord(t, ct, cid, s)
			if rec.InputIds[0] < constants.UtxoConfirmedPoolStart {
				require.Len(t, rec.InputIds, 1, "a legacy entry is still swept alone (H-2)")
			}
			c := confirmMigrationSweep(t, ct, cid, owner, s, h)
			require.True(t, c.Success)
			confirmRC += c.RcUsed
			h += 10
		}
		i1Holds(t, ct, cid)
	}
	t.Logf("drained in %d rounds; all settles together used rc=%d", rounds, confirmRC)
	require.LessOrEqual(t, rounds, 3, "36 tranches drain in 3 rounds (16 + 16 + 3, the dust written off), not 36")
	left := 0
	for id := range registryIds(t, ct, cid) {
		if id != h2ReserveId && utxoGenerationForId(t, ct, cid, id) == 0 {
			left++
			require.Equal(t, uint16(20+29), id, "only the dust entry is left on gen-0")
		}
	}
	require.Equal(t, 1, left)
	w := callKeyAction(t, ct, cid, owner, "writeOffDust", []byte(""))
	require.Empty(t, w.Err, w.ErrMsg)
	i1Holds(t, ct, cid)
}

// MIG-PAR, M-2: a later tranche the fee reserve cannot cover ends the call's loop and keeps
// every tranche already built; the next call, after a top-up, continues where it stopped.
func TestMigPar_ReserveShortStopsTheLoopKeepsBuiltTranches(t *testing.T) {
	var seeds []utxoSeed
	for i := 0; i < 6; i++ {
		seeds = append(seeds, utxoSeed{uint16(20 + i), 200_000})
	}
	ct, cid, owner := newOneRotationCT(t, seeds)
	// At 200 sat/vB the 100k reserve covers about three one-input sweeps.
	s := loadSupply(t, ct, cid)
	s.BaseFeeRate = 200
	ct.StateSet(cid, constants.SupplyKey, string(mapping.MarshalSupply(&s)))
	perSweep := int64(0)
	{
		r := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
		require.Empty(t, r.Err, r.ErrMsg)
		perSweep = readSweepRecord(t, ct, cid, r.Ret).BtcFee
	}
	sweeps, err := mapping.UnmarshalTxSpendsRegistry([]byte(ct.StateGet(cid, constants.MigrationSweepRegistryKey)))
	require.NoError(t, err)
	built := len(sweeps)
	require.GreaterOrEqual(t, built, 1)
	require.Less(t, built, 6, "the 100k reserve cannot cover six sweeps at 200 sat/vB (%d sats each)", perSweep)
	t.Logf("reserve 100000, %d sats per sweep: the call built %d of 6 and kept them", perSweep, built)
	for _, s := range sweeps {
		rec := readSweepRecord(t, ct, cid, s)
		require.Len(t, rec.InputIds, 1)
		require.NotEmpty(t, ct.StateGet(cid, constants.TxSpendsPrefix+s), "every kept tranche is fully recorded")
	}
	// Refused cleanly while the reserve is short, then continues after a top-up.
	r := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
	require.NotEmpty(t, r.Err, "nothing more fits the reserve")
	require.Contains(t, r.ErrMsg, "insufficient fee reserve")
	seedReserve(t, ct, cid, 1, 2002, 1_000_000)
	r = callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	after, err := mapping.UnmarshalTxSpendsRegistry([]byte(ct.StateGet(cid, constants.MigrationSweepRegistryKey)))
	require.NoError(t, err)
	require.Equal(t, 6, len(after), "the rest is built after the top-up")
	i1Holds(t, ct, cid)
}
