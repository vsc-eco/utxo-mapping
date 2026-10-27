package current_test

import (
	"bytes"
	"os"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
	"vsc-node/lib/test_utils"
)

func sweepOuts(t *testing.T, ct *test_utils.ContractTest, cid, txId string) []*wire.TxOut {
	t.Helper()
	var tx wire.MsgTx
	require.NoError(t, tx.Deserialize(bytes.NewReader(signingTx(t, ct, cid, txId))))
	return tx.TxOut
}

func gen1Coins(t *testing.T, ct *test_utils.ContractTest, cid string) int {
	t.Helper()
	n := 0
	for id := range registryIds(t, ct, cid) {
		if id != h2ReserveId && utxoGenerationForId(t, ct, cid, id) == 1 {
			n++
		}
	}
	return n
}

// SWEEP-SPLIT + L7-01: a stuck split sweep is re-driven into a replacement with the same
// number of successor coins and a higher fee; settling either member conserves exactly.
func TestSweepSplit_RedriveKeepsTheSplit(t *testing.T) {
	for _, settleReplacement := range []bool{true, false} {
		seeds := []utxoSeed{{1100, 400_000}, {1101, 400_000}, {1102, 400_000}, {1103, 400_000}}
		ct, cid, owner := newOneRotationCT(t, seeds)
		r := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
		require.Empty(t, r.Err, r.ErrMsg)
		orig := r.Ret
		require.Len(t, sweepOuts(t, ct, cid, orig), 4)

		ct.StateSet(cid, constants.LastHeightKey, "130") // past RedriveStaleBlocks
		rd := callKeyAction(t, ct, cid, owner, "redriveSpend", []byte(orig))
		require.Empty(t, rd.Err, rd.ErrMsg)
		repl := parseRedriveNewTxId(t, rd.Ret)
		outs := sweepOuts(t, ct, cid, repl)
		require.Len(t, outs, 4, "the replacement keeps the split")
		for _, o := range outs {
			require.Equal(t, outs[0].PkScript, o.PkScript, "every coin pays the successor")
		}
		require.Greater(t, readSweepRecord(t, ct, cid, repl).BtcFee, readSweepRecord(t, ct, cid, orig).BtcFee)

		settle := orig
		if settleReplacement {
			settle = repl
		}
		c := confirmMigrationSweep(t, ct, cid, owner, settle, 140)
		require.True(t, c.Success, c.ErrMsg)
		require.Empty(t, ct.StateGet(cid, constants.MigrationSweepPrefix+orig), "group cleared")
		require.Empty(t, ct.StateGet(cid, constants.MigrationSweepPrefix+repl), "group cleared")
		require.Equal(t, 4, gen1Coins(t, ct, cid))
		i1Holds(t, ct, cid)
	}
}

// SWEEP-SPLIT + VR2-11: at a fee spike the builder derives the highest rate under the half
// ceiling; every coin of the split still stays at or above MinMigrationOutputValue/2.
func TestSweepSplit_FeeSpikeKeepsCoinsAboveFloor(t *testing.T) {
	seeds := []utxoSeed{{1100, 100_000}, {1101, 100_000}, {1102, 100_000}}
	ct, cid, owner := newOneRotationCT(t, seeds)
	seedReserve(t, ct, cid, 1, 2001, 300_000) // a reserve big enough for a spiked-rate sweep
	s := loadSupply(t, ct, cid)
	s.BaseFeeRate = 1000
	ct.StateSet(cid, constants.SupplyKey, string(mapping.MarshalSupply(&s)))
	r := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	outs := sweepOuts(t, ct, cid, r.Ret)
	require.Len(t, outs, 3)
	reduced := false
	for _, l := range r.Logs[cid].Logs {
		if bytes.HasPrefix([]byte(l), []byte("migrate-fee-reduced|")) {
			reduced = true
		}
	}
	require.True(t, reduced, "the spike must take the VR2-11 reduced-rate path, or this test proves nothing")
	fee := readSweepRecord(t, ct, cid, r.Ret).BtcFee
	require.LessOrEqual(t, fee, int64(300_000/2), "V5-4 ceiling")
	for _, o := range outs {
		require.GreaterOrEqual(t, o.Value, constants.MinMigrationOutputValue/2)
	}
	require.True(t, confirmMigrationSweep(t, ct, cid, owner, r.Ret, 200).Success)
	require.Equal(t, 3+1, gen1Coins(t, ct, cid), "three swept coins plus the extra reserve coin 2001")
	i1Holds(t, ct, cid)
}

// Upgrade case: a one-coin sweep built by the pre-split contract is in flight when the new
// code lands; a re-drive rebuilds it with the split, and either member settles.
func TestSweepSplit_RedriveOfAPreSplitSweep(t *testing.T) {
	old := os.Getenv("PRE_SPLIT_WASM")
	if old == "" {
		t.Skip("set PRE_SPLIT_WASM to a pre-SWEEP-SPLIT dev.wasm")
	}
	oldWasm, err := os.ReadFile(old)
	require.NoError(t, err)
	for _, settleReplacement := range []bool{true, false} {
		seeds := []utxoSeed{{1100, 400_000}, {1101, 400_000}, {1102, 400_000}}
		ct, cid, owner := newOneRotationCT(t, seeds)
		ct.RegisterContract(cid, owner, oldWasm)
		r := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
		require.Empty(t, r.Err, r.ErrMsg)
		orig := r.Ret
		require.Len(t, sweepOuts(t, ct, cid, orig), 1, "built by the old code: one coin")

		ct.RegisterContract(cid, owner, ContractWasm) // the upgrade
		ct.StateSet(cid, constants.LastHeightKey, "130")
		rd := callKeyAction(t, ct, cid, owner, "redriveSpend", []byte(orig))
		require.Empty(t, rd.Err, rd.ErrMsg)
		repl := parseRedriveNewTxId(t, rd.Ret)
		require.Len(t, sweepOuts(t, ct, cid, repl), 3, "the new code re-drives it with the split")

		settle, want := orig, 1
		if settleReplacement {
			settle, want = repl, 3
		}
		c := confirmMigrationSweep(t, ct, cid, owner, settle, 140)
		require.True(t, c.Success, c.ErrMsg)
		require.Equal(t, want, gen1Coins(t, ct, cid))
		require.Empty(t, ct.StateGet(cid, constants.MigrationSweepPrefix+orig))
		require.Empty(t, ct.StateGet(cid, constants.MigrationSweepPrefix+repl))
		i1Holds(t, ct, cid)
	}
}
