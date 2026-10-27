package current_test

import (
	"bytes"
	"testing"

	"btc-mapping-contract/contract/constants"

	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// SWEEP-SPLIT: a five-coin tranche pays the successor in five equal coins (the remainder on
// the first), settles with exact conservation, and right after the settle three withdrawals
// go out at once instead of one per confirmation.
func TestSweepSplit_SeveralCoinsAndParallelPayouts(t *testing.T) {
	seeds := []utxoSeed{{1100, 400_000}, {1101, 400_000}, {1102, 400_000}, {1103, 400_000}, {1104, 400_001}}
	ct, cid, owner := newOneRotationCT(t, seeds)
	const user = "hive:milo-hpr"
	ct.StateSet(cid, constants.BalancePrefix+user, encodeBalance(t, 2_000_001))

	r := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	sweep := r.Ret
	var tx wire.MsgTx
	require.NoError(t, tx.Deserialize(bytes.NewReader(signingTx(t, ct, cid, sweep))))
	require.Len(t, tx.TxOut, 5, "one coin per input (5 <= MaxMigrationOutputs, each >= MinMigrationOutputValue)")
	var sum int64
	for i, out := range tx.TxOut {
		require.Equal(t, tx.TxOut[0].PkScript, out.PkScript, "every coin pays the successor (NN#1)")
		if i > 0 {
			require.Equal(t, tx.TxOut[1].Value, out.Value, "equal shares")
		}
		sum += out.Value
	}
	require.Less(t, tx.TxOut[0].Value-tx.TxOut[1].Value, int64(5), "the remainder (< coins) rides on the first coin")
	require.Equal(t, readSweepRecord(t, ct, cid, sweep).BtcFee, int64(2_000_001)-sum, "outputs = inputs - fee")

	require.True(t, confirmMigrationSweep(t, ct, cid, owner, sweep, 200).Success)
	i1Holds(t, ct, cid)
	g1 := 0
	for id := range registryIds(t, ct, cid) {
		if id != h2ReserveId && utxoGenerationForId(t, ct, cid, id) == 1 {
			g1++
		}
	}
	require.Equal(t, 5, g1, "gen-1 holds five coins")

	for i := 0; i < 3; i++ {
		u := wqUnmap(t, ct, cid, user, 300_000)
		require.True(t, u.Success, "withdrawal %d: %s", i, u.ErrMsg)
	}
	head, tail := wqBounds(t, ct, cid)
	require.Equal(t, head, tail, "nothing queued: three coins were free")
	require.Len(t, wqPending(t, ct, cid), 3, "three withdrawals in flight at once")
}
