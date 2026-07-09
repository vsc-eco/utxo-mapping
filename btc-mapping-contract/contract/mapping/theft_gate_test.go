package mapping

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// M1.1b — the pure rogue-spend trip decision. A trip fires iff the reported tx spends a
// currently-registered vault UTXO (by outpoint txid:vout) AND its own txid is not an
// authorised in-flight spend. These prove every branch off-chain; the SPV verify + flag
// write are exercised by the tests/current WASM harness in CI.

const (
	thTxA = "1111111111111111111111111111111111111111111111111111111111111111"
	thTxB = "2222222222222222222222222222222222222222222222222222222222222222"
	thTxC = "3333333333333333333333333333333333333333333333333333333333333333"
)

type thOutp struct {
	txid string
	vout uint32
}

func thMkTx(t *testing.T, ins ...thOutp) *wire.MsgTx {
	t.Helper()
	tx := wire.NewMsgTx(wire.TxVersion)
	for _, in := range ins {
		h, err := chainhash.NewHashFromStr(in.txid)
		require.NoError(t, err)
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(h, in.vout), nil, nil))
	}
	tx.AddTxOut(wire.NewTxOut(1000, []byte{0x00})) // a dummy output → a valid, distinct txid
	return tx
}

func TestClassifyReportedSpend(t *testing.T) {
	registry := []*Utxo{{TxId: thTxA, Vout: 0}, {TxId: thTxA, Vout: 1}, {TxId: thTxB, Vout: 0}}

	// (1) Rogue: spends registered thTxA:0, txid ∉ authorised set → (spends=true, auth=false) → TRIP.
	rogue := thMkTx(t, thOutp{thTxA, 0})
	sp, au := classifyReportedSpend(rogue, registry, nil)
	require.True(t, sp, "rogue spends a registered vault UTXO")
	require.False(t, au, "rogue is not an authorised spend")

	// (2) Legit in-flight: same spend, but its OWN txid is in TxSpendsList → authorised, no trip.
	legit := thMkTx(t, thOutp{thTxA, 0})
	sp, au = classifyReportedSpend(legit, registry, []string{legit.TxID()})
	require.True(t, sp)
	require.True(t, au, "an in-flight authorised spend must classify authorised")

	// (3) Confirmed legit / unrelated: spends an outpoint NOT in the registry → no trip.
	unrelated := thMkTx(t, thOutp{thTxC, 0})
	sp, _ = classifyReportedSpend(unrelated, registry, nil)
	require.False(t, sp, "spends nothing the vault currently holds → not a vault drain")

	// (4) Multi-input, one matches a registered UTXO → spends=true.
	multi := thMkTx(t, thOutp{thTxC, 5}, thOutp{thTxB, 0})
	sp, au = classifyReportedSpend(multi, registry, nil)
	require.True(t, sp, "one matching input is enough")
	require.False(t, au)

	// (5) Vout precision: registry has thTxA:0/1 but the spend is thTxA:2 → not registered.
	wrongVout := thMkTx(t, thOutp{thTxA, 2})
	sp, _ = classifyReportedSpend(wrongVout, registry, nil)
	require.False(t, sp, "outpoint match is txid:vout, not txid alone")

	// (6) A DIFFERENT txid in the authorised list does not authorise this spend → still trips.
	other := thMkTx(t, thOutp{thTxA, 0})
	sp, au = classifyReportedSpend(other, registry, []string{thTxC})
	require.True(t, sp)
	require.False(t, au, "the list must contain THIS tx's own txid to authorise it")
}
