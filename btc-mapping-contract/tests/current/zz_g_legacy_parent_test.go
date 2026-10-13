package current_test

// G (parent-clear half): when a migration sweep consumes a legacy unconfirmed-pool input U -
// an unconfirmed CHANGE output of some parent spend T - T's change is gone, so T's confirmSpend
// can never promote anything. Without the clear, T lingers in TxSpends forever and the bot (C1)
// retries confirmSpend(T) every pass. settleMigrationSweep (sweep confirms) and abandonSweep
// (sweep written off) both clear T.
//
// newH2CT seeds its legacy gen-0 entry with a fixed TxId ("ab" x 32) and Vout = id
// (seedGenUtxos), so that TxId IS U's parent T; registering T as a pending spend with U as its
// only unconfirmed output lets us assert the clear.
//
// NOTE (clauderfly-68): these run only under CONTRACT-COMBINED - the contract suite needs the
// wasm rebuild I cannot run locally. The RESERVATION half of G (a real confirmSpend(T) must skip
// the reserved U so S is not bricked) needs a real tx T with a valid SPV proof, which this fake
// TxId cannot provide; that half is for the proof harness (08).

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// legacyParentTxId is the TxId seedGenUtxos stamps on every seeded entry.
var legacyParentTxId = strings.Repeat("ab", 32)

// TestG_SettleClearsSweptLegacyParent: the sweep of a legacy input settles, deleting U, so its
// parent T (its last unconfirmed output now gone) is cleared from the pending set.
func TestG_SettleClearsSweptLegacyParent(t *testing.T) {
	ct, contractId, owner := newH2CT(t, []utxoSeed{{10, 40_000}}, 100_000)
	ct.StateSet(contractId, constants.TxSpendsPrefix+legacyParentTxId, "01") // d-<T>: non-empty signing marker
	ct.StateSet(contractId, constants.TxSpendsRegistryKey, string(mapping.MarshalTxSpendsRegistry(mapping.TxSpendsRegistry{legacyParentTxId})))

	_, repl, build := migrateAndRedrive(t, ct, contractId, owner)
	replTx := signingTx(t, ct, contractId, repl)
	require.True(t, confirmTxBytes(t, ct, contractId, owner, replTx, build+constants.SweepAbandonBlocks+5).Success,
		"the legacy sweep settles")

	require.Empty(t, ct.StateGet(contractId, constants.TxSpendsPrefix+legacyParentTxId),
		"settling the sweep consumed T's last unconfirmed output, so T's d- record must be cleared (else C1 loops confirmSpend(T))")
	txids, err := mapping.UnmarshalTxSpendsRegistry([]byte(ct.StateGet(contractId, constants.TxSpendsRegistryKey)))
	require.NoError(t, err)
	require.NotContains(t, txids, legacyParentTxId, "T must be out of the TxSpends registry")
}

// TestG_AbandonClearsWrittenOffLegacyParent: abandoning the legacy sweep writes off U, which
// also removes it, so T must be cleared the same way (the gap 08 found - abandon needs the
// parent-clear too, not only the unreserve).
func TestG_AbandonClearsWrittenOffLegacyParent(t *testing.T) {
	ct, contractId, owner := newH2CT(t, []utxoSeed{{10, 40_000}}, 100_000)
	ct.StateSet(contractId, constants.TxSpendsPrefix+legacyParentTxId, "01")
	ct.StateSet(contractId, constants.TxSpendsRegistryKey, string(mapping.MarshalTxSpendsRegistry(mapping.TxSpendsRegistry{legacyParentTxId})))

	orig, _, build := migrateAndRedrive(t, ct, contractId, owner)
	setHeight(ct, contractId, build+constants.SweepAbandonBlocks)
	require.True(t, callAs(t, ct, contractId, owner, "abandonSweep", []byte(orig)).Success, "the stuck legacy sweep is abandoned")

	require.Empty(t, ct.StateGet(contractId, constants.TxSpendsPrefix+legacyParentTxId),
		"abandon wrote off T's last unconfirmed output, so T's d- record must be cleared too")
}

// TestG_ReservationKeepsSweepUnbricked (the reservation half, 08's recipe): a legacy input U
// is an unconfirmed change output (vout 1) of a REAL parent tx T. A migration sweep S takes U
// and reserves it. A confirmSpend(T) that would re-id U is SKIPPED (reserved), so U keeps its
// id and S is not bricked; S then settles normally. Dropping the reserveUtxo line (mutation)
// lets confirmSpend(T) re-id U, and S's settle then fails with its input missing - G's brick.
func TestG_ReservationKeepsSweepUnbricked(t *testing.T) {
	const amount = int64(40_000)
	ct, contractId, owner := newH2CT(t, []utxoSeed{{10, amount}}, 100_000)

	// A real parent tx T: one dummy input, recipient at vout 0, the change U at vout 1.
	p2wpkh := append([]byte{0x00, 0x14}, make([]byte, 20)...)
	parentTx := wire.NewMsgTx(2)
	parentTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 0}, Sequence: wire.MaxTxInSequenceNum})
	parentTx.AddTxOut(&wire.TxOut{Value: 50_000, PkScript: p2wpkh})
	parentTx.AddTxOut(&wire.TxOut{Value: amount, PkScript: p2wpkh})
	var pbuf bytes.Buffer
	require.NoError(t, parentTx.Serialize(&pbuf))
	txidT := parentTx.TxID()

	// Re-seed the single gen-0 entry (id 10, unconfirmed pool) as U = T's change at vout 1,
	// replacing seedGenUtxos's "ab"x32 stamp, and register T as a pending spend.
	u := mapping.Utxo{TxId: txidT, Vout: 1, Amount: amount, Generation: 0}
	ublob := mapping.MarshalUtxo(&u)
	require.NotNil(t, ublob)
	ct.StateSet(contractId, constants.UtxoPrefix+strconv.FormatUint(10, 16), string(ublob))
	ct.StateSet(contractId, constants.TxSpendsPrefix+txidT, "01")
	ct.StateSet(contractId, constants.TxSpendsRegistryKey, string(mapping.MarshalTxSpendsRegistry(mapping.TxSpendsRegistry{txidT})))

	// migrateVault builds sweep S over U (id 10) and reserves it.
	orig, repl, build := migrateAndRedrive(t, ct, contractId, owner)
	_ = orig

	// confirmSpend(T, [1]) must NOT promote U: it is reserved, so the promotion loop skips it,
	// and T has no ms-/us-/sa- record, so the call fails "no unconfirmed outputs matched". U
	// keeps its unconfirmed id - the sweep is not bricked.
	cr := confirmTxBytesIdx(t, ct, contractId, owner, pbuf.Bytes(), build+constants.SweepAbandonBlocks, []uint32{1})
	require.False(t, cr.Success, "confirmSpend(T) must not promote the reserved sweep input")
	require.Contains(t, cr.ErrMsg, "no unconfirmed outputs matched")
	require.Contains(t, registryIds(t, ct, contractId), uint16(10),
		"U keeps its unconfirmed id (reserved, skipped); without the reservation this re-ids and bricks S")

	// S settles: U is swept and deleted, and the parent-clear removes T from pending.
	replTx := signingTx(t, ct, contractId, repl)
	require.True(t, confirmTxBytes(t, ct, contractId, owner, replTx, build+constants.SweepAbandonBlocks+5).Success,
		"the sweep settles (its input U was never re-id'd away)")
	require.Empty(t, ct.StateGet(contractId, constants.TxSpendsPrefix+txidT), "T is cleared once its change is swept")

	// confirmSpend(T) again fails cleanly, changing nothing.
	cr2 := confirmTxBytesIdx(t, ct, contractId, owner, pbuf.Bytes(), build+constants.SweepAbandonBlocks+10, []uint32{1})
	require.False(t, cr2.Success)
}
