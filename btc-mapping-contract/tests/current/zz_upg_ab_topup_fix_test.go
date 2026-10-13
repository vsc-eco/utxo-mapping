package current_test

// UPG-1 / UPG-2 / AB-1 — HandleTopUpFeeReserve must never double-index an outpoint.
//
// A top-up SPV-proves a BTC deposit to the vault's untagged address, credits FeeSupply,
// and indexes the output as a confirmed UTXO. Its dedup guards are: the tx is not a live
// "us-"/"ms-"/"d-" vault spend, and the output is not already in the per-block observed
// list. Two gaps (both verified open on this base, 458d13e):
//
//   UPG-1/UPG-2: a v2 settle records its output observed, but an output indexed BEFORE
//   that discipline existed — a legacy "main"-era change/sweep carried over by an IN-PLACE
//   #29 upgrade — has no observed entry. A top-up pointed at that already-held outpoint
//   indexed it a SECOND time: phantom duplicate UTXO, FeeSupply inflated, false theft-halt,
//   first sweep double-spends. Fix: outpointRegistered() rejects an outpoint already held.
//
//   AB-1: abandoning a sweep deletes its "ms-"/"d-" records (clearSpendGroup) and leaves
//   an "sa-<txid>" record, so the three guards miss it; a top-up then credits it now and
//   settleAbandonedSweep credits the same output again on confirm. Fix: an "sa-" guard,
//   mirroring the us-/ms-/d- guards. (AB-1's other half — settleAbandonedSweep recording
//   observed — is already present on this base, so it is not re-fixed here.)

import (
	"strconv"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"github.com/stretchr/testify/require"
)

// TestWR_UPG1_TopUpRefusesAlreadyRegisteredOutpoint reproduces the main-era condition (an
// output that is a live registered UTXO but carries no observed entry) by clearing the
// observed list after a normal top-up, then replays the top-up. The fix catches it via the
// registry rather than the observed list, so no duplicate UTXO and no FeeSupply inflation.
func TestWR_UPG1_TopUpRefusesAlreadyRegisteredOutpoint(t *testing.T) {
	const amount = int64(250_000)
	const blockHeight = uint32(100)
	fx := buildFeeReserveFixture(t, amount, blockHeight)
	ct, contractId, _ := newFeeReserveCT(t, fx, 3)

	// First top-up: credits + indexes + records the outpoint observed (normal v2 discipline).
	require.True(t, callTopUpFeeReserve(t, ct, contractId, "hive:funder", fx, "tx-topup-1").Success)
	supply1 := loadSupply(t, ct, contractId)
	reg1, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, reg1, 1, "the first top-up indexes exactly one UTXO")
	require.Equal(t, amount, supply1.FeeSupply)

	// Recreate the UPG-1 precondition: a live registered UTXO with NO observed entry (exactly
	// a "main"-era output carried over by an in-place upgrade — v1 never recorded observed).
	// Clearing the per-block observed list leaves the registry untouched.
	ct.StateSet(contractId, constants.ObservedBlockPrefix+strconv.FormatUint(uint64(blockHeight), 10), "")

	// Replay the SAME outpoint. Before the fix the absent observed entry let it index a SECOND
	// time (duplicate UTXO, FeeSupply inflated). The fix rejects it via the registry.
	res := callTopUpFeeReserve(t, ct, contractId, "hive:funder", fx, "tx-topup-2")
	require.False(t, res.Success, "re-crediting an already-registered outpoint must be refused")

	supply2 := loadSupply(t, ct, contractId)
	reg2, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, reg2, 1, "no phantom duplicate UTXO — the registry is unchanged by the replay")
	require.Equal(t, supply1.FeeSupply, supply2.FeeSupply, "FeeSupply not inflated by the replay")
}

// TestWR_AB1_TopUpRefusesAbandonedSweepTx proves the "sa-" guard. The guard (like its
// us-/ms-/d- siblings) is a presence check, so a non-empty "sa-<txid>" record is the exact
// precondition; the realistic abandon lifecycle is covered by the abandon tests.
func TestWR_AB1_TopUpRefusesAbandonedSweepTx(t *testing.T) {
	const amount = int64(250_000)
	const blockHeight = uint32(100)
	fx := buildFeeReserveFixture(t, amount, blockHeight)
	ct, contractId, _ := newFeeReserveCT(t, fx, 3)

	// An abandoned sweep keyed by this tx's id: abandon deletes "ms-"/"d-" and leaves "sa-".
	ct.StateSet(contractId, constants.AbandonedSweepPrefix+fx.TxId, "x")

	res := callTopUpFeeReserve(t, ct, contractId, "hive:funder", fx, "tx-topup-ab")
	require.False(t, res.Success, "a top-up pointed at an abandoned sweep tx must be refused")
	require.Contains(t, res.ErrMsg, "abandoned migration sweep",
		"refused by the AB-1 sa- guard specifically; got %q", res.ErrMsg)

	// Nothing credited or indexed — an abandoned sweep settles via confirmSpend, not topUp.
	require.Equal(t, int64(0), loadSupply(t, ct, contractId).FeeSupply, "no FeeSupply credit from the refused top-up")
	require.Empty(t, ct.StateGet(contractId, constants.UtxoRegistryKey), "no phantom UTXO indexed")
}
