package current_test

// WQ-1 edge cases: refunds at the head or a settle that skipped its drain must never leave an
// honest withdrawal queued with nothing to drain it, an exhausted sequence number refuses
// without a debit, and a record that does not decode is kept, not skipped.

import (
	"math"
	"strconv"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/require"
)

// R1: refunds caused by a fee-rate rise between request and build (an honest, unavoidable
// source: every build prices at cs.Supply.BaseFeeRate) must not strand an honest withdrawal
// queued behind them. a and b set max_fee 2000, valid at 1 sat/vB when they queue; the rate
// rises to 50 before the sweep settles, so both can only be refunded. h must still be built
// by that settle.
func TestWQ1R_FeeRiseRefundsDoNotStrandQueue(t *testing.T) {
	const a, b, h = "hive:a", "hive:b", "hive:h"
	ct, contractId, owner := wqRotationCT(t, []utxoSeed{{1100, 900_000}}, 20_000, a)
	ct.StateSet(contractId, constants.BalancePrefix+a, encodeBalance(t, 100_000))
	ct.StateSet(contractId, constants.BalancePrefix+b, encodeBalance(t, 100_000))
	ct.StateSet(contractId, constants.BalancePrefix+h, encodeBalance(t, 700_000))
	wqConserved(t, ct, contractId, 0, a, b, h)

	maxFee := int64(2000)
	for _, who := range []string{a, b} {
		p, err := tinyjson.Marshal(mapping.TransferParams{Amount: "50000", To: regtestDestAddress(t), MaxFee: &maxFee})
		require.NoError(t, err)
		r := callAs(t, ct, contractId, who, "unmap", p)
		require.True(t, r.Success, "max_fee 2000 is valid at 1 sat/vB, so it queues: %s", r.ErrMsg)
	}
	require.True(t, wqUnmap(t, ct, contractId, h, 200_000).Success)

	m := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, m.Err, m.ErrMsg)
	sup := loadSupply(t, ct, contractId)
	sup.BaseFeeRate = 50
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&sup)))

	s := confirmMigrationSweep(t, ct, contractId, owner, m.Ret, 103)
	require.True(t, s.Success, s.ErrMsg)
	require.Equal(t, int64(100_000), wqBal(t, ct, contractId, a), "a refunded in full")
	require.Equal(t, int64(100_000), wqBal(t, ct, contractId, b), "b refunded in full")
	hd, tl := wqBounds(t, ct, contractId)
	require.Equal(t, hd, tl, "STRANDED: h still queued (head %d tail %d) after the settle", hd, tl)
	require.Len(t, wqPending(t, ct, contractId), 1, "h is built by the same settle")
	final, ok := logField(s, "unmap", "d")
	require.True(t, ok)
	wqConserved(t, ct, contractId, final, a, b, h)
}

// R2: a queue left with an entry, free coins and nothing in flight (here: the sweep settled
// while paused, so its drain was skipped, then unpause) must heal on the next withdrawal
// instead of queueing it behind an entry nothing will ever drain.
func TestWQ1R_NextWithdrawalHealsStrandedQueue(t *testing.T) {
	const user = "hive:milo-hpr"
	ct, contractId, owner := wqRotationCT(t, []utxoSeed{{1100, 500_000}}, 100_000, user)
	require.True(t, wqUnmap(t, ct, contractId, user, 200_000).Success)
	m := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, m.Err, m.ErrMsg)
	require.Empty(t, callKeyAction(t, ct, contractId, owner, "pause", []byte("")).Err)
	require.True(t, confirmMigrationSweep(t, ct, contractId, owner, m.Ret, 103).Success)
	require.Empty(t, callKeyAction(t, ct, contractId, owner, "unpause", []byte("")).Err)
	require.Empty(t, wqPending(t, ct, contractId), "precondition: nothing in flight")
	require.NotNil(t, wqEntry(t, ct, contractId, 0), "precondition: entry 0 still queued")

	r := wqUnmap(t, ct, contractId, user, 50_000)
	require.True(t, r.Success, r.ErrMsg)
	require.Nil(t, wqEntry(t, ct, contractId, 0), "STRANDED: entry 0 was not drained by the next withdrawal")
	require.NotEmpty(t, wqPending(t, ct, contractId), "STRANDED: nothing in flight after the next withdrawal")
}

// R3: the sequence-number guard.
func TestWQ1R_SequenceExhaustedRefusesWithoutDebit(t *testing.T) {
	const user = "hive:milo-hpr"
	ct, contractId, _ := wqRotationCT(t, []utxoSeed{{1100, 500_000}}, 100_000, user)
	wqSetBounds(ct, contractId, math.MaxUint32-1, math.MaxUint32)
	r := wqUnmap(t, ct, contractId, user, 200_000)
	require.False(t, r.Success)
	require.Contains(t, r.ErrMsg, "sequence exhausted")
	require.Equal(t, int64(500_000), wqBal(t, ct, contractId, user), "refused request debits nothing")
}

// R4: a corrupt record at the head (only a bug can write one) stops the drain without
// losing anything, and the sweep settle it runs in still succeeds.
func TestWQ1R_CorruptHeadRecordDoesNotBreakSettle(t *testing.T) {
	const user = "hive:milo-hpr"
	ct, contractId, owner := wqRotationCT(t, []utxoSeed{{1100, 500_000}}, 100_000, user)
	require.True(t, wqUnmap(t, ct, contractId, user, 200_000).Success)
	ct.StateSet(contractId, constants.UnmapQueuePrefix+"0", "garbage")
	m := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, m.Err, m.ErrMsg)
	s := confirmMigrationSweep(t, ct, contractId, owner, m.Ret, 103)
	require.True(t, s.Success, "the sweep settle must not fail because of the queue: %s", s.ErrMsg)
	hd, tl := wqBounds(t, ct, contractId)
	require.Equal(t, [2]uint32{0, 1}, [2]uint32{hd, tl}, "the corrupt entry is kept, not skipped")
}

// F-1: one live queued withdrawal per account. A second request from the same account is
// refused with no debit, so one account cannot fill the queue in the window (and cancel for
// free before the settle) to refuse everyone else; after a cancel it may queue again.
func TestWQ1F1_OneQueuedWithdrawalPerAccount(t *testing.T) {
	const user = "hive:milo-hpr"
	ct, contractId, _ := wqRotationCT(t, []utxoSeed{{1100, 500_000}}, 100_000, user)
	require.True(t, wqUnmap(t, ct, contractId, user, 200_000).Success)
	bal := wqBal(t, ct, contractId, user)
	second := wqUnmap(t, ct, contractId, user, 150_000)
	require.False(t, second.Success, "a second queued withdrawal from the same account is refused")
	require.Contains(t, second.ErrMsg, "already has a queued withdrawal")
	require.Equal(t, bal, wqBal(t, ct, contractId, user), "the refused request debits nothing")
	hd, tl := wqBounds(t, ct, contractId)
	require.Equal(t, [2]uint32{0, 1}, [2]uint32{hd, tl})
	require.True(t, callAs(t, ct, contractId, user, "cancelUnmap", []byte("0")).Success)
	require.True(t, wqUnmap(t, ct, contractId, user, 150_000).Success, "after a cancel the account may queue again")
	require.NotNil(t, wqEntry(t, ct, contractId, 1), "the re-queued withdrawal is seq 1")
	wqConserved(t, ct, contractId, 0, user) // nothing is built; wqConserved counts queued escrow itself
}

// F-2: a record that does not decode (a bug, or an entry from an unknown layout version)
// never blocks the entries behind it: it is kept and logged, the head does not move past
// it, and the next entry is still built at the settle.
func TestWQ1F2_UndecodableRecordDoesNotBlockOthers(t *testing.T) {
	const a, b = "hive:a", "hive:b"
	ct, contractId, owner := wqRotationCT(t, []utxoSeed{{1100, 900_000}}, 20_000, a)
	ct.StateSet(contractId, constants.BalancePrefix+a, encodeBalance(t, 400_000))
	ct.StateSet(contractId, constants.BalancePrefix+b, encodeBalance(t, 500_000))
	require.True(t, wqUnmap(t, ct, contractId, a, 100_000).Success)
	require.True(t, wqUnmap(t, ct, contractId, b, 200_000).Success)
	balA := wqBal(t, ct, contractId, a)
	// Entry 0 becomes a record from an unknown layout version.
	raw := []byte(ct.StateGet(contractId, constants.UnmapQueuePrefix+"0"))
	raw[0] = 9
	ct.StateSet(contractId, constants.UnmapQueuePrefix+"0", string(raw))

	m := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, m.Err, m.ErrMsg)
	s := confirmMigrationSweep(t, ct, contractId, owner, m.Ret, 103)
	require.True(t, s.Success, "the settle succeeds despite the undecodable record: %s", s.ErrMsg)
	wqPaidTxId(t, s, 1)
	require.Len(t, wqPending(t, ct, contractId), 1, "b's withdrawal behind the bad record is built")
	require.Nil(t, wqEntry(t, ct, contractId, 1))
	require.Equal(t, string(raw), ct.StateGet(contractId, constants.UnmapQueuePrefix+"0"), "the bad record is kept untouched")
	hd, tl := wqBounds(t, ct, contractId)
	require.Equal(t, [2]uint32{0, 2}, [2]uint32{hd, tl}, "the head does not move past the kept record")
	require.Equal(t, balA, wqBal(t, ct, contractId, a), "a's escrow is neither refunded nor lost: it stays with the kept record")
	require.False(t, callAs(t, ct, contractId, a, "cancelUnmap", []byte("0")).Success, "cancel cannot decode it either")
}

// F-2: unreadable queue bounds fail closed. A withdrawal that needs the queue is refused
// with no debit (instead of handing out sequence numbers whose records may still hold
// escrow); a withdrawal that can be built now still goes through; cancel is refused; a
// settle still succeeds.
func TestWQ1F2_UnreadableBoundsFailClosed(t *testing.T) {
	const user = "hive:milo-hpr"
	ct, contractId, owner := wqRotationCT(t, []utxoSeed{{1100, 500_000}}, 100_000, user)
	ct.StateSet(contractId, constants.UnmapQueueKey, "bad")
	bal := wqBal(t, ct, contractId, user)
	r := wqUnmap(t, ct, contractId, user, 200_000) // needs the queue (more than the 100k gen-1 coin)
	require.False(t, r.Success)
	require.Contains(t, r.ErrMsg, "withdrawal queue state is unreadable")
	require.Equal(t, bal, wqBal(t, ct, contractId, user))
	require.Equal(t, "bad", ct.StateGet(contractId, constants.UnmapQueueKey), "nothing overwrote the bounds")
	direct := wqUnmap(t, ct, contractId, user, 50_000) // fits the free gen-1 coin
	require.True(t, direct.Success, "a withdrawal that can be built now still goes through: %s", direct.ErrMsg)
	require.Len(t, wqPending(t, ct, contractId), 1)
	require.False(t, callAs(t, ct, contractId, user, "cancelUnmap", []byte("0")).Success)
	m := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, m.Err, m.ErrMsg)
	require.True(t, confirmMigrationSweep(t, ct, contractId, owner, m.Ret, 103).Success, "a settle still succeeds")
}

// A queued user can always take the escrow back: cancel is gated neither by the pause nor
// by the theft-halt flag.
func TestWQ1_CancelWorksWhilePausedAndUnderTheftHalt(t *testing.T) {
	const user = "hive:milo-hpr"
	ct, contractId, owner := wqRotationCT(t, []utxoSeed{{1100, 500_000}}, 100_000, user)
	full := wqBal(t, ct, contractId, user)
	require.True(t, wqUnmap(t, ct, contractId, user, 200_000).Success)
	require.Empty(t, callKeyAction(t, ct, contractId, owner, "pause", []byte("")).Err)
	require.True(t, callAs(t, ct, contractId, user, "cancelUnmap", []byte("0")).Success, "cancel while paused")
	require.Equal(t, full, wqBal(t, ct, contractId, user))
	require.Empty(t, callKeyAction(t, ct, contractId, owner, "unpause", []byte("")).Err)
	require.True(t, wqUnmap(t, ct, contractId, user, 200_000).Success)
	ct.StateSet(contractId, constants.BtcTheftHaltKey, "1")
	require.True(t, callAs(t, ct, contractId, user, "cancelUnmap", []byte("1")).Success, "cancel under the theft halt")
	require.Equal(t, full, wqBal(t, ct, contractId, user))
	wqConserved(t, ct, contractId, 0, user)
}

// F-4: the escape when the bot cannot afford a loaded settle: while paused the sweep's
// confirmSpend skips the drain, so it costs about what it costs with an empty queue.
func TestWQ1F4_PausedSettleCostsLikeAnEmptyQueue(t *testing.T) {
	settleRc := func(queued int) int64 {
		const first = "hive:u0"
		ct, contractId, owner := wqRotationCT(t, []utxoSeed{{1100, 900_000}}, 20_000, first)
		ct.StateSet(contractId, constants.BalancePrefix+first, encodeBalance(t, 900_000-int64(queued)*100_000))
		for i := 1; i <= queued; i++ {
			ct.StateSet(contractId, constants.BalancePrefix+"hive:u"+strconv.Itoa(i), encodeBalance(t, 100_000))
		}
		for i := 1; i <= queued; i++ {
			require.True(t, wqUnmap(t, ct, contractId, "hive:u"+strconv.Itoa(i), 50_000).Success)
		}
		m := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
		require.Empty(t, m.Err, m.ErrMsg)
		require.Empty(t, callKeyAction(t, ct, contractId, owner, "pause", []byte("")).Err)
		c := confirmMigrationSweep(t, ct, contractId, owner, m.Ret, 103)
		require.True(t, c.Success, c.ErrMsg)
		require.Empty(t, wqPending(t, ct, contractId), "nothing built while paused")
		return c.RcUsed
	}
	empty, loaded := settleRc(0), settleRc(8)
	t.Logf("paused sweep confirmSpend RC: empty queue %d, 8 queued %d", empty, loaded)
	require.LessOrEqual(t, loaded, empty+100, "a paused settle does no queue work")
}
