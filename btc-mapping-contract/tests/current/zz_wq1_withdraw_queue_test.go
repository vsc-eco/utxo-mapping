package current_test

// WQ-1 withdrawal queue. From activateKey until the old generation's sweep settles every
// coin is on the RETIRING generation, and an unmap never draws a superseded generation's
// coins (D-1), so every withdrawal used to be refused with "total available balance
// insufficient". The same refusal hit a second withdrawal while a big coin was reserved by
// a first one (CONC-UNMAP-1). Now such a withdrawal is queued: the user is debited an
// escrow, and the settle that frees the coins builds it, oldest first, through the same
// code as a direct unmap. These tests drive the real ops and check I1/I2 at every step.

import (
	"crypto/sha256"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
	"time"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"vsc-node/lib/test_utils"
	tss_db "vsc-node/modules/db/vsc/tss"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// wqRotationCT is newOneRotationCT with the fee reserve size chosen by the test, and the
// gen-0 value credited to `user`, so I1, I2 and I3 (one account holds all of UserSupply)
// hold from the start. gen-0 RETIRING holds `gen0`, gen-1 ACTIVE holds only the reserve
// coin h2ReserveId.
func wqRotationCT(t *testing.T, gen0 []utxoSeed, reserve int64, user string) (*test_utils.ContractTest, string, string) {
	t.Helper()
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.LastHeightKey, "102")
	seedActiveGen0(t, &ct, contractId, owner)
	seedGenUtxos(t, &ct, contractId, 0, gen0)
	var total int64
	for _, s := range gen0 {
		total += s.amount
	}
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: total, UserSupply: total, BaseFeeRate: 1,
	})))
	ct.StateSet(contractId, constants.BalancePrefix+user, encodeBalance(t, total))
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	r := callKeyAction(t, &ct, contractId, owner, "activateKey", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	seedReserve(t, &ct, contractId, 1, h2ReserveId, reserve)
	return &ct, contractId, owner
}

func wqUnmap(t *testing.T, ct *test_utils.ContractTest, contractId, caller string, amount int64) test_utils.ContractTestCallResult {
	t.Helper()
	p, err := tinyjson.Marshal(mapping.TransferParams{Amount: strconv.FormatInt(amount, 10), To: regtestDestAddress(t)})
	require.NoError(t, err)
	return callAs(t, ct, contractId, caller, "unmap", p)
}

func wqBounds(t *testing.T, ct *test_utils.ContractTest, contractId string) (uint32, uint32) {
	t.Helper()
	raw := ct.StateGet(contractId, constants.UnmapQueueKey)
	if raw == "" {
		return 0, 0
	}
	require.Len(t, raw, 8)
	b := []byte(raw)
	return binary.BigEndian.Uint32(b[0:4]), binary.BigEndian.Uint32(b[4:8])
}

func wqSetBounds(ct *test_utils.ContractTest, contractId string, head, tail uint32) {
	var b [8]byte
	binary.BigEndian.PutUint32(b[0:4], head)
	binary.BigEndian.PutUint32(b[4:8], tail)
	ct.StateSet(contractId, constants.UnmapQueueKey, string(b[:]))
}

func wqEntry(t *testing.T, ct *test_utils.ContractTest, contractId string, seq uint32) *mapping.QueuedUnmap {
	t.Helper()
	raw := ct.StateGet(contractId, constants.UnmapQueuePrefix+strconv.FormatUint(uint64(seq), 10))
	if raw == "" {
		return nil
	}
	q, err := mapping.UnmarshalQueuedUnmap([]byte(raw))
	require.NoError(t, err)
	return q
}

func wqPending(t *testing.T, ct *test_utils.ContractTest, contractId string) []string {
	t.Helper()
	raw := ct.StateGet(contractId, constants.TxSpendsRegistryKey)
	if raw == "" {
		return nil
	}
	l, err := mapping.UnmarshalTxSpendsRegistry([]byte(raw))
	require.NoError(t, err)
	return l
}

func wqBal(t *testing.T, ct *test_utils.ContractTest, contractId, acct string) int64 {
	t.Helper()
	raw := ct.StateGet(contractId, constants.BalancePrefix+acct)
	if raw == "" {
		return 0
	}
	return decodeBalance(t, raw)
}

// wqQueuedEscrow sums the escrow of every live queued withdrawal.
func wqQueuedEscrow(t *testing.T, ct *test_utils.ContractTest, contractId string) int64 {
	t.Helper()
	head, tail := wqBounds(t, ct, contractId)
	var sum int64
	for seq := head; seq < tail; seq++ {
		if q := wqEntry(t, ct, contractId, seq); q != nil {
			sum += q.Escrow
		}
	}
	return sum
}

// wqConserved checks I1 and I2 with the value the vault is knowingly over-collateralised
// by: the queued escrow (read from state) plus inFlight, the debits of withdrawals in
// flight (their inputs stay registered until settle). balances lists every account
// holding a balance (I3).
func wqConserved(t *testing.T, ct *test_utils.ContractTest, contractId string, inFlight int64, balances ...string) {
	t.Helper()
	s := loadSupply(t, ct, contractId)
	require.Equal(t, sumRegistry(t, ct, contractId), s.ActiveSupply+s.FeeSupply+wqQueuedEscrow(t, ct, contractId)+inFlight,
		"I1: Sigma(UTXO) == Active + Fee + queued escrow + in-flight debits")
	require.Equal(t, s.ActiveSupply, s.UserSupply, "I2: Active == User")
	var sum int64
	for _, a := range balances {
		sum += wqBal(t, ct, contractId, a)
	}
	require.Equal(t, s.UserSupply, sum, "I3: Sigma(balances) == User")
}

// wqPaidTxId returns the txid in the "unmapq|paid|seq=<seq>|id=<txid>" log of a call.
func wqPaidTxId(t *testing.T, r test_utils.ContractTestCallResult, seq uint32) string {
	t.Helper()
	prefix := "unmapq|paid|seq=" + strconv.FormatUint(uint64(seq), 10) + "|id="
	for _, out := range r.Logs {
		for _, l := range out.Logs {
			if id, ok := strings.CutPrefix(l, prefix); ok {
				return id
			}
		}
	}
	t.Fatalf("no paid log for queued withdrawal %d", seq)
	return ""
}

// The main case, end to end: refused before, queued now, built exactly once at the settle
// that brings the coins back, settled, and the books exact afterwards.
func TestWQ1_QueuedDuringRotationPaidOnceAfterSweep(t *testing.T) {
	const user = "hive:milo-hpr"
	const want = int64(200_000) // more than the 100k reserve coin, the only gen-1 coin
	ct, contractId, owner := wqRotationCT(t, []utxoSeed{{1100, 500_000}}, 100_000, user)
	wqConserved(t, ct, contractId, 0, user)

	r := wqUnmap(t, ct, contractId, user, want)
	require.True(t, r.Success, "a withdrawal in the rotation window is queued, not refused: %s", r.ErrMsg)
	require.Empty(t, r.Logs[contractId].TssOps, "nothing is signed for a queued withdrawal")
	require.Empty(t, wqPending(t, ct, contractId), "nothing is built")
	head, tail := wqBounds(t, ct, contractId)
	require.Equal(t, [2]uint32{0, 1}, [2]uint32{head, tail})
	q := wqEntry(t, ct, contractId, 0)
	require.NotNil(t, q)
	require.Equal(t, user, q.From)
	require.Greater(t, q.Escrow, want+546, "escrow = amount + vscFee (0) + the single-input fee ceiling (largest fee + dust)")
	require.Less(t, q.Escrow-want, int64(2_000), "the single-input fee ceiling at rate 1 is a little over 1,100 sats")
	require.Equal(t, 500_000-q.Escrow, wqBal(t, ct, contractId, user))
	wqConserved(t, ct, contractId, 0, user)

	// The sweep is built; the queue waits.
	m := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, m.Err, m.ErrMsg)
	sweep := m.Ret
	require.NotNil(t, wqEntry(t, ct, contractId, 0), "building the sweep does not touch the queue")
	wqConserved(t, ct, contractId, 0, user)

	// The sweep settles: its output is a gen-1 coin, and the same call builds the queued
	// withdrawal from it.
	c := confirmMigrationSweep(t, ct, contractId, owner, sweep, 103)
	require.True(t, c.Success, "the sweep settles: %s", c.ErrMsg)
	unmapTx := wqPaidTxId(t, c, 0)
	require.Equal(t, []string{unmapTx}, wqPending(t, ct, contractId), "exactly one spend in flight: the queued withdrawal")
	require.NotEmpty(t, ct.StateGet(contractId, constants.PendingUnmapPrefix+unmapTx))
	require.NotEmpty(t, c.Logs[contractId].TssOps, "the drained withdrawal is signed in the settle call")
	for _, op := range c.Logs[contractId].TssOps {
		require.Equal(t, contractId+"-mainv1", op.KeyId, "only the active generation's key signs it (D-1, S3)")
	}
	_, outs := spendOutputs(t, ct, contractId, unmapTx)
	require.True(t, outs[want], "the withdrawal pays exactly the requested amount")
	require.Nil(t, wqEntry(t, ct, contractId, 0), "the entry is gone once built")
	head, tail = wqBounds(t, ct, contractId)
	require.Equal(t, head, tail, "queue empty")
	final, ok := logField(c, "unmap", "d")
	require.True(t, ok)
	require.Greater(t, final, want, "finalAmt = amount + true miner fee")
	require.Equal(t, int64(500_000)-final, wqBal(t, ct, contractId, user),
		"the user paid amount + miner fee in total, exactly what a direct unmap charges")
	wqConserved(t, ct, contractId, final, user)

	// The withdrawal settles: the books are exact.
	unmapTxBytes := signingTx(t, ct, contractId, unmapTx)
	u := confirmMigrationSweep(t, ct, contractId, owner, unmapTx, 110)
	require.True(t, u.Success, u.ErrMsg)
	wqConserved(t, ct, contractId, 0, user)

	// Paid once: nothing left to build, a drain and a replayed settle change nothing.
	balAfter := wqBal(t, ct, contractId, user)
	d := callAs(t, ct, contractId, "hive:anyone", "drainUnmapQueue", []byte(""))
	require.True(t, d.Success, d.ErrMsg)
	require.Empty(t, d.Logs[contractId].TssOps)
	rp := confirmTxBytes(t, ct, contractId, owner, unmapTxBytes, 120)
	require.False(t, rp.Success, "a replayed settle of the paid withdrawal is refused")
	require.Empty(t, wqPending(t, ct, contractId))
	require.Equal(t, balAfter, wqBal(t, ct, contractId, user))
	wqConserved(t, ct, contractId, 0, user)
}

// A genuinely insufficient USER balance is refused exactly as before, rotation or not, and
// nothing is queued or debited.
func TestWQ1_UserBalanceRefusalUnchanged(t *testing.T) {
	const user = "hive:milo-hpr"
	ct, contractId, _ := wqRotationCT(t, []utxoSeed{{1100, 500_000}}, 100_000, user)
	r := wqUnmap(t, ct, contractId, user, 600_000)
	require.False(t, r.Success)
	require.Contains(t, r.ErrMsg, "caller balance 500000 insufficient for amount+fee 600000",
		"the same preliminary refusal as before the queue")
	h, tl := wqBounds(t, ct, contractId)
	require.Equal(t, h, tl, "nothing queued")
	require.Equal(t, int64(500_000), wqBal(t, ct, contractId, user))
	wqConserved(t, ct, contractId, 0, user)
}

// CONC-UNMAP-1 outside any rotation: one coin, reserved by a first withdrawal. The second
// is queued and built from the first one's change when it settles.
func TestWQ1_SecondWithdrawalWaitsForReservedCoin(t *testing.T) {
	const user = "hive:milo-hpr"
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", user
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.LastHeightKey, "102")
	seedActiveGen0(t, &ct, contractId, owner)
	seedGenUtxos(t, &ct, contractId, 0, []utxoSeed{{1100, 300_000}})
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: 300_000, UserSupply: 300_000, BaseFeeRate: 1,
	})))
	ct.StateSet(contractId, constants.BalancePrefix+user, encodeBalance(t, 300_000))

	a := wqUnmap(t, &ct, contractId, user, 100_000)
	require.True(t, a.Success, a.ErrMsg)
	finalA, _ := logField(a, "unmap", "d")
	txA := wqPending(t, &ct, contractId)[0]
	wqConserved(t, &ct, contractId, finalA, user)

	b := wqUnmap(t, &ct, contractId, user, 50_000)
	require.True(t, b.Success, "the only coin is reserved by A, so B is queued, not refused: %s", b.ErrMsg)
	require.Equal(t, []string{txA}, wqPending(t, &ct, contractId), "B is not built yet")
	wqConserved(t, &ct, contractId, finalA, user)

	c := confirmMigrationSweep(t, &ct, contractId, owner, txA, 103)
	require.True(t, c.Success, c.ErrMsg)
	txB := wqPaidTxId(t, c, 0)
	finalB, _ := logField(c, "unmap", "d")
	require.Equal(t, []string{txB}, wqPending(t, &ct, contractId), "A settled, B built from A's change")
	wqConserved(t, &ct, contractId, finalB, user)

	require.True(t, confirmMigrationSweep(t, &ct, contractId, owner, txB, 110).Success)
	wqConserved(t, &ct, contractId, 0, user)
	require.Equal(t, int64(300_000)-finalA-finalB, wqBal(t, &ct, contractId, user))
}

// The queue cap refuses with no debit; one below it still queues. The settle drain plans at
// most MaxQueuePlansPerSettle; drainUnmapQueue builds the rest.
func TestWQ1_QueueCapAndDrainCap(t *testing.T) {
	const user = "hive:milo-hpr"
	const depositor = "hive:depositor"
	ct, contractId, owner := wqRotationCT(t, []utxoSeed{{1100, 900_000}}, 20_000, user)

	// Cap: a full queue (seeded bounds) refuses, with no debit. A placeholder spend in flight
	// keeps the self-heal (which would step over the seeded holes) out of the way.
	ct.StateSet(contractId, constants.TxSpendsRegistryKey, string(mapping.MarshalTxSpendsRegistry(mapping.TxSpendsRegistry{strings.Repeat("ee", 32)})))
	wqSetBounds(ct, contractId, 0, constants.MaxQueuedUnmaps)
	full := wqUnmap(t, ct, contractId, user, 100_000)
	require.False(t, full.Success)
	require.Contains(t, full.ErrMsg, "withdrawal queue is full")
	require.Equal(t, int64(900_000), wqBal(t, ct, contractId, user), "a refused request debits nothing")
	// One below the cap still queues (behind holes the drain steps over); cancel it again.
	wqSetBounds(ct, contractId, 0, constants.MaxQueuedUnmaps-1)
	last := strconv.Itoa(constants.MaxQueuedUnmaps - 1)
	one := wqUnmap(t, ct, contractId, user, 100_000)
	require.True(t, one.Success, one.ErrMsg)
	require.NotNil(t, wqEntry(t, ct, contractId, constants.MaxQueuedUnmaps-1))
	require.True(t, callAs(t, ct, contractId, user, "cancelUnmap", []byte(last)).Success)
	require.Equal(t, int64(900_000), wqBal(t, ct, contractId, user))
	ct.StateSet(contractId, constants.UnmapQueueKey, "")
	ct.StateSet(contractId, constants.TxSpendsRegistryKey, "")

	// Five queued withdrawals (each waits behind the first: FIFO). The settle plans 4 (the
	// cap), the drain the fifth. One per account (F-1), so the first four are distinct
	// accounts carved out of the gen-0 credit, so the whole queue is still backed only by the
	// held gen-0 coin (nothing a withdrawal can be built from yet).
	q := []string{"hive:q0", "hive:q1", "hive:q2", "hive:q3"}
	ct.StateSet(contractId, constants.BalancePrefix+user, encodeBalance(t, 900_000-int64(len(q))*150_000))
	for _, a := range q {
		ct.StateSet(contractId, constants.BalancePrefix+a, encodeBalance(t, 150_000))
	}
	for _, a := range q {
		r := wqUnmap(t, ct, contractId, a, 100_000)
		require.True(t, r.Success, r.ErrMsg)
	}
	h, tl := wqBounds(t, ct, contractId)
	require.Equal(t, [2]uint32{0, 4}, [2]uint32{h, tl})
	wqConserved(t, ct, contractId, 0, user, q[0], q[1], q[2], q[3])

	// The sweep is in flight. Deposits to the new generation meanwhile: enough free gen-1
	// coins that the settle's four builds plus the drained fifth each have one.
	m := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, m.Err, m.ErrMsg)
	for i := 0; i < 6; i++ {
		appendGenUtxo(t, ct, contractId, 1, uint16(3001+i), 200_000)
	}
	ct.StateSet(contractId, constants.BalancePrefix+depositor, encodeBalance(t, 6*200_000))
	wqConserved(t, ct, contractId, 0, user, q[0], q[1], q[2], q[3], depositor)

	// FIFO: coins are free now, but with a settle coming a new withdrawal still waits behind
	// the queue.
	late := wqUnmap(t, ct, contractId, depositor, 50_000)
	require.True(t, late.Success, late.ErrMsg)
	require.Equal(t, []string{m.Ret}, wqPending(t, ct, contractId), "it does not jump the queue")
	require.NotNil(t, wqEntry(t, ct, contractId, 4))
	wqConserved(t, ct, contractId, 0, user, q[0], q[1], q[2], q[3], depositor)

	c := confirmMigrationSweep(t, ct, contractId, owner, m.Ret, 103)
	require.True(t, c.Success, c.ErrMsg)
	require.Len(t, wqPending(t, ct, contractId), constants.MaxQueuePlansPerSettle,
		"one settle builds at most MaxQueuePlansPerSettle queued withdrawals")
	h, tl = wqBounds(t, ct, contractId)
	require.Equal(t, [2]uint32{4, 5}, [2]uint32{h, tl}, "the fifth still waits, in order")

	d := callAs(t, ct, contractId, "hive:anyone", "drainUnmapQueue", []byte(""))
	require.True(t, d.Success, d.ErrMsg)
	wqPaidTxId(t, d, 4)
	require.Len(t, wqPending(t, ct, contractId), 5)
	h, tl = wqBounds(t, ct, contractId)
	require.Equal(t, h, tl, "queue empty")

	// Settle all five; the books are exact.
	for i, tx := range wqPending(t, ct, contractId) {
		r := confirmMigrationSweep(t, ct, contractId, owner, tx, uint32(110+10*i))
		require.True(t, r.Success, r.ErrMsg)
	}
	wqConserved(t, ct, contractId, 0, user, q[0], q[1], q[2], q[3], depositor)
}

// A re-driven sweep: the queue is untouched by the re-drive and paid once when the
// replacement confirms.
func TestWQ1_RedrivenSweepPaysQueueOnce(t *testing.T) {
	const user = "hive:milo-hpr"
	ct, contractId, owner := wqRotationCT(t, []utxoSeed{{1100, 500_000}}, 100_000, user)
	require.True(t, wqUnmap(t, ct, contractId, user, 200_000).Success)

	m := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, m.Err, m.ErrMsg)
	setHeight(ct, contractId, 102+constants.RedriveStaleBlocks)
	rd := callKeyAction(t, ct, contractId, owner, "redriveSpend", []byte(m.Ret))
	require.Empty(t, rd.Err, rd.ErrMsg)
	repl := parseRedriveNewTxId(t, rd.Ret)
	require.NotNil(t, wqEntry(t, ct, contractId, 0), "a re-drive does not touch the queue")
	wqConserved(t, ct, contractId, 0, user)

	c := confirmTxBytes(t, ct, contractId, owner, signingTx(t, ct, contractId, repl), 200)
	require.True(t, c.Success, c.ErrMsg)
	tx := wqPaidTxId(t, c, 0)
	final, _ := logField(c, "unmap", "d")
	require.Equal(t, []string{tx}, wqPending(t, ct, contractId), "the whole sweep group cleared, the withdrawal built once")
	wqConserved(t, ct, contractId, final, user)
	require.True(t, confirmMigrationSweep(t, ct, contractId, owner, tx, 210).Success)
	wqConserved(t, ct, contractId, 0, user)
}

// An abandoned sweep leaves the queue intact; a late confirmation of it brings the coin
// back and pays the queue. Here the reserve coin is held by a first withdrawal in flight,
// so the second has no free coin at all.
func TestWQ1_AbandonedSweepLeavesQueueThenLateSettlePays(t *testing.T) {
	const user = "hive:milo-hpr"
	ct, contractId, owner := newH2CT(t, []utxoSeed{{10, 60_000}}, 100_000)
	ct.StateSet(contractId, constants.BalancePrefix+user, encodeBalance(t, 60_000))
	wqConserved(t, ct, contractId, 0, user)

	a := wqUnmap(t, ct, contractId, user, 10_000) // built from the reserve coin, which it reserves
	require.True(t, a.Success, a.ErrMsg)
	finalA, _ := logField(a, "unmap", "d")
	txA := wqPending(t, ct, contractId)[0]
	b := wqUnmap(t, ct, contractId, user, 30_000)
	require.True(t, b.Success, "queued: the reserve coin is reserved, gen-0 is retiring: %s", b.ErrMsg)
	wqConserved(t, ct, contractId, finalA, user)

	orig, repl, build := migrateAndRedrive(t, ct, contractId, owner)
	replTx := signingTx(t, ct, contractId, repl)
	setHeight(ct, contractId, build+constants.SweepAbandonBlocks)
	ab := callAs(t, ct, contractId, owner, "abandonSweep", []byte(orig))
	require.True(t, ab.Success, ab.ErrMsg)
	require.NotNil(t, wqEntry(t, ct, contractId, 0), "the abandon leaves the queued withdrawal in place")
	require.Equal(t, []string{txA}, wqPending(t, ct, contractId))
	// The written-off input left Sigma(UTXO) and FeeSupply together; the queue's escrow is
	// still over-collateralisation.
	wqConserved(t, ct, contractId, finalA, user)

	c := confirmTxBytes(t, ct, contractId, owner, replTx, build+constants.SweepAbandonBlocks+5)
	require.True(t, c.Success, "the late confirmation settles: %s", c.ErrMsg)
	txB := wqPaidTxId(t, c, 0)
	finalB, _ := logField(c, "unmap", "d")
	wqConserved(t, ct, contractId, finalA+finalB, user)

	h := build + constants.SweepAbandonBlocks + 20
	for _, tx := range []string{txA, txB} {
		r := confirmMigrationSweep(t, ct, contractId, owner, tx, h)
		require.True(t, r.Success, r.ErrMsg)
		h += 10
	}
	wqConserved(t, ct, contractId, 0, user)
	require.Equal(t, int64(60_000)-finalA-finalB, wqBal(t, ct, contractId, user))
}

// Cancel: only the account that queued it or the owner; the escrow comes back; a cancelled
// entry is never built; a second cancel is refused.
func TestWQ1_CancelRefundsAndIsNeverPaid(t *testing.T) {
	// Two accounts, one queued withdrawal each (F-1: one live per account). alice holds the
	// gen-0 credit; bob is funded explicitly.
	// Carve the gen-0 credit across alice and bob so both balances stay backed by the held
	// gen-0 coin (UserSupply unchanged), and give each one queued withdrawal (F-1).
	const alice, bob = "hive:alice", "hive:bob"
	ct, contractId, owner := wqRotationCT(t, []utxoSeed{{1100, 500_000}}, 100_000, alice)
	ct.StateSet(contractId, constants.BalancePrefix+alice, encodeBalance(t, 300_000))
	ct.StateSet(contractId, constants.BalancePrefix+bob, encodeBalance(t, 200_000))
	require.True(t, wqUnmap(t, ct, contractId, alice, 200_000).Success) // seq 0
	require.True(t, wqUnmap(t, ct, contractId, bob, 150_000).Success)   // seq 1
	e1 := wqEntry(t, ct, contractId, 1).Escrow
	wqConserved(t, ct, contractId, 0, alice, bob)

	s := callAs(t, ct, contractId, "hive:mallory", "cancelUnmap", []byte("0"))
	require.False(t, s.Success, "a stranger cannot cancel")
	require.Contains(t, s.ErrMsg, "only the account that queued")
	require.False(t, callAs(t, ct, contractId, bob, "cancelUnmap", []byte("0")).Success, "another user cannot cancel alice's entry")

	c0 := callAs(t, ct, contractId, alice, "cancelUnmap", []byte("0"))
	require.True(t, c0.Success, c0.ErrMsg)
	require.Nil(t, wqEntry(t, ct, contractId, 0))
	h, tl := wqBounds(t, ct, contractId)
	require.Equal(t, [2]uint32{1, 2}, [2]uint32{h, tl}, "the head steps over the cancelled entry")
	require.Equal(t, int64(300_000), wqBal(t, ct, contractId, alice), "alice's escrow returned in full")
	wqConserved(t, ct, contractId, 0, alice, bob)
	require.False(t, callAs(t, ct, contractId, alice, "cancelUnmap", []byte("0")).Success, "cancelled once only")
	// A record below the head (which the contract never leaves) is not refundable either.
	stale := ct.StateGet(contractId, constants.UnmapQueuePrefix+"1")
	ct.StateSet(contractId, constants.UnmapQueuePrefix+"0", stale)
	below := callAs(t, ct, contractId, bob, "cancelUnmap", []byte("0"))
	require.False(t, below.Success, "only head..tail-1 can be cancelled")
	require.Contains(t, below.ErrMsg, "no queued withdrawal 0")
	require.Equal(t, int64(200_000)-e1, wqBal(t, ct, contractId, bob))
	ct.StateSet(contractId, constants.UnmapQueuePrefix+"0", "")

	// The owner may cancel too (the escape hatch); the escrow goes to the account that paid it.
	c1 := callAs(t, ct, contractId, owner, "cancelUnmap", []byte("1"))
	require.True(t, c1.Success, c1.ErrMsg)
	h, tl = wqBounds(t, ct, contractId)
	require.Equal(t, h, tl, "queue empty")
	require.Equal(t, int64(200_000), wqBal(t, ct, contractId, bob), "bob's escrow returned in full")
	wqConserved(t, ct, contractId, 0, alice, bob)

	// The settle that frees the coins builds nothing for the cancelled entries.
	m := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, m.Err, m.ErrMsg)
	c := confirmMigrationSweep(t, ct, contractId, owner, m.Ret, 103)
	require.True(t, c.Success, c.ErrMsg)
	require.Empty(t, wqPending(t, ct, contractId), "a cancelled withdrawal is never built")
	wqConserved(t, ct, contractId, 0, alice, bob)
}

// Pause: the settle stays pause-exempt but builds nothing; drainUnmapQueue is refused while
// paused and pays the queue after unpause.
func TestWQ1_PauseHoldsQueueDrainAfterUnpause(t *testing.T) {
	const user = "hive:milo-hpr"
	ct, contractId, owner := wqRotationCT(t, []utxoSeed{{1100, 500_000}}, 100_000, user)
	require.True(t, wqUnmap(t, ct, contractId, user, 200_000).Success)
	m := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, m.Err, m.ErrMsg)

	require.Empty(t, callKeyAction(t, ct, contractId, owner, "pause", []byte("")).Err)
	c := confirmMigrationSweep(t, ct, contractId, owner, m.Ret, 103)
	require.True(t, c.Success, "the sweep still settles while paused: %s", c.ErrMsg)
	require.Empty(t, wqPending(t, ct, contractId), "nothing is built while paused")
	require.NotNil(t, wqEntry(t, ct, contractId, 0))
	wqConserved(t, ct, contractId, 0, user)
	dp := callAs(t, ct, contractId, "hive:anyone", "drainUnmapQueue", []byte(""))
	require.False(t, dp.Success)
	require.Contains(t, dp.ErrMsg, "paused")

	require.Empty(t, callKeyAction(t, ct, contractId, owner, "unpause", []byte("")).Err)
	d := callAs(t, ct, contractId, "hive:anyone", "drainUnmapQueue", []byte(""))
	require.True(t, d.Success, d.ErrMsg)
	tx := wqPaidTxId(t, d, 0)
	final, _ := logField(d, "unmap", "d")
	wqConserved(t, ct, contractId, final, user)
	require.True(t, confirmMigrationSweep(t, ct, contractId, owner, tx, 110).Success)
	wqConserved(t, ct, contractId, 0, user)
}

// A spender using an allowance (unmapFrom) is never queued: it keeps today's refusal.
func TestWQ1_AllowanceSpenderIsNotQueued(t *testing.T) {
	const user = "hive:alice"
	const spender = "hive:bob"
	ct, contractId, _ := wqRotationCT(t, []utxoSeed{{1100, 500_000}}, 100_000, user)
	ap, err := tinyjson.Marshal(mapping.AllowanceParams{Spender: spender, Amount: "300000"})
	require.NoError(t, err)
	require.True(t, callAs(t, ct, contractId, user, "approve", ap).Success)
	p, err := tinyjson.Marshal(mapping.TransferParams{Amount: "200000", To: regtestDestAddress(t), From: user})
	require.NoError(t, err)
	r := callAs(t, ct, contractId, spender, "unmapFrom", p)
	require.False(t, r.Success, "an allowance spender keeps the refusal")
	require.Contains(t, r.ErrMsg, "total available balance insufficient")
	h, tl := wqBounds(t, ct, contractId)
	require.Equal(t, h, tl, "nothing queued")
	require.Equal(t, int64(500_000), wqBal(t, ct, contractId, user))
}

// Coins that are not held anywhere (nothing reserved, no superseded generation) and still
// cannot cover the withdrawal: refused as before, not queued.
func TestWQ1_InsufficientCoinsNotHeldIsRefused(t *testing.T) {
	const user = "hive:milo-hpr"
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", user
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.LastHeightKey, "102")
	seedActiveGen0(t, &ct, contractId, owner)
	seedGenUtxos(t, &ct, contractId, 0, []utxoSeed{{1100, 300_000}})
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: 300_000, UserSupply: 300_000, BaseFeeRate: 1,
	})))
	ct.StateSet(contractId, constants.BalancePrefix+user, encodeBalance(t, 300_000))

	r := wqUnmap(t, &ct, contractId, user, 300_000) // the whole vault, plus a fee no coin covers
	require.False(t, r.Success)
	require.Contains(t, r.ErrMsg, "total available balance insufficient to complete transaction")
	h, tl := wqBounds(t, &ct, contractId)
	require.Equal(t, h, tl, "not queued: no coin is held, so waiting would not help")
	require.Equal(t, int64(300_000), wqBal(t, &ct, contractId, user))
}

// A request the build would refuse at the current fee rate is refused up front, with
// today's wording and no debit. A queued withdrawal that can no longer be paid as asked
// (here: the fee rate rose past its max_fee) is refunded in full when its turn comes, and
// the drain goes on. A deduct_fee withdrawal gets the unused fee estimate back, as a direct
// one keeps it.
func TestWQ1_BuildTimeRefusalsRefundInFull(t *testing.T) {
	const a, b, c, d = "hive:a", "hive:b", "hive:c", "hive:d"
	ct, contractId, owner := wqRotationCT(t, []utxoSeed{{1100, 900_000}}, 20_000, a)
	ct.StateSet(contractId, constants.BalancePrefix+a, encodeBalance(t, 200_000))
	ct.StateSet(contractId, constants.BalancePrefix+b, encodeBalance(t, 100_000))
	ct.StateSet(contractId, constants.BalancePrefix+c, encodeBalance(t, 300_000))
	ct.StateSet(contractId, constants.BalancePrefix+d, encodeBalance(t, 300_000))
	who := []string{a, b, c, d}
	wqConserved(t, ct, contractId, 0, who...)

	// a: everything, fee on top, nothing left for the miner fee.
	ra := wqUnmap(t, ct, contractId, a, 200_000)
	require.False(t, ra.Success)
	require.Contains(t, ra.ErrMsg, "account [hive:a] balance 200000 insufficient needs", "today's build-time wording")
	// b: a max_fee no build can meet.
	one := int64(1)
	pb, err := tinyjson.Marshal(mapping.TransferParams{Amount: "50000", To: regtestDestAddress(t), MaxFee: &one})
	require.NoError(t, err)
	rb := callAs(t, ct, contractId, b, "unmap", pb)
	require.False(t, rb.Success)
	require.Contains(t, rb.ErrMsg, "exceeds max_fee 1")
	// b: deduct_fee on an amount the fee leaves as dust.
	pb2, err := tinyjson.Marshal(mapping.TransferParams{Amount: "600", To: regtestDestAddress(t), DeductFee: true})
	require.NoError(t, err)
	rb2 := callAs(t, ct, contractId, b, "unmap", pb2)
	require.False(t, rb2.Success)
	require.Contains(t, rb2.ErrMsg, "amount too small to cover fees")
	h, tl := wqBounds(t, ct, contractId)
	require.Equal(t, h, tl, "none of them queued")
	require.Equal(t, int64(200_000), wqBal(t, ct, contractId, a))
	require.Equal(t, int64(100_000), wqBal(t, ct, contractId, b))

	// c: deduct_fee, queued. d: a max_fee the current rate meets, queued.
	pc, err := tinyjson.Marshal(mapping.TransferParams{Amount: "100000", To: regtestDestAddress(t), DeductFee: true})
	require.NoError(t, err)
	require.True(t, callAs(t, ct, contractId, c, "unmap", pc).Success)
	require.Greater(t, wqEntry(t, ct, contractId, 0).Escrow, int64(100_000), "deduct_fee escrows the amount plus room for a build costing more than its estimate")
	maxD := int64(2_000)
	pd, err := tinyjson.Marshal(mapping.TransferParams{Amount: "100000", To: regtestDestAddress(t), MaxFee: &maxD})
	require.NoError(t, err)
	rd := callAs(t, ct, contractId, d, "unmap", pd)
	require.True(t, rd.Success, rd.ErrMsg)
	wqConserved(t, ct, contractId, 0, who...)

	// The fee rate rises before the coins come back.
	m := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, m.Err, m.ErrMsg)
	sup := loadSupply(t, ct, contractId)
	sup.BaseFeeRate = 50
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&sup)))

	s := confirmMigrationSweep(t, ct, contractId, owner, m.Ret, 103)
	require.True(t, s.Success, s.ErrMsg)
	txC := wqPaidTxId(t, s, 0)
	finalC, _ := logField(s, "unmap", "d")
	require.LessOrEqual(t, finalC, int64(100_000), "deduct_fee: the user pays at most the amount")
	require.Equal(t, int64(300_000)-finalC, wqBal(t, ct, contractId, c), "the unused estimate came back")
	require.Equal(t, int64(300_000), wqBal(t, ct, contractId, d), "d refunded in full: the fee now exceeds its max_fee")
	require.Nil(t, wqEntry(t, ct, contractId, 1))
	require.Equal(t, []string{txC}, wqPending(t, ct, contractId), "only c was built")
	h, tl = wqBounds(t, ct, contractId)
	require.Equal(t, h, tl)
	wqConserved(t, ct, contractId, finalC, who...)
	require.True(t, confirmMigrationSweep(t, ct, contractId, owner, txC, 110).Success)
	wqConserved(t, ct, contractId, 0, who...)
}

// The drain must never break the settle it runs in. With the active key refusing to sign,
// the sweep still settles, the withdrawal stays queued with nothing half-written, and it
// is paid once the key signs again.
func TestWQ1_SigningRefusalKeepsQueueAndSettle(t *testing.T) {
	const user = "hive:milo-hpr"
	ct, contractId, owner := wqRotationCT(t, []utxoSeed{{1100, 500_000}}, 100_000, user)
	require.True(t, wqUnmap(t, ct, contractId, user, 200_000).Success)
	m := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, m.Err, m.ErrMsg)
	before := registryIds(t, ct, contractId)

	require.NoError(t, ct.Tss.Keys.SetKey(tss_db.TssKey{Id: contractId + "-mainv1", Status: tss_db.TssKeyDeprecated}))
	c := confirmMigrationSweep(t, ct, contractId, owner, m.Ret, 103)
	require.True(t, c.Success, "the settle succeeds even though the queued build cannot be signed: %s", c.ErrMsg)
	require.NotEqual(t, before, registryIds(t, ct, contractId), "the sweep really settled")
	require.Empty(t, c.Logs[contractId].TssOps, "no sign request left behind")
	require.Empty(t, wqPending(t, ct, contractId), "no spend recorded")
	require.NotNil(t, wqEntry(t, ct, contractId, 0), "still queued")
	require.Equal(t, 500_000-wqEntry(t, ct, contractId, 0).Escrow, wqBal(t, ct, contractId, user), "escrow still held, nothing else charged")
	wqConserved(t, ct, contractId, 0, user)

	setTssKeyProof(t, ct, contractId, "mainv1", Gen1PrimaryHex, 1, true)
	d := callAs(t, ct, contractId, "hive:anyone", "drainUnmapQueue", []byte(""))
	require.True(t, d.Success, d.ErrMsg)
	tx := wqPaidTxId(t, d, 0)
	final, _ := logField(d, "unmap", "d")
	wqConserved(t, ct, contractId, final, user)
	require.True(t, confirmMigrationSweep(t, ct, contractId, owner, tx, 110).Success)
	wqConserved(t, ct, contractId, 0, user)
}

// wqEscrowFee learns the fee room the contract escrows for a non-deduct withdrawal to
// regtestDestAddress at the current rate (the single-input fee ceiling): it queues one, reads
// escrow minus amount, and cancels it.
func wqEscrowFee(t *testing.T, ct *test_utils.ContractTest, contractId, acct string, amount int64) int64 {
	t.Helper()
	r := wqUnmap(t, ct, contractId, acct, amount)
	require.True(t, r.Success, r.ErrMsg)
	head, tail := wqBounds(t, ct, contractId)
	require.Equal(t, head+1, tail, "probe must be the only entry")
	m := wqEntry(t, ct, contractId, head).Escrow - amount
	require.True(t, callAs(t, ct, contractId, acct, "cancelUnmap", []byte(strconv.FormatUint(uint64(head), 10))).Success)
	return m
}

// wqPlannedRefundCT sets up the multi-input planned-refund residual. gen-0 retiring
// holds one large coin, so the baits queue (their coins are held) and can carry large
// balances. nBait accounts each queue a withdrawal of baitAmount with a balance of exactly
// baitAmount + the one-input escrow fee: the request and the cheap drain check both pass (an
// honest single-input build would fit), but every free coin after the deposits below is
// smaller than baitAmount, so the real build needs several inputs, whose higher fee the tight
// balance cannot cover, and it is refunded AFTER planning. The honest account queues a small
// withdrawal a single free coin covers. Then many small gen-1 deposit coins are added (and a
// depositor credited to keep I3), so coins are free but nothing is in flight: the next
// queueable withdrawal self-heals (the same MaxQueuePlansPerSettle cap confirmSpend uses).
func wqPlannedRefundCT(t *testing.T, nBait int, baitAmount, honestAmount int64) (ct *test_utils.ContractTest, contractId, owner string, baits []string, honest string, escrowFee int64) {
	t.Helper()
	const probe = "hive:probe"
	c, contractId, owner := wqRotationCT(t, []utxoSeed{{1100, 50_000_000}}, 20_000, probe)
	ct = c
	escrowFee = wqEscrowFee(t, ct, contractId, probe, baitAmount)
	honest = "hive:honest"
	rest := int64(50_000_000)
	for i := 0; i < nBait; i++ {
		a := "hive:bait" + strconv.Itoa(i)
		ct.StateSet(contractId, constants.BalancePrefix+a, encodeBalance(t, baitAmount+escrowFee))
		rest -= baitAmount + escrowFee
		baits = append(baits, a)
	}
	ct.StateSet(contractId, constants.BalancePrefix+honest, encodeBalance(t, honestAmount+100_000))
	rest -= honestAmount + 100_000
	// Trigger accounts, funded from the same held backing so I3 holds; they withdraw in the
	// test to fire the self-heal.
	for _, tg := range []string{"hive:trigger", "hive:trigger2"} {
		ct.StateSet(contractId, constants.BalancePrefix+tg, encodeBalance(t, honestAmount+100_000))
		rest -= honestAmount + 100_000
	}
	ct.StateSet(contractId, constants.BalancePrefix+probe, encodeBalance(t, rest))

	for _, a := range baits {
		require.True(t, wqUnmap(t, ct, contractId, a, baitAmount).Success, "bait %s must queue", a)
		require.Equal(t, int64(0), wqBal(t, ct, contractId, a), "escrow took the whole balance")
	}
	require.True(t, wqUnmap(t, ct, contractId, honest, honestAmount).Success, "honest must queue")

	// Free coins: 40 small gen-1 deposits of 40k each, credited to a depositor. A bait of 1M
	// needs ~25 of them, and a 25-input build's fee exceeds the single-input ceiling, so the
	// bait is refunded AFTER planning. (A 2-3 input build still fits the escrowed ceiling and
	// would just be built, so the residual genuinely needs a many-input amount.)
	for i := 0; i < 40; i++ {
		appendGenUtxo(t, ct, contractId, 1, uint16(4001+i), 40_000)
	}
	ct.StateSet(contractId, constants.BalancePrefix+"hive:depositor", encodeBalance(t, 40*40_000))
	return ct, contractId, owner, baits, honest, escrowFee
}

func wqAccounts(baits []string, honest string) []string {
	return append(append([]string{"hive:probe", "hive:depositor", "hive:trigger", "hive:trigger2"}, baits...), honest)
}

// wqSettleAll confirms every in-flight unmap, so the vault is no longer over-collateralised
// and conservation returns to the clean state (over == 0).
func wqSettleAll(t *testing.T, ct *test_utils.ContractTest, contractId, owner string, startHeight uint32) {
	t.Helper()
	h := startHeight
	for _, tx := range wqPending(t, ct, contractId) {
		require.True(t, confirmMigrationSweep(t, ct, contractId, owner, tx, h).Success)
		h += 5
	}
	require.Empty(t, wqPending(t, ct, contractId), "all settled")
}

// 3 planned refunds ahead of an honest entry: one self-heal drain (MaxQueuePlansPerSettle = 4)
// refunds the 3 and builds the honest one in the same pass (4 plans, within the cap). No
// strand.
func TestWQ1_PlannedRefundsDoNotStrandQueue(t *testing.T) {
	const baitAmount, honestAmount = int64(1_000_000), int64(300_000)
	ct, contractId, owner, baits, honest, escrowFee := wqPlannedRefundCT(t, 3, baitAmount, honestAmount)
	who := wqAccounts(baits, honest)
	wqConserved(t, ct, contractId, 0, who...)

	// A queueable withdrawal with the queue non-empty and nothing in flight self-heals.
	tr := wqUnmap(t, ct, contractId, "hive:trigger", honestAmount)
	require.True(t, tr.Success, tr.ErrMsg)

	refunds, paid := 0, 0
	for _, out := range tr.Logs {
		for _, l := range out.Logs {
			if strings.HasPrefix(l, "unmapq|refund|") {
				refunds++
			}
			if strings.HasPrefix(l, "unmapq|paid|") {
				paid++
			}
		}
	}
	require.Equal(t, 3, refunds, "the 3 baits were refunded after planning")
	require.Equal(t, 1, paid, "the honest entry was built in the same self-heal pass (plan 4 of 4)")
	for _, a := range baits {
		require.Equal(t, baitAmount+escrowFee, wqBal(t, ct, contractId, a), "bait refunded in full")
	}
	// The heal emptied the queue, so the trigger itself then took the direct path: the honest
	// entry (from the heal) and the trigger are both in flight, nothing stranded.
	require.Nil(t, wqEntry(t, ct, contractId, 4), "the honest entry (seq 4) was built")
	require.Len(t, wqPending(t, ct, contractId), 2, "honest + trigger in flight")
	hd, tl := wqBounds(t, ct, contractId)
	require.Equal(t, hd, tl, "queue empty, nothing stranded")
	wqSettleAll(t, ct, contractId, owner, 200)
	wqConserved(t, ct, contractId, 0, who...)
}

// 4 planned refunds ahead of an honest entry is the residual: one cap-4 drain spends all 4
// plans on refunds and does not reach the honest entry, which is left queued with nothing in
// flight (the strand). The next withdrawal heals it; so does drainUnmapQueue.
func TestWQ1_PlannedRefundResidualHealsAfterStrand(t *testing.T) {
	const baitAmount, honestAmount = int64(1_000_000), int64(300_000)
	heal := func(t *testing.T, byDrainEntrypoint bool) {
		ct, contractId, owner, baits, honest, escrowFee := wqPlannedRefundCT(t, 4, baitAmount, honestAmount)
		who := wqAccounts(baits, honest)
		wqConserved(t, ct, contractId, 0, who...)

		// probe took seq 0, the 4 baits seqs 1..4, the honest entry seq 5.
		// First self-heal: 4 bait refunds use up the cap (4 plans), the honest entry (plan 5)
		// is not reached.
		tr := wqUnmap(t, ct, contractId, "hive:trigger", honestAmount)
		require.True(t, tr.Success, tr.ErrMsg)
		for _, a := range baits {
			require.Equal(t, baitAmount+escrowFee, wqBal(t, ct, contractId, a), "bait refunded in full")
		}
		require.Empty(t, wqPending(t, ct, contractId), "STRAND: nothing was built, nothing is in flight")
		require.NotNil(t, wqEntry(t, ct, contractId, 5), "STRAND: the honest entry (seq 5) is still queued")
		require.NotNil(t, wqEntry(t, ct, contractId, 6), "the trigger queued behind it")
		wqConserved(t, ct, contractId, 0, who...)

		// Heal.
		if byDrainEntrypoint {
			d := callAs(t, ct, contractId, "hive:anyone", "drainUnmapQueue", []byte(""))
			require.True(t, d.Success, d.ErrMsg)
		} else {
			require.True(t, wqUnmap(t, ct, contractId, "hive:trigger2", honestAmount).Success)
		}
		require.Nil(t, wqEntry(t, ct, contractId, 5), "healed: the honest entry was built")
		require.GreaterOrEqual(t, len(wqPending(t, ct, contractId)), 1, "healed: it is in flight")
		hd, tl := wqBounds(t, ct, contractId)
		require.Equal(t, hd, tl, "queue empty after the heal")
		wqSettleAll(t, ct, contractId, owner, 200)
		wqConserved(t, ct, contractId, 0, who...)
	}
	t.Run("next-withdrawal", func(t *testing.T) { heal(t, false) })
	t.Run("drainUnmapQueue", func(t *testing.T) { heal(t, true) })
}

// wqWithChangeFee learns the true miner fee of a one-input build with a single change output
// WITHOUT using the queue's own escrow: a direct unmap from a single coin a little above the
// amount (change below splitThreshold, so exactly one change output). The ceiling sits well
// above it. rate sets the oracle fee rate.
func wqWithChangeFee(t *testing.T, amount, rate int64) int64 {
	t.Helper()
	const user = "hive:probefee"
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, user, ContractWasm)
	activateTssKey(&ct, contractId)
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	ct.StateSet(contractId, constants.LastHeightKey, "102")
	ct.StateSet(contractId, constants.BlockPrefix+"100", buildSeedHeaderRaw(t, time.Unix(0, 0)))
	coin := amount + 800_000 // change ~800k < splitThreshold -> exactly one change output
	ct.StateSet(contractId, constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(mapping.UtxoRegistry{{Id: 1024, Amount: coin}})))
	ct.StateSet(contractId, constants.UtxoPrefix+"400", changeUtxoBinary(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0, coin))
	ct.StateSet(contractId, constants.UtxoLastIdKey, encodeUtxoCounters(1025, 0))
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{ActiveSupply: coin, UserSupply: coin, BaseFeeRate: rate})))
	ct.StateSet(contractId, constants.BalancePrefix+user, encodeBalance(t, coin))
	r := wqUnmap(t, &ct, contractId, user, amount)
	require.True(t, r.Success, r.ErrMsg)
	final, ok := logField(r, "unmap", "d")
	require.True(t, ok)
	return final - amount
}

// wqCeiling reads the contract's escrowed single-input fee ceiling for a non-deduct
// withdrawal of amount to regtestDestAddress at the given rate: a throwaway rotation window
// where the coin is held, so the probe queues and its escrow is amount + the ceiling. It is
// the contract's own number; TestWQ1_CeilingIsTheBuildersWorstFee pins it to the builder's
// real worst fee measured on the direct path.
func wqCeiling(t *testing.T, amount, rate int64) int64 {
	t.Helper()
	const cp = "hive:ceilprobe"
	ct, contractId, _ := wqRotationCT(t, []utxoSeed{{1100, 50_000_000}}, 20_000, cp)
	if rate != 1 {
		sup := loadSupply(t, ct, contractId)
		sup.BaseFeeRate = rate
		ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&sup)))
	}
	require.True(t, wqUnmap(t, ct, contractId, cp, amount).Success)
	head, _ := wqBounds(t, ct, contractId)
	return wqEntry(t, ct, contractId, head).Escrow - amount
}

func wqHasRefundLog(r test_utils.ContractTestCallResult) bool {
	for _, out := range r.Logs {
		for _, l := range out.Logs {
			if strings.HasPrefix(l, "unmapq|refund|") {
				return true
			}
		}
	}
	return false
}

// wqBoundaryCT is a rotation window with one gen-0 coin; its sweep output is the single free
// coin, so a withdrawal builds from one input. gen0coin < 2*splitThreshold gives one change
// output. user holds userBal; filler holds the rest (I3).
func wqBoundaryCT(t *testing.T, user string, userBal, gen0coin int64) (*test_utils.ContractTest, string, string) {
	t.Helper()
	ct, contractId, owner := wqRotationCT(t, []utxoSeed{{1100, gen0coin}}, 20_000, "hive:filler")
	ct.StateSet(contractId, constants.BalancePrefix+user, encodeBalance(t, userBal))
	ct.StateSet(contractId, constants.BalancePrefix+"hive:filler", encodeBalance(t, gen0coin-userBal))
	return ct, contractId, owner
}

// The change-output bait: a non-deduct withdrawal whose balance is exactly amount + the
// one-input-one-change fee is refused at request, because the ceiling covers up to
// maxChangeOutputs change outputs plus the dust burn, and a real build from one big coin makes
// 4 change outputs (true fee above the one-change fee). So the bait cannot pass the cheap
// check and be refunded after planning. One big coin so the build would 4-split; refused at
// request with the ceiling message.
func TestWQ1_ChangeOutputBaitRefusedAtRequest(t *testing.T) {
	const user = "hive:milo-hpr"
	const amount = int64(300_000)
	oneChange := wqWithChangeFee(t, amount, 1)
	ceiling := wqCeiling(t, amount, 1)
	require.Greater(t, ceiling, oneChange, "the ceiling must exceed the one-change fee (4 change outputs + dust)")
	ct, contractId, _ := wqBoundaryCT(t, user, amount+oneChange, 12_000_000)
	r := wqUnmap(t, ct, contractId, user, amount)
	require.False(t, r.Success, "a balance at the one-change fee is below the ceiling: refused")
	require.Contains(t, r.ErrMsg, "largest fee it can cost", "the ceiling message names the room needed")
	hd, tl := wqBounds(t, ct, contractId)
	require.Equal(t, hd, tl, "nothing queued")
	require.Equal(t, amount+oneChange, wqBal(t, ct, contractId, user), "no debit")
}

// Positive boundary (i): a non-deduct request with balance EXACTLY amount + vscFee + the
// ceiling is queued (escrow == that) and then built; one sat below is refused. The real
// single-input build costs the one-change fee, well under the ceiling, so the build returns
// the unused margin to the user and never charges beyond the escrow and never full-refunds.
func TestWQ1_BoundaryExactBalanceQueuedAndBuilt(t *testing.T) {
	const user = "hive:exact"
	const amount = int64(300_000)
	ceiling := wqCeiling(t, amount, 1)
	oneChange := wqWithChangeFee(t, amount, 1)

	ct0, id0, _ := wqBoundaryCT(t, user, amount+ceiling-1, 1_500_000)
	r0 := wqUnmap(t, ct0, id0, user, amount)
	require.False(t, r0.Success, "one sat below the ceiling is refused")
	require.Contains(t, r0.ErrMsg, "largest fee it can cost")

	ct, contractId, owner := wqBoundaryCT(t, user, amount+ceiling, 1_500_000)
	who := []string{user, "hive:filler"}
	r := wqUnmap(t, ct, contractId, user, amount)
	require.True(t, r.Success, "exactly amount + the ceiling is accepted: %s", r.ErrMsg)
	q := wqEntry(t, ct, contractId, 0)
	require.NotNil(t, q)
	require.Equal(t, amount+ceiling, q.Escrow, "the escrow is amount + the single-input ceiling")
	require.Equal(t, int64(0), wqBal(t, ct, contractId, user))
	wqConserved(t, ct, contractId, 0, who...)

	m := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, m.Err, m.ErrMsg)
	s := confirmMigrationSweep(t, ct, contractId, owner, m.Ret, 103)
	require.True(t, s.Success, s.ErrMsg)
	tx := wqPaidTxId(t, s, 0)
	require.False(t, wqHasRefundLog(s), "built, not full-refunded")
	final, _ := logField(s, "unmap", "d")
	require.Equal(t, amount+oneChange, final, "the build charges only its true one-change fee")
	require.Equal(t, ceiling-oneChange, wqBal(t, ct, contractId, user), "the unused ceiling margin is returned, nothing charged beyond the escrow")
	wqConserved(t, ct, contractId, final, who...)
	require.True(t, confirmMigrationSweep(t, ct, contractId, owner, tx, 110).Success)
	wqConserved(t, ct, contractId, 0, who...)
}

// Positive boundary (ii): max_fee EXACTLY vscFee + the ceiling is queued and built; one sat
// below is refused at request.
func TestWQ1_BoundaryExactMaxFeeQueuedAndBuilt(t *testing.T) {
	const user = "hive:maxfee"
	const amount = int64(300_000)
	ceiling := wqCeiling(t, amount, 1)
	req := func(ct *test_utils.ContractTest, id string, maxFee int64) test_utils.ContractTestCallResult {
		p, err := tinyjson.Marshal(mapping.TransferParams{Amount: strconv.FormatInt(amount, 10), To: regtestDestAddress(t), MaxFee: &maxFee})
		require.NoError(t, err)
		return callAs(t, ct, id, user, "unmap", p)
	}

	ct0, id0, _ := wqBoundaryCT(t, user, 2_000_000, 1_500_000)
	r0 := req(ct0, id0, ceiling-1)
	require.False(t, r0.Success, "max_fee one sat below the ceiling is refused")
	require.Contains(t, r0.ErrMsg, "exceeds max_fee")

	ct, contractId, owner := wqBoundaryCT(t, user, 2_000_000, 1_500_000)
	who := []string{user, "hive:filler"}
	r := req(ct, contractId, ceiling)
	require.True(t, r.Success, "max_fee exactly the ceiling is accepted: %s", r.ErrMsg)
	m := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, m.Err, m.ErrMsg)
	s := confirmMigrationSweep(t, ct, contractId, owner, m.Ret, 103)
	require.True(t, s.Success, s.ErrMsg)
	tx := wqPaidTxId(t, s, 0)
	require.False(t, wqHasRefundLog(s), "built, not refunded")
	wqConserved(t, ct, contractId, mustLogField(t, s), who...)
	require.True(t, confirmMigrationSweep(t, ct, contractId, owner, tx, 110).Success)
	wqConserved(t, ct, contractId, 0, who...)
}

func mustLogField(t *testing.T, r test_utils.ContractTestCallResult) int64 {
	t.Helper()
	v, ok := logField(r, "unmap", "d")
	require.True(t, ok)
	return v
}

// Positive boundary (iii), the drain-time cheap check: queued at rate 1 (escrow takes the
// whole balance), the rate rises to 2, and the user is topped up by exactly the ceiling
// difference, so at the drain escrow + balance == amount + the rate-2 ceiling. It is not
// cheap-refunded; it is built. One sat less and it is cheap-refunded.
func TestWQ1_BoundaryDrainCheapCheckExact(t *testing.T) {
	const user = "hive:drainexact"
	const amount = int64(300_000)
	ceil1 := wqCeiling(t, amount, 1)
	ceil2 := wqCeiling(t, amount, 2)
	require.Greater(t, ceil2, ceil1)
	run := func(t *testing.T, topUp int64) (test_utils.ContractTestCallResult, *test_utils.ContractTest, string, string) {
		ct, contractId, owner := wqBoundaryCT(t, user, amount+ceil1, 1_500_000)
		require.True(t, wqUnmap(t, ct, contractId, user, amount).Success)
		require.Equal(t, int64(0), wqBal(t, ct, contractId, user))
		m := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
		require.Empty(t, m.Err, m.ErrMsg)
		tp, err := tinyjson.Marshal(mapping.TransferParams{Amount: strconv.FormatInt(topUp, 10), To: user})
		require.NoError(t, err)
		require.True(t, callAs(t, ct, contractId, "hive:filler", "transfer", tp).Success)
		sup := loadSupply(t, ct, contractId)
		sup.BaseFeeRate = 2
		ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&sup)))
		s := confirmMigrationSweep(t, ct, contractId, owner, m.Ret, 103)
		require.True(t, s.Success, s.ErrMsg)
		return s, ct, contractId, owner
	}
	t.Run("exact", func(t *testing.T) {
		s, ct, contractId, owner := run(t, ceil2-ceil1)
		tx := wqPaidTxId(t, s, 0)
		require.False(t, wqHasRefundLog(s), "exactly enough at the drain rate: not cheap-refunded")
		wqConserved(t, ct, contractId, mustLogField(t, s), user, "hive:filler")
		require.True(t, confirmMigrationSweep(t, ct, contractId, owner, tx, 110).Success)
		wqConserved(t, ct, contractId, 0, user, "hive:filler")
	})
	t.Run("one-sat-below", func(t *testing.T) {
		s, ct, contractId, _ := run(t, ceil2-ceil1-1)
		require.True(t, wqHasRefundLog(s), "one sat below at the drain rate: cheap-refunded")
		require.Empty(t, wqPending(t, ct, contractId), "nothing built")
		require.Equal(t, amount+ceil1+(ceil2-ceil1-1), wqBal(t, ct, contractId, user), "escrow returned in full")
		wqConserved(t, ct, contractId, 0, user, "hive:filler")
	})
}

// wqLinearCeiling is the single-input ceiling a 43-bytes-per-change-output size model gives:
// one tagged input, the destination, maxChangeOutputs change outputs, plus dust. It is what a
// builder pricing change outputs linearly would charge at most. buildSpendTransaction prices
// k change outputs as 43*k(k+1)/2 bytes, so from about 3 sat/vB its 4-change build costs more
// than this; the bait tests use it as the balance a too-small ceiling would accept.
func wqLinearCeiling(t *testing.T, rate int64) int64 {
	t.Helper()
	net := regtestParams()
	_, tagged, err := mapping.AddressWithBackup(TestPrimaryPubKeyHex, TestBackupPubKeyHex, make([]byte, 32), net)
	require.NoError(t, err)
	changeAddr, _, err := mapping.AddressWithBackup(TestPrimaryPubKeyHex, TestBackupPubKeyHex, nil, net)
	require.NoError(t, err)
	changeDecoded, err := btcutil.DecodeAddress(changeAddr, net)
	require.NoError(t, err)
	changePk, err := txscript.PayToAddrScript(changeDecoded)
	require.NoError(t, err)
	destDecoded, err := btcutil.DecodeAddress(regtestDestAddress(t), net)
	require.NoError(t, err)
	destPk, err := txscript.PayToAddrScript(destDecoded)
	require.NoError(t, err)
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(0, destPk))
	for i := 0; i < 4; i++ {
		tx.AddTxOut(wire.NewTxOut(0, changePk))
	}
	baseSize := int64(tx.SerializeSize())
	totalSize := baseSize + int64(72+len(tagged)+5)
	return ((baseSize*3+totalSize+3)/4+2)*rate + 546
}

var wqTag = func() []byte { h := sha256.Sum256([]byte("wq-tagged-coin")); return h[:] }()

// wqDirect builds a withdrawal on the DIRECT path (no queue, no rotation) from one free coin
// of `coin` sats, tagged like a deposit or untagged like change, at `rate`, and returns
// finalAmt - amount: the true miner fee without deduct_fee, btcFee - estimate with it. It
// reads the builder's real behaviour without going through any queue bound, so the queue
// tests can compare the contract's bounds against it.
func wqDirect(t *testing.T, coin int64, tagged bool, amount, rate int64, deduct bool) int64 {
	t.Helper()
	const user = "hive:direct"
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	id := "mapping_contract"
	ct.RegisterContract(id, user, ContractWasm)
	activateTssKey(&ct, id)
	ct.StateSet(id, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(id, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	ct.StateSet(id, constants.LastHeightKey, "102")
	ct.StateSet(id, constants.BlockPrefix+"100", buildSeedHeaderRaw(t, time.Unix(0, 0)))
	u := mapping.Utxo{TxId: strings.Repeat("ab", 32), Vout: 0, Amount: coin}
	if tagged {
		u.Tag = wqTag
	}
	ct.StateSet(id, constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(mapping.UtxoRegistry{{Id: 1024, Amount: coin}})))
	ct.StateSet(id, constants.UtxoPrefix+"400", string(mapping.MarshalUtxo(&u)))
	ct.StateSet(id, constants.UtxoLastIdKey, encodeUtxoCounters(1025, 0))
	ct.StateSet(id, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{ActiveSupply: coin, UserSupply: coin, BaseFeeRate: rate})))
	ct.StateSet(id, constants.BalancePrefix+user, encodeBalance(t, coin))
	p, err := tinyjson.Marshal(mapping.TransferParams{Amount: strconv.FormatInt(amount, 10), To: regtestDestAddress(t), DeductFee: deduct})
	require.NoError(t, err)
	r := callAs(t, &ct, id, user, "unmap", p)
	require.True(t, r.Success, "direct build: %s", r.ErrMsg)
	final, ok := logField(r, "unmap", "d")
	require.True(t, ok)
	return final - amount
}

// wqDeductMargin learns the escrowed deduct_fee room (escrow - amount) at `rate` from a
// queued probe, like wqCeiling.
func wqDeductMargin(t *testing.T, amount, rate int64) int64 {
	t.Helper()
	const cp = "hive:marginprobe"
	ct, contractId, _ := wqRotationCT(t, []utxoSeed{{1100, 50_000_000}}, 20_000, cp)
	wqSetRate(t, ct, contractId, rate)
	r := wqDeductUnmap(t, ct, contractId, cp, amount)
	require.True(t, r.Success, r.ErrMsg)
	head, _ := wqBounds(t, ct, contractId)
	return wqEntry(t, ct, contractId, head).Escrow - amount
}

func wqSetRate(t *testing.T, ct *test_utils.ContractTest, contractId string, rate int64) {
	t.Helper()
	sup := loadSupply(t, ct, contractId)
	sup.BaseFeeRate = rate
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&sup)))
}

func wqDeductUnmap(t *testing.T, ct *test_utils.ContractTest, contractId, caller string, amount int64) test_utils.ContractTestCallResult {
	t.Helper()
	p, err := tinyjson.Marshal(mapping.TransferParams{Amount: strconv.FormatInt(amount, 10), To: regtestDestAddress(t), DeductFee: true})
	require.NoError(t, err)
	return callAs(t, ct, contractId, caller, "unmap", p)
}

// wqTaggedCT is a rotation window at `rate` where the user's queued withdrawal will be built
// from ONE free tagged gen-1 coin of `coin` sats (a deposit made during the window): the
// filler queues a 30M blocker first (seq 0, larger than the tagged coin, so it waits for and
// is then built from the sweep output), then the coin arrives, credited to a depositor; the
// user holds userBal out of the filler's share. The user's request, made next, queues behind
// the blocker (seq 1) and at the drain finds the sweep output reserved by the blocker's
// build, so it is built from the tagged coin alone (the 100k fee reserve, which funds the
// sweep up to 200 sat/vB, is too small for the amounts these tests withdraw).
func wqTaggedCT(t *testing.T, user string, userBal, coin, rate int64) (*test_utils.ContractTest, string, string, []string) {
	t.Helper()
	const gen0 = int64(40_000_000)
	ct, contractId, owner := wqRotationCT(t, []utxoSeed{{1100, gen0}}, 100_000, "hive:filler")
	wqSetRate(t, ct, contractId, rate)
	require.True(t, wqUnmap(t, ct, contractId, "hive:filler", 30_000_000).Success, "blocker queued")
	u := mapping.Utxo{TxId: strings.Repeat("ef", 32), Vout: 7, Amount: coin, Tag: wqTag, Generation: 1}
	var reg mapping.UtxoRegistry
	if raw := ct.StateGet(contractId, constants.UtxoRegistryKey); len(raw) > 0 {
		r, err := mapping.UnmarshalUtxoRegistry([]byte(raw))
		require.NoError(t, err)
		reg = r
	}
	reg = append(reg, mapping.UtxoRegistryEntry{Id: 3001, Amount: coin})
	ct.StateSet(contractId, constants.UtxoPrefix+strconv.FormatUint(3001, 16), string(mapping.MarshalUtxo(&u)))
	ct.StateSet(contractId, constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(reg)))
	sup := loadSupply(t, ct, contractId)
	sup.ActiveSupply += coin
	sup.UserSupply += coin
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&sup)))
	filler := wqBal(t, ct, contractId, "hive:filler")
	require.LessOrEqual(t, userBal, filler)
	ct.StateSet(contractId, constants.BalancePrefix+"hive:filler", encodeBalance(t, filler-userBal))
	ct.StateSet(contractId, constants.BalancePrefix+user, encodeBalance(t, userBal))
	ct.StateSet(contractId, constants.BalancePrefix+"hive:depositor", encodeBalance(t, coin))
	who := []string{user, "hive:filler", "hive:depositor"}
	wqConserved(t, ct, contractId, 0, who...)
	return ct, contractId, owner, who
}

// wqTaggedDrain settles the sweep (draining the queue: the blocker, then the user's entry)
// and requires the user's entry (seq 1) to be BUILT, not refunded, then settles every build
// and checks conservation. It returns the user's balance after the build.
func wqTaggedDrain(t *testing.T, ct *test_utils.ContractTest, contractId, owner, user string, who []string) int64 {
	t.Helper()
	m := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, m.Err, m.ErrMsg)
	s := confirmMigrationSweep(t, ct, contractId, owner, m.Ret, 103)
	require.True(t, s.Success, s.ErrMsg)
	wqPaidTxId(t, s, 0)
	wqPaidTxId(t, s, 1)
	require.False(t, wqHasRefundLog(s), "nothing refunded")
	hd, tl := wqBounds(t, ct, contractId)
	require.Equal(t, hd, tl, "queue drained")
	bal := wqBal(t, ct, contractId, user)
	wqSettleAll(t, ct, contractId, owner, 110)
	wqConserved(t, ct, contractId, 0, who...)
	return bal
}

func wqRefusedNoDebit(t *testing.T, ct *test_utils.ContractTest, contractId, user string, r test_utils.ContractTestCallResult, bal int64, msg string) {
	t.Helper()
	require.False(t, r.Success, msg)
	hd, tl := wqBounds(t, ct, contractId)
	require.Equal(t, uint32(1), tl-hd, "only the blocker is queued")
	require.Equal(t, bal, wqBal(t, ct, contractId, user), "no debit")
}

var wqRates = []int64{1, 50, 200}

// The ceiling is exactly the builder's own worst single-input fee plus dust: the true fee of
// a direct build from one TAGGED coin large enough for maxChangeOutputs change outputs, plus
// dustThreshold. Measured on the direct path, so it does not move with the contract's bound.
func TestWQ1_CeilingIsTheBuildersWorstFee(t *testing.T) {
	const amount = int64(300_000)
	for _, rate := range wqRates {
		worst := wqDirect(t, amount+12_000_000, true, amount, rate, false)
		require.Equal(t, worst+546, wqCeiling(t, amount, rate), "rate %d", rate)
		// CHANGE-FEE-1 fixed: the builder prices each change output once, so its real worst is
		// exactly the linear model (it used to exceed it by 43*(k(k+1)/2-k) vbytes).
		require.Equal(t, worst+546, wqLinearCeiling(t, rate), "rate %d: the builder's real worst is the linear model", rate)
	}
}

// The 4-change bait: one big tagged coin, so the build makes maxChangeOutputs change outputs.
// A balance one sat below amount + the ceiling is refused at request (with CHANGE-FEE-1 fixed
// the ceiling IS the linear model); exactly amount + the ceiling is queued and built with no refund, the user keeping exactly
// dustThreshold (the build cost the ceiling minus dust); one sat less is refused. Also with
// max_fee exactly the ceiling: queued and built; one sat less refused.
func TestWQ1_FourChangeBaitRefusedOrBuilt(t *testing.T) {
	const user = "hive:bait4"
	const amount = int64(300_000)
	const coin = amount + 12_000_000
	for _, rate := range wqRates {
		t.Run("rate"+strconv.FormatInt(rate, 10), func(t *testing.T) {
			ceil := wqCeiling(t, amount, rate)
			for _, bal := range []int64{amount + ceil - 1} {
				ct, id, _, _ := wqTaggedCT(t, user, bal, coin, rate)
				r := wqUnmap(t, ct, id, user, amount)
				wqRefusedNoDebit(t, ct, id, user, r, bal, "below the ceiling: refused at request")
				require.Contains(t, r.ErrMsg, "largest fee it can cost")
			}
			ct, id, owner, who := wqTaggedCT(t, user, amount+ceil, coin, rate)
			require.True(t, wqUnmap(t, ct, id, user, amount).Success)
			require.Equal(t, int64(546), wqTaggedDrain(t, ct, id, owner, user, who), "built from the tagged coin with 4 change outputs: exactly dust left")

			req := func(ct *test_utils.ContractTest, id string, maxFee int64) test_utils.ContractTestCallResult {
				p, err := tinyjson.Marshal(mapping.TransferParams{Amount: strconv.FormatInt(amount, 10), To: regtestDestAddress(t), MaxFee: &maxFee})
				require.NoError(t, err)
				return callAs(t, ct, id, user, "unmap", p)
			}
			ct, id, _, _ = wqTaggedCT(t, user, amount+2*ceil, coin, rate)
			r := req(ct, id, ceil-1)
			wqRefusedNoDebit(t, ct, id, user, r, amount+2*ceil, "max_fee one below the ceiling: refused")
			require.Contains(t, r.ErrMsg, "exceeds max_fee")
			ct, id, owner, who = wqTaggedCT(t, user, amount+2*ceil, coin, rate)
			require.True(t, req(ct, id, ceil).Success, "max_fee exactly the ceiling is queued")
			require.Equal(t, ceil+546, wqTaggedDrain(t, ct, id, owner, user, who), "built, true fee = ceiling - dust")
		})
	}
}

// The deduct_fee burn bait: one tagged coin just above the amount, so the deduct build has no
// change output and burns the remainder; finalAmt exceeds the amount by that remainder (more
// than dust here). A balance of exactly the amount, or the amount + dust, is refused at
// request; amount + the deduct margin is queued and built with no refund. Only at low fee
// rates can a single-input deduct build burn: from about 5 sat/vB the estimate subtracted
// from the amount always leaves a change output above dust.
func TestWQ1_DeductBurnBaitRefusedOrBuilt(t *testing.T) {
	const user = "hive:burn"
	const amount = int64(300_000)
	const rate = int64(1)
	const coin = amount + 560
	excess := wqDirect(t, coin, true, amount, rate, true)
	require.Greater(t, excess, int64(546), "the burn bait is genuine: finalAmt exceeds amount + dust")
	margin := wqDeductMargin(t, amount, rate)
	for _, bal := range []int64{amount, amount + 546, amount + margin - 1} {
		ct, id, _, _ := wqTaggedCT(t, user, bal, coin, rate)
		r := wqDeductUnmap(t, ct, id, user, amount)
		wqRefusedNoDebit(t, ct, id, user, r, bal, "below amount + margin: refused at request")
		require.Contains(t, r.ErrMsg, "deduct_fee included")
	}
	ct, id, owner, who := wqTaggedCT(t, user, amount+margin, coin, rate)
	require.True(t, wqDeductUnmap(t, ct, id, user, amount).Success)
	require.Equal(t, margin-excess, wqTaggedDrain(t, ct, id, owner, user, who), "built; the build cost exactly the burned remainder above the amount")
}

// The deduct_fee change-count crossing bait: the estimate sees no change output, but the real
// build (which sends amount - estimate, so has the estimate's worth more change) adds one, so
// finalAmt exceeds the amount by that output's priced size minus the estimate's slack, well
// above dust at high rates. Refused at request below amount + margin (amount + dust included);
// built with no refund at amount + margin.
func TestWQ1_DeductChangeCrossingBaitRefusedOrBuilt(t *testing.T) {
	const user = "hive:cross"
	const amount = int64(300_000)
	for _, rate := range wqRates {
		t.Run("rate"+strconv.FormatInt(rate, 10), func(t *testing.T) {
			coin := amount + 546 + 144*rate // the estimate's own no-change edge for one input
			excess := wqDirect(t, coin, true, amount, rate, true)
			if rate >= 50 {
				require.Greater(t, excess, int64(546), "the crossing bait is genuine at rate %d", rate)
			}
			margin := wqDeductMargin(t, amount, rate)
			require.GreaterOrEqual(t, margin, excess)
			for _, bal := range []int64{amount + 546, amount + margin - 1} {
				ct, id, _, _ := wqTaggedCT(t, user, bal, coin, rate)
				r := wqDeductUnmap(t, ct, id, user, amount)
				wqRefusedNoDebit(t, ct, id, user, r, bal, "below amount + margin: refused at request")
			}
			ct, id, owner, who := wqTaggedCT(t, user, amount+margin, coin, rate)
			require.True(t, wqDeductUnmap(t, ct, id, user, amount).Success)
			require.Equal(t, margin-excess, wqTaggedDrain(t, ct, id, owner, user, who), "built with no refund")
		})
	}
}

// The deduct_fee small-amount bait: from one big coin, planUnmap's estimate for one input
// counts maxChangeOutputs change outputs, so it refuses as dust a deduct amount that a
// no-change bound would let through (the window between the two bounds: 691-862 sats at
// rate 1 with each change output priced once, CHANGE-FEE-1). Those are refused at request,
// with the smallest queueable amount in the message; that amount is queued and built with no
// refund, one sat less is refused.
func TestWQ1_DeductSmallAmountBaitRefusedOrBuilt(t *testing.T) {
	const user = "hive:small"
	const coin = int64(12_000_000)
	for _, rate := range wqRates {
		t.Run("rate"+strconv.FormatInt(rate, 10), func(t *testing.T) {
			// Read the stated least from one clear refusal, then probe INSIDE the bait window
			// (between the no-change bound and the real 4-change bound): least minus four and
			// two change outputs' worth, and least - 1 (review W-1).
			least := int64(0)
			{
				ct, id, _, _ := wqTaggedCT(t, user, 5_000_000, coin, rate)
				r := wqDeductUnmap(t, ct, id, user, 600)
				wqRefusedNoDebit(t, ct, id, user, r, 5_000_000, "600 sats deduct refused at request")
				i := strings.LastIndex(r.ErrMsg, "withdraw at least ")
				require.GreaterOrEqual(t, i, 0, r.ErrMsg)
				n, err := strconv.ParseInt(r.ErrMsg[i+len("withdraw at least "):], 10, 64)
				require.NoError(t, err)
				least = n
			}
			for _, amt := range []int64{least - 4*43*rate, least - 2*43*rate} {
				if amt <= 546 {
					continue
				}
				ct, id, _, _ := wqTaggedCT(t, user, 5_000_000, coin, rate)
				r := wqDeductUnmap(t, ct, id, user, amt)
				wqRefusedNoDebit(t, ct, id, user, r, 5_000_000, "inside the bait window: refused at request")
				require.Contains(t, r.ErrMsg, "amount too small to cover fees")
				require.Contains(t, r.ErrMsg, "withdraw at least "+strconv.FormatInt(least, 10), "the same least is stated")
			}
			ct, id, _, _ := wqTaggedCT(t, user, 5_000_000, coin, rate)
			wqRefusedNoDebit(t, ct, id, user, wqDeductUnmap(t, ct, id, user, least-1), 5_000_000, "one below the stated least")
			ct, id, owner, who := wqTaggedCT(t, user, 5_000_000, coin, rate)
			require.True(t, wqDeductUnmap(t, ct, id, user, least).Success, "the stated least is queued")
			wqTaggedDrain(t, ct, id, owner, user, who)
		})
	}
}
