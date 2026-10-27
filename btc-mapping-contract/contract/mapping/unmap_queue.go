package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"encoding/binary"
	"errors"
	"math"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// unmap_queue.go: WQ-1, the withdrawal queue.
//
// From activateKey until the old generation's sweep settles, every coin sits on the
// RETIRING generation, and a user unmap never draws a superseded generation's coins (D-1,
// getInputUtxoIds; the node's S3 output scoping enforces the same). The same refusal hits
// a second withdrawal while one big coin is reserved by a first one (reserved until its
// settle). In both cases the coins are not gone, only held, and they come back at a
// settle: the sweep's output is indexed to the active generation, an unmap's change is
// indexed as a new coin.
//
// So such a withdrawal is accepted instead of refused. The request debits the user an escrow
// (what HandleUnmap's preliminary check requires, plus room for the largest fee any
// single-input build of it can cost: checkUnmapPayable), records the request, and returns.
// The next confirmSpend (the settle that frees the coins) builds queued withdrawals oldest
// first, through the same planUnmap/commitUnmap as a direct unmap, and settles the escrow
// against the real cost: the unused part goes back to the user, a miner fee beyond it is
// charged from the user's balance, exactly as HandleUnmap's own debit would. A request a
// single-input build might not pay at the current fee rate is refused up front
// (enqueueUnmap) and again, as a cheap refund before any coin selection, at the drain, so a
// withdrawal is refunded after coin selection only when it needs several inputs or the
// coins turned out genuinely insufficient. A user may cancel a queued withdrawal and get the
// escrow back.
//
// Accounting, with E the escrow and F the build's finalAmt:
//   request:  balance -= E, UserSupply -= E, ActiveSupply -= E. Sigma(UTXO) unchanged, so
//             the vault is over-collateralised by E, the same state as a withdrawal in
//             flight. I2 (Active == User) holds.
//   build:    balance, UserSupply and ActiveSupply += E - F; FeeSupply += vscFee. Net of
//             request and build that is exactly HandleUnmap's own movement (-F, -F, +vscFee).
//   refund:   balance, UserSupply and ActiveSupply += E. Net zero.
//   settle:   unchanged (settleUnmap).
//
// Scope: only a user withdrawing their own balance in a direct call is queued. A contract
// caller or an allowance spender keeps the refusal, so its own transaction reverts as a
// whole: a contract that is told "paid" cannot be paid later, or refunded to a balance it
// cannot attribute. Those callers are never queued and never wait behind the queue.
//
// Nothing here touches the node's signing rules: a queued withdrawal is built only from
// active-generation coins, at a moment where a direct unmap would also be built.

// isOwnDirectWithdrawal reports whether this unmap may be queued: the debited account is
// the caller, and the caller is the transaction's own signer (not a contract call).
func isOwnDirectWithdrawal(env sdk.Env, from string) bool {
	caller := env.Caller.String()
	return from == caller && caller == env.Sender.Address.String()
}

func queuedUnmapKey(seq uint32) string {
	return constants.UnmapQueuePrefix + strconv.FormatUint(uint64(seq), 10)
}

// loadUnmapQueueBounds reads (head, tail). Absent is an empty queue at 0 (ok). A present
// value that does not decode (only a bug writes one) is NOT read as empty: that would hand
// out sequence numbers whose records still hold escrow and overwrite them. ok is false
// then, and every caller parks the queue instead (no enqueue, no drain, no cancel) until
// the state is repaired; withdrawals that do not need the queue keep working.
func loadUnmapQueueBounds() (uint32, uint32, bool) {
	raw := sdk.StateGetObject(constants.UnmapQueueKey)
	if raw == nil || *raw == "" {
		return 0, 0, true
	}
	if len(*raw) != 8 {
		return 0, 0, false
	}
	b := []byte(*raw)
	head := binary.BigEndian.Uint32(b[0:4])
	tail := binary.BigEndian.Uint32(b[4:8])
	if tail < head {
		return 0, 0, false
	}
	return head, tail, true
}

var errQueueStateUnreadable = ce.NewContractError(ce.ErrStateAccess,
	"withdrawal queue state is unreadable; withdrawals that need the queue are refused until it is repaired")

// saveUnmapQueueBounds keeps the key even when the queue is empty, so a sequence number is
// never handed out twice (log lines and cancel numbers stay unique).
func saveUnmapQueueBounds(head, tail uint32) {
	var b [8]byte
	binary.BigEndian.PutUint32(b[0:4], head)
	binary.BigEndian.PutUint32(b[4:8], tail)
	sdk.StateSetObject(constants.UnmapQueueKey, string(b[:]))
}

// unmapQueueLength is tail-head: live entries plus cancelled holes not yet stepped over. An
// unreadable queue reads as 0 here, so a withdrawal that can be built now is not sent to a
// queue that would refuse it; enqueueUnmap still refuses one that needs the queue.
func unmapQueueLength() uint32 {
	head, tail, ok := loadUnmapQueueBounds()
	if !ok {
		return 0
	}
	return tail - head
}

// QueuedUnmap layout ("wq-"+seq), version 1:
//
//	[1] layout version (1), so a later contract version can still read entries queued
//	    under this one
//	[8] Amount  [8] Escrow  [8] VscFee  [8] MaxFee (0 when absent)
//	[1] flags (bit 0 DeductFee, bit 1 MaxFee present)
//	[4] RequestHeight
//	[2] len(From)  [N] From
//	[M] To (the record tail, no length prefix)
const queuedUnmapLayoutV1 = 1

const queuedUnmapFixedLen = 1 + 8 + 8 + 8 + 8 + 1 + 4 + 2

func MarshalQueuedUnmap(q *QueuedUnmap) []byte {
	buf := make([]byte, queuedUnmapFixedLen+len(q.From)+len(q.To))
	buf[0] = queuedUnmapLayoutV1
	off := 1
	binary.BigEndian.PutUint64(buf[off:], uint64(q.Amount))
	off += 8
	binary.BigEndian.PutUint64(buf[off:], uint64(q.Escrow))
	off += 8
	binary.BigEndian.PutUint64(buf[off:], uint64(q.VscFee))
	off += 8
	var flags byte
	var maxFee int64
	if q.DeductFee {
		flags |= 1
	}
	if q.MaxFee != nil {
		flags |= 2
		maxFee = *q.MaxFee
	}
	binary.BigEndian.PutUint64(buf[off:], uint64(maxFee))
	off += 8
	buf[off] = flags
	off++
	binary.BigEndian.PutUint32(buf[off:], q.RequestHeight)
	off += 4
	binary.BigEndian.PutUint16(buf[off:], uint16(len(q.From)))
	off += 2
	copy(buf[off:], q.From)
	off += len(q.From)
	copy(buf[off:], q.To)
	return buf
}

func UnmarshalQueuedUnmap(data []byte) (*QueuedUnmap, error) {
	if len(data) < queuedUnmapFixedLen {
		return nil, errors.New("queued unmap record too short")
	}
	if data[0] != queuedUnmapLayoutV1 {
		return nil, errors.New("queued unmap record has unknown layout version " + strconv.Itoa(int(data[0])))
	}
	q := &QueuedUnmap{}
	off := 1
	q.Amount = int64(binary.BigEndian.Uint64(data[off:]))
	off += 8
	q.Escrow = int64(binary.BigEndian.Uint64(data[off:]))
	off += 8
	q.VscFee = int64(binary.BigEndian.Uint64(data[off:]))
	off += 8
	maxFee := int64(binary.BigEndian.Uint64(data[off:]))
	off += 8
	flags := data[off]
	off++
	q.DeductFee = flags&1 != 0
	if flags&2 != 0 {
		q.MaxFee = &maxFee
	}
	q.RequestHeight = binary.BigEndian.Uint32(data[off:])
	off += 4
	n := int(binary.BigEndian.Uint16(data[off:]))
	off += 2
	if off+n > len(data) {
		return nil, errors.New("queued unmap record truncated (from)")
	}
	q.From = string(data[off : off+n])
	off += n
	q.To = string(data[off:])
	if q.From == "" || q.To == "" || q.Amount <= 0 || q.Escrow <= 0 || q.VscFee < 0 {
		return nil, errors.New("queued unmap record has empty or non-positive fields")
	}
	return q, nil
}

// unmapScripts is what the queue's fee bounds need about one withdrawal's destination:
//   - to and changeAddress: the destination and the vault change address, as planUnmap
//     passes them to buildSpendTransaction;
//   - dest: the destination output script (txscript.PayToAddrScript, as the builder);
//   - witness: the active generation's UNTAGGED vault witness script, the smallest a vault
//     input can carry (change coins, sweep outputs, fee-reserve coins).
type unmapScripts struct {
	to, changeAddress string
	dest, witness     []byte
}

// checkUnmapDestination refuses up front, with the same errors, a destination that the
// build would refuse anyway (HandleUnmap's change-address guard, buildSpendTransaction's
// decode and network checks), so a request that can never be paid is not queued, and
// returns what the fee bounds need.
func (cs *ContractState) checkUnmapDestination(to string) (*unmapScripts, error) {
	changeAddress, witness, err := createP2WSHAddressWithBackup(cs.PublicKeys.Primary, cs.PublicKeys.Backup, nil, cs.NetworkParams)
	if err != nil {
		return nil, ce.WrapContractError(ce.ErrTransaction, err, "error creating change address")
	}
	if strings.EqualFold(to, changeAddress) {
		return nil, ce.NewContractError(ce.ErrInput, "destination address must differ from the vault change address")
	}
	destAddr, err := btcutil.DecodeAddress(to, cs.NetworkParams)
	if err != nil {
		return nil, ce.WrapContractError(ce.ErrInput, err, "error decoding destination btc address ["+to+"]")
	}
	if !destAddr.IsForNet(cs.NetworkParams) {
		return nil, ce.NewContractError(ce.ErrInput,
			"destination btc address ["+to+"] is not a "+cs.NetworkParams.Name+" address")
	}
	dest, err := txscript.PayToAddrScript(destAddr)
	if err != nil {
		return nil, ce.WrapContractError(ce.ErrInput, err, "error building destination script")
	}
	return &unmapScripts{to: to, changeAddress: changeAddress, dest: dest, witness: witness}, nil
}

// minUnmapFee is a lower bound of estimateFee for this withdrawal at the current rate: one
// input with the untagged witness, the destination output, no change output, priced by the
// builder's own calculateSegwitFee. estimateFee prices at least this for any number of
// inputs n >= 1 and any change: the same vSize formula with 10+41n+43 non-witness bytes
// (here 59 + a destination script of at most 34 bytes, the longest DecodeAddress accepts)
// plus its change outputs, and 189 witness bytes per input (here 77 + a 76-78 byte script).
func (cs *ContractState) minUnmapFee(sc *unmapScripts) (int64, error) {
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(0, sc.dest))
	return cs.calculateSegwitFee(int64(tx.SerializeSize()), map[int][]byte{0: sc.witness})
}

// feeBoundChange is the change the fee bounds give their synthetic single-input spend. At
// any rate up to MaxBaseFeeRate a single-input fee is a few hundred thousand sats at most,
// so this change always splits into maxChangeOutputs outputs, each far above dust, in both
// buildSpendTransaction and estimateFee.
const feeBoundChange = 10 * splitThreshold

// singleInputFeeCeiling is an UPPER bound of the true miner fee (btcFee) of every
// single-input build of this withdrawal at the current rate. It runs buildSpendTransaction
// itself (which writes no state) on a synthetic spend: one input carrying the largest
// witness script a vault coin can have (a 32-byte deposit tag; change coins carry none, and
// every generation uses 33-byte keys and the network CSV), the real destination and change
// address, and feeBoundChange of change, so the builder adds maxChangeOutputs change
// outputs and prices them exactly as it prices a real build. The ceiling is that btcFee plus
// dustThreshold. Against buildSpendTransaction, a real single-input build has one input
// whose witness is at most the tagged one, the same destination, and k change outputs:
//   - with change (1 <= k <= maxChangeOutputs) its btcFee is the size fee the builder priced
//     for k outputs, which grows with k and with the witness, so it is at most the
//     synthetic btcFee S;
//   - without change it burns the remainder: either availableChange = totalChange - fee_0 <=
//     dustThreshold, or the first change output would have been dust (totalChange - fee_1
//     <= dustThreshold), so btcFee = totalChange <= fee_1 + dustThreshold <= S +
//     dustThreshold; a negative availableChange gives btcFee < fee_0 <= S.
//
// So every single-input build's btcFee <= S + dustThreshold. Only a build needing several
// inputs can cost more.
func (cs *ContractState) singleInputFeeCeiling(sc *unmapScripts, sendAmount int64) (int64, error) {
	value, err := safeAdd64(sendAmount, feeBoundChange)
	if err != nil {
		return 0, ce.WrapContractError(ce.ErrArithmetic, err, "error computing fee bound")
	}
	gen := uint32(0)
	if i := firstVaultWithStatus(cs.Vaults, VaultStatusActive); i >= 0 {
		gen = cs.Vaults[i].Generation
	} else if len(cs.Vaults) > 0 {
		gen = cs.Vaults[0].Generation
	}
	synthetic := &Utxo{
		TxId:       strings.Repeat("00", 32),
		Amount:     value,
		Tag:        make([]byte, 32),
		Generation: gen,
	}
	tx, _, btcFee, err := cs.buildSpendTransaction([]*Utxo{synthetic}, value, sc.to, sc.changeAddress, sendAmount)
	if err != nil {
		return 0, err
	}
	if len(tx.TxOut) != 1+maxChangeOutputs {
		return 0, ce.NewContractError(ce.ErrTransaction, "fee bound did not split into the largest change")
	}
	return safeAdd64(btcFee, dustThreshold)
}

// checkUnmapPayable refuses a queued withdrawal that a single-input build might not be able
// to pay at the current fee rate, so that every entry that reaches coin selection and is
// built from one input is guaranteed to be paid:
//   - max_fee below vscFee + the ceiling (with or without deduct_fee);
//   - without deduct_fee, available below amount + vscFee + the ceiling;
//   - with deduct_fee, an amount that planUnmap's own dust rule ("amount too small to cover
//     fees": sel - estimateFee <= dustThreshold) refuses at the largest single-input
//     estimate, estimateFee(1, sel, sel + feeBoundChange). estimateFee grows with the change
//     it is given (more change outputs, up to maxChangeOutputs), so no single-input build is
//     refused by that rule once this one passes;
//   - with deduct_fee, available below amount + (ceiling - minUnmapFee). A deduct build's
//     finalAmt is vscFee + (sel - estimate) + btcFee = amount + btcFee - estimate, its btcFee
//     is at most the ceiling and its estimate at least minUnmapFee, so finalAmt is at most
//     amount + ceiling - minUnmapFee.
//
// It returns the fee room to escrow above HandleUnmap's preliminary requirement: the
// ceiling without deduct_fee, ceiling - minUnmapFee with it. Used at request (available =
// balance) and at drain (available = escrow + balance), so the two judge alike.
//
// Deliberate over-refusal, queue path only, while coins are held: a request the direct path
// would pay (its real fee being lower than the bound) is refused if its balance, its max_fee
// or its deduct_fee amount does not cover the bound. The messages say so and give the
// number. The direct path is unchanged.
func (cs *ContractState) checkUnmapPayable(from string, sc *unmapScripts, amount, vscFee int64, deductFee bool, maxFee *int64, available int64) (int64, error) {
	ceiling, err := cs.singleInputFeeCeiling(sc, amount)
	if err != nil {
		return 0, err
	}
	totalCeiling, err := safeAdd64(vscFee, ceiling)
	if err != nil {
		return 0, ce.WrapContractError(ce.ErrArithmetic, err, "error computing total fee")
	}
	if maxFee != nil && totalCeiling > *maxFee {
		return 0, ce.NewContractError(
			ce.ErrTransaction,
			"total fee up to "+strconv.FormatInt(totalCeiling, 10)+
				" exceeds max_fee "+strconv.FormatInt(*maxFee, 10)+
				": vault coins are held right now, so this withdrawal would be queued, and a queued"+
				" withdrawal's max_fee must cover the largest fee it can cost at the current fee rate;"+
				" set max_fee to at least "+strconv.FormatInt(totalCeiling, 10),
		)
	}
	room, roomNote := ceiling, totalCeiling
	if deductFee {
		sel, err := unmapSelectionAmount(amount, vscFee, true)
		if err != nil {
			return 0, err
		}
		change, err := safeAdd64(sel, feeBoundChange)
		if err != nil {
			return 0, ce.WrapContractError(ce.ErrArithmetic, err, "error computing fee bound")
		}
		estMax, err := cs.estimateFee(1, sel, change)
		if err != nil {
			return 0, err
		}
		if sel-estMax <= dustThreshold {
			least := vscFee + estMax + dustThreshold + 1
			return 0, ce.NewContractError(ce.ErrBalance,
				"amount too small to cover fees: vault coins are held right now, so this withdrawal would"+
					" be queued, and a queued deduct_fee withdrawal must exceed the largest fee it can cost"+
					" by more than the dust limit; withdraw at least "+strconv.FormatInt(least, 10))
		}
		floor, err := cs.minUnmapFee(sc)
		if err != nil {
			return 0, err
		}
		room, err = safeSubtract64(ceiling, floor)
		if err != nil {
			return 0, ce.WrapContractError(ce.ErrArithmetic, err, "error computing fee bound")
		}
		roomNote = room
	}
	need, err := safeAdd64(amount, roomNote)
	if err != nil {
		return 0, ce.WrapContractError(ce.ErrArithmetic, err, "error computing final amount")
	}
	if available < need {
		advice := "; keep that much above the amount, or use deduct_fee"
		if deductFee {
			advice = ", deduct_fee included; keep that much above the amount"
		}
		return 0, ce.NewContractError(ce.ErrBalance,
			"account ["+from+"] balance "+strconv.FormatInt(available, 10)+
				" insufficient needs "+strconv.FormatInt(need, 10)+
				": vault coins are held right now, so this withdrawal would be queued, and a queued"+
				" withdrawal must leave room for the largest fee it can cost ("+strconv.FormatInt(roomNote, 10)+
				" sats at the current fee rate"+advice+")")
	}
	return room, nil
}

// queuedUnmapUnpayable is checkUnmapPayable for a queued withdrawal at drain time, at the
// fee rate of that moment: no coin selection, no build. reason is empty when it may still be
// payable (or cannot be judged cheaply, which planUnmap then decides).
func (cs *ContractState) queuedUnmapUnpayable(q *QueuedUnmap) string {
	sc, err := cs.checkUnmapDestination(q.To)
	if err != nil {
		return err.Error()
	}
	available, err := safeAdd64(q.Escrow, getAccBal(q.From))
	if err != nil {
		return ""
	}
	if _, err := cs.checkUnmapPayable(q.From, sc, q.Amount, q.VscFee, q.DeductFee, q.MaxFee, available); err != nil {
		if cerr, ok := err.(*ce.ContractError); ok && cerr.Symbol == ce.ErrArithmetic {
			return ""
		}
		return err.Error()
	}
	return ""
}

// enqueueUnmap accepts a withdrawal whose coins are held for now. prelimRequired is what
// HandleUnmap's preliminary check already proved the caller holds. The per-block rate limit
// (BTC-C3) is charged here, at the debit, as HandleUnmap charges it at its own.
//
// It first refuses what a single-input build might not be able to pay at the current fee
// rate (checkUnmapPayable), then escrows the fee room that check returns on top of the
// preliminary requirement, so a single-input build always fits and only returns the unused
// part. Only a build that needs several inputs can cost more; its remainder is charged at
// build or, if the balance cannot cover it, refunded (the multi-input residual).
func (cs *ContractState) enqueueUnmap(env sdk.Env, from string, instructions *TransferParams, amount, vscFee, prelimRequired int64) error {
	head, tail, ok := loadUnmapQueueBounds()
	if !ok {
		return errQueueStateUnreadable
	}
	// One live queued withdrawal per account, so one account cannot fill every slot during a
	// rotation (and cancel before the settle, for free) and refuse everyone else. A record
	// that does not decode is skipped here; the drain reports it.
	for seq := head; seq < tail; seq++ {
		raw := sdk.StateGetObject(queuedUnmapKey(seq))
		if raw == nil || *raw == "" {
			continue
		}
		if q, err := UnmarshalQueuedUnmap([]byte(*raw)); err == nil && q.From == from {
			return ce.NewContractError(ce.ErrTransaction,
				"account ["+from+"] already has a queued withdrawal (seq "+strconv.FormatUint(uint64(seq), 10)+
					"); wait for it to be paid or cancel it with cancelUnmap")
		}
	}
	if tail-head >= constants.MaxQueuedUnmaps {
		return ce.NewContractError(ce.ErrTransaction,
			"vault coins are held by a rotation or by withdrawals in flight, and the withdrawal queue is full ("+
				strconv.FormatUint(uint64(tail-head), 10)+" of "+strconv.Itoa(constants.MaxQueuedUnmaps)+
				"); retry once queued withdrawals are paid")
	}
	if tail == math.MaxUint32 {
		return ce.NewContractError(ce.ErrTransaction, "withdrawal queue sequence exhausted")
	}
	sc, err := cs.checkUnmapDestination(instructions.To)
	if err != nil {
		return err
	}
	escrowFee, err := cs.checkUnmapPayable(from, sc, amount, vscFee,
		instructions.DeductFee, instructions.MaxFee, getAccBal(from))
	if err != nil {
		return err
	}
	escrow, err := safeAdd64(prelimRequired, escrowFee)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error computing final amount")
	}

	// from == caller (isOwnDirectWithdrawal), so this is a plain balance debit.
	if err := checkAndDeductBalance(env, from, escrow); err != nil {
		return err
	}
	if err := checkAndUpdateUnmapRateLimit(env.BlockHeight, escrow); err != nil {
		return err
	}
	newActive, err := safeSubtract64(cs.Supply.ActiveSupply, escrow)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error decrementing active supply")
	}
	newUser, err := safeSubtract64(cs.Supply.UserSupply, escrow)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error decrementing user supply")
	}

	rec := &QueuedUnmap{
		From:          from,
		To:            instructions.To,
		Amount:        amount,
		Escrow:        escrow,
		VscFee:        vscFee,
		DeductFee:     instructions.DeductFee,
		MaxFee:        instructions.MaxFee,
		RequestHeight: currentLastHeight(),
	}
	sdk.StateSetObject(queuedUnmapKey(tail), string(MarshalQueuedUnmap(rec)))
	saveUnmapQueueBounds(head, tail+1)
	cs.Supply.ActiveSupply = newActive
	cs.Supply.UserSupply = newUser

	sdk.Log("unmapq|seq=" + strconv.FormatUint(uint64(tail), 10) + "|f=" + from + "|t=" + instructions.To +
		"|a=" + strconv.FormatInt(amount, 10) + "|e=" + strconv.FormatInt(escrow, 10) +
		"|ahead=" + strconv.FormatUint(uint64(tail-head), 10))
	return nil
}

const (
	queueWait   = iota // cannot be built yet; it stays at the head and the drain stops
	queuePaid          // built, signed, recorded as an in-flight unmap
	queueRefund        // can never be paid as asked; refund the escrow
)

// payQueuedUnmap tries to build one queued withdrawal. It writes state only when it
// returns queuePaid.
func (cs *ContractState) payQueuedUnmap(q *QueuedUnmap) (int, string) {
	// VR2-03: the drain is a permissionless producer of pending spends too.
	if len(cs.TxSpendsList) >= constants.MaxConcurrentPendingSpends {
		return queueWait, "too many pending spends in flight"
	}
	sel, err := unmapSelectionAmount(q.Amount, q.VscFee, q.DeductFee)
	if err != nil {
		return queueRefund, err.Error()
	}
	plan, held, err := cs.planUnmap(q.To, q.Amount, q.VscFee, sel, q.DeductFee, q.MaxFee)
	if err != nil {
		if held {
			return queueWait, err.Error()
		}
		return queueRefund, err.Error()
	}

	// Settle the escrow against what the withdrawal really costs. diff > 0 returns the
	// unused part to the user; diff < 0 charges the rest of the miner fee from the user's
	// current balance, as HandleUnmap's own debit of finalAmt would. All arithmetic is done
	// here, before commitUnmap writes anything.
	diff, err := safeSubtract64(q.Escrow, plan.finalAmt)
	if err != nil {
		return queueRefund, err.Error()
	}
	newBal, err := safeAdd64(getAccBal(q.From), diff)
	if err != nil || newBal < 0 {
		return queueRefund, "balance cannot cover the miner fee"
	}
	newActive, err := safeAdd64(cs.Supply.ActiveSupply, diff)
	if err != nil || newActive < 0 {
		return queueRefund, "active supply arithmetic"
	}
	newUser, err := safeAdd64(cs.Supply.UserSupply, diff)
	if err != nil || newUser < 0 {
		return queueRefund, "user supply arithmetic"
	}
	newFee, err := safeAdd64(cs.Supply.FeeSupply, q.VscFee)
	if err != nil {
		return queueRefund, "fee supply arithmetic"
	}

	// A signing refusal (the active key missing or not active) is not the user's fault and
	// fails every withdrawal alike: keep it queued. signSpendTransaction checks every input
	// before the first sign request, and all inputs of a withdrawal share the active key,
	// so a refusal leaves no sign request behind.
	txId, err := cs.commitUnmap(plan, q.From, q.To, q.VscFee)
	if err != nil {
		return queueWait, err.Error()
	}
	setAccBal(q.From, newBal)
	cs.Supply.ActiveSupply = newActive
	cs.Supply.UserSupply = newUser
	cs.Supply.FeeSupply = newFee
	return queuePaid, txId
}

// refundQueuedUnmap returns the whole escrow. It changes nothing when the arithmetic
// fails (false), so the entry can stay queued rather than be lost.
func (cs *ContractState) refundQueuedUnmap(q *QueuedUnmap) bool {
	newBal, err := safeAdd64(getAccBal(q.From), q.Escrow)
	if err != nil {
		return false
	}
	newActive, err := safeAdd64(cs.Supply.ActiveSupply, q.Escrow)
	if err != nil {
		return false
	}
	newUser, err := safeAdd64(cs.Supply.UserSupply, q.Escrow)
	if err != nil {
		return false
	}
	setAccBal(q.From, newBal)
	cs.Supply.ActiveSupply = newActive
	cs.Supply.UserSupply = newUser
	return true
}

// drainUnmapQueue builds or refunds queued withdrawals, oldest first, and steps over
// cancelled holes. It never returns an error and never aborts its caller: a withdrawal that
// cannot be built yet stays at the head (FIFO, no partial fills) and the drain stops. Paused
// contract: nothing is built (an unmap is pause-gated, and so is this). An entry that cannot
// be paid at the current fee rate whatever coins are free (queuedUnmapUnpayable) is refunded
// at once without coin selection.
//
// maxPlans bounds the cost: every entry that reaches planUnmap counts, built or refunded
// there, so coin selection runs at most maxPlans times per drain. A cheap refund (refused
// before planning) does not count and stays nearly free. A griefer can still make up to
// maxPlans entries per drain refund AFTER planning (multi-input entries that pass the cheap
// check but whose fee a tight balance cannot cover at build); that is bounded, not
// stranding. When a drain ends, every entry still queued is behind maxPlans builds now in
// flight (whose settles drain again), or is a cheap-refusable entry at a rate that has
// since changed, or is waiting for coins. Bounded: the queue never holds more than
// MaxQueuedUnmaps entries and holes, and the loop looks at no more than that, so one drain
// always reaches the tail.
func (cs *ContractState) drainUnmapQueue(maxPlans int) {
	head, tail, ok := loadUnmapQueueBounds()
	if !ok {
		sdk.Log("unmapq|stuck|why=queue bounds unreadable")
		return
	}
	if head == tail {
		return
	}
	if p := sdk.StateGetObject(constants.PausedKey); p != nil && *p != "" {
		return
	}
	start := head
	plans := 0
	// kept is set once the drain steps past a record it must leave in place (it does not
	// decode, or its refund cannot be computed): such a record may hold someone's escrow, so
	// it is never deleted, and the head never moves past it; but it no longer blocks the
	// entries behind it, which the drain still pays or refunds. It stays logged until a
	// contract fix reads it.
	kept := false
	for cur, steps := head, 0; cur < tail && steps < constants.MaxQueuedUnmaps && plans < maxPlans; cur, steps = cur+1, steps+1 {
		key := queuedUnmapKey(cur)
		raw := sdk.StateGetObject(key)
		if raw == nil || *raw == "" {
			if !kept {
				head = cur + 1 // cancelled or already settled
			}
			continue
		}
		seq := strconv.FormatUint(uint64(cur), 10)
		q, err := UnmarshalQueuedUnmap([]byte(*raw))
		if err != nil {
			sdk.Log("unmapq|stuck|seq=" + seq + "|why=" + err.Error())
			kept = true
			continue
		}
		// A cheap refund (checkUnmapPayable refuses it before any coin selection) stays free
		// and does not count against maxPlans; only an entry that reaches planUnmap does,
		// whether it is built or refunded there for a shortfall the balance cannot cover.
		outcome, note := queueRefund, cs.queuedUnmapUnpayable(q)
		if note == "" {
			plans++
			outcome, note = cs.payQueuedUnmap(q)
		}
		if outcome == queueWait {
			break
		}
		if outcome == queueRefund {
			if !cs.refundQueuedUnmap(q) {
				sdk.Log("unmapq|stuck|seq=" + seq + "|why=refund arithmetic")
				kept = true
				continue
			}
			sdk.Log("unmapq|refund|seq=" + seq + "|f=" + q.From + "|e=" + strconv.FormatInt(q.Escrow, 10) + "|why=" + note)
		} else {
			sdk.Log("unmapq|paid|seq=" + seq + "|id=" + note)
		}
		sdk.StateDeleteObject(key)
		if !kept {
			head = cur + 1
		}
	}
	if head != start {
		saveUnmapQueueBounds(head, tail)
	}
}

// HandleDrainUnmapQueue is the permissionless drainUnmapQueue entrypoint. confirmSpend
// already drains after every settle; this covers the cases where coins are free but no
// settle is coming (the contract was paused when the last settle ran, or new deposits
// arrived while the head waited on a coin held by a spend that is stuck).
func (cs *ContractState) HandleDrainUnmapQueue() string {
	head, tail, _ := loadUnmapQueueBounds()
	cs.drainUnmapQueue(constants.MaxQueuePlansPerDrain)
	newHead, newTail, _ := loadUnmapQueueBounds()
	return "queue: " + strconv.FormatUint(uint64(tail-head), 10) + " before, " +
		strconv.FormatUint(uint64(newTail-newHead), 10) + " after"
}

// HandleCancelQueuedUnmap refunds a queued withdrawal that has not been built yet. The
// account that queued it may cancel it, and so may the contract owner (an escape hatch for
// a withdrawal that can never be paid, for example during a rotation that cannot finish).
// The escrow goes back to the account that paid it either way. Active authority required.
func (cs *ContractState) HandleCancelQueuedUnmap(seqStr string, owner string) error {
	env := sdk.GetEnv()
	if err := checkAuth(env); err != nil {
		return err
	}
	seq64, err := strconv.ParseUint(strings.TrimSpace(seqStr), 10, 32)
	if err != nil {
		return ce.NewContractError(ce.ErrInput, "expected the queued withdrawal's sequence number")
	}
	seq := uint32(seq64)
	// Only a live slot. The drain moves the head past an entry in the same call that pays or
	// refunds it, so anything below the head has been settled one way or the other; a record
	// left there by a bug must never be refundable a second time.
	head, tail, ok := loadUnmapQueueBounds()
	if !ok {
		return errQueueStateUnreadable
	}
	key := queuedUnmapKey(seq)
	raw := sdk.StateGetObject(key)
	if seq < head || seq >= tail || raw == nil || *raw == "" {
		return ce.NewContractError(ce.ErrInput, "no queued withdrawal "+seqStr+" (already paid, refunded or cancelled)")
	}
	q, err := UnmarshalQueuedUnmap([]byte(*raw))
	if err != nil {
		return ce.NewContractError(ce.ErrStateAccess, "error decoding queued withdrawal: "+err.Error())
	}
	caller := env.Caller.String()
	if caller != q.From && caller != owner {
		return ce.NewContractError(ce.ErrNoPermission, "only the account that queued this withdrawal, or the owner, may cancel it")
	}
	if !cs.refundQueuedUnmap(q) {
		return ce.NewContractError(ce.ErrArithmetic, "error refunding queued withdrawal")
	}
	sdk.StateDeleteObject(key)

	// Step the head over this and any following holes, so a queue of only cancelled
	// entries reads as empty and does not hold new withdrawals behind it.
	if seq == head {
		for head < tail {
			if r := sdk.StateGetObject(queuedUnmapKey(head)); r != nil && *r != "" {
				break
			}
			head++
		}
		saveUnmapQueueBounds(head, tail)
	}
	sdk.Log("unmapq|cancel|seq=" + strconv.FormatUint(uint64(seq), 10) + "|f=" + q.From +
		"|e=" + strconv.FormatInt(q.Escrow, 10) + "|by=" + caller)
	return nil
}
