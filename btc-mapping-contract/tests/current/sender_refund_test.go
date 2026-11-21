package current_test

// SENDER-REFUND-1 (owner 11-21): a deposit swap that does not complete goes back
// to the address that SENT it (THORChain bifrost getSender: the address of the
// output the deposit's first input spends), nobody types a refund address, and
// it never lands in a Magi balance: refunds are held and sent home on Bitcoin.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"
	"btc-mapping-contract/tests/mocks"
)

// srTx is a transaction spending in (nil: a coinbase-like input) and paying
// amount to each of addrs.
func srTx(t *testing.T, in *wire.OutPoint, amount int64, addrs ...string) *wire.MsgTx {
	t.Helper()
	tx := wire.NewMsgTx(wire.TxVersion)
	op := wire.OutPoint{Index: 0xffffffff}
	if in != nil {
		op = *in
	}
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op, SignatureScript: []byte{0x00}, Sequence: wire.MaxTxInSequenceNum})
	for _, a := range addrs {
		addr, err := btcutil.DecodeAddress(a, regtestParams())
		require.NoError(t, err)
		script, err := txscript.PayToAddrScript(addr)
		require.NoError(t, err)
		tx.AddTxOut(&wire.TxOut{Value: amount, PkScript: script})
	}
	return tx
}

// srBlock stores a one-transaction block holding tx at height and returns its
// proof request.
func (e *rfEnv) srBlock(tx *wire.MsgTx, height uint32) mapping.VerificationRequest {
	header := buildRegtestHeader(chainhash.Hash{}, tx.TxHash(), time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	e.ct.StateSet(rfContract, constants.BlockPrefix+strconv.FormatUint(uint64(height), 10), decodeHex(e.t, serializeHeader(e.t, header)))
	return mapping.VerificationRequest{BlockHeight: height, RawTxHex: serializeTx(e.t, tx), TxIndex: 0}
}

func (e *rfEnv) srDepositAddr(instruction string) string {
	addr, _, err := mapping.DepositAddress(TestPrimaryPubKeyHex, TestBackupPubKeyHex, instruction, regtestParams())
	require.NoError(e.t, err)
	return addr
}

// srSend: the sender's wallet funds prev (to sender) at height 90, then deposits
// from it to the instruction's address at 100. It returns the deposit and the
// sender proof.
func (e *rfEnv) srSend(sender, instruction string) (*wire.MsgTx, mapping.VerificationRequest) {
	// Another user's coin in the vault: a sendHome with the fee taken from the
	// amount needs more than a lone 10,000-sat coin (as in SendHomeReturnsBitcoinRefund).
	if r, _ := e.mapDepositAt("deposit_to=hive:someone-else", 99); !r.Success {
		e.t.Fatalf("seed coin: %s %s", r.Err, r.ErrMsg)
	}
	prev := srTx(e.t, nil, rfAmount+5_000, sender)
	proof := e.srBlock(prev, 90)
	dep := srTx(e.t, &wire.OutPoint{Hash: prev.TxHash(), Index: 0}, rfAmount, e.srDepositAddr(instruction))
	return dep, proof
}

func (e *rfEnv) srMap(dep *wire.MsgTx, instructions ...string) {
	req := e.srBlock(dep, 100)
	payload, err := tinyjson.Marshal(mapping.MapParams{TxData: &req, Instructions: instructions})
	require.NoError(e.t, err)
	r := e.call(rfOwner, "map", string(payload))
	require.True(e.t, r.Success, "map: %s %s", r.Err, r.ErrMsg)
}

func (e *rfEnv) srProve(dep *wire.MsgTx, sender mapping.VerificationRequest) (bool, string) {
	var buf bytes.Buffer
	require.NoError(e.t, dep.SerializeNoWitness(&buf))
	payload, err := tinyjson.Marshal(mapping.ProveSenderParams{DepositTxHex: hex.EncodeToString(buf.Bytes()), Sender: &sender})
	require.NoError(e.t, err)
	r := e.call(rfOwner, "proveSender", string(payload))
	return r.Success, r.Err + " " + r.ErrMsg + " " + r.Ret
}

// srHeldFor asserts amount is held for addr (records + hold balance) and that no
// Magi account of it, the recipient's or the contract's holds anything.
func (e *rfEnv) srHeldFor(addr string, amount int64) {
	e.t.Helper()
	assert.Equal(e.t, strconv.FormatInt(amount, 10), e.state(constants.RefundHeldPrefix+addr), "held record")
	assert.Equal(e.t, strconv.FormatInt(amount, 10), e.state(constants.RefundablePrefix+addr), "refundable record")
	assert.Equal(e.t, amount, e.bal(constants.BtcRefundHoldAccount), "refund hold balance")
	assert.Zero(e.t, e.bal(rfDID(addr)), "never on the address's Magi account")
	assert.Zero(e.t, e.bal(rfSender), "never on a hive: Magi account")
	assert.Zero(e.t, e.bal(rfRecipient), "swap_to must never receive a refund")
	assert.Zero(e.t, e.bal("contract:"+rfContract), "the contract must not keep the deposit")
	s := e.supply()
	assert.Equal(e.t, s.ActiveSupply, s.UserSupply, "every mapped sat is user supply")
}

func ethSwapInstr(refundTo string) string {
	i := "swap_to=did:pkh:eip155:1:0x00000000000000000000000000000000000000e2&swap_asset_out=eth&destination_chain=ETH&min_amount_out=1&payout_gas_limit=25200"
	if refundTo != "" {
		i += "&refund_to=" + refundTo
	}
	return i
}

// Proven before map: the swap paid out on Ethereum is attempted (here the mock
// router's zero output is a failed swap) and the BTC goes back to the SENDING
// address, held and sent home; refund_to (a hive: login) is not credited.
func TestSenderRefund_ProvenBeforeMapRefundsTheSender(t *testing.T) {
	e := newRfEnv(t, mocks.MockRouterWasm)
	sender := refundBtcAddr(t)
	instr := ethSwapInstr(rfSender)
	dep, proof := e.srSend(sender, instr)
	ok, msg := e.srProve(dep, proof)
	require.True(t, ok, msg)
	assert.Equal(t, sender, e.state(constants.SenderPrefix+dep.TxID()))
	e.srMap(dep, instr)
	assert.Equal(t, "", e.state(constants.SenderPrefix+dep.TxID()), "map consumes the proven sender")
	e.srHeldFor(sender, rfAmount)

	// sendHome pays it from the hold to the sender on Bitcoin.
	r := e.call(rfSender, "sendHome", sender)
	require.True(t, r.Success, "%s %s", r.Err, r.ErrMsg)
	assert.Less(t, e.bal(constants.BtcRefundHoldAccount), rfAmount, "sent from the hold")
	assert.Zero(t, e.bal(rfDID(sender)))
}

// A map raced in without the proof: the Ethereum payout is not attempted (no
// sending address to return it to), the BTC is held for the deposit, and a later
// proveSender sends it to the sender. A front-run map delays, never redirects.
func TestSenderRefund_MapWithoutProofHoldsThenProveSenderSendsHome(t *testing.T) {
	e := newRfEnv(t, mocks.MockRouterWasm)
	sender := refundBtcAddr(t)
	instr := ethSwapInstr("")
	dep, proof := e.srSend(sender, instr)
	e.srMap(dep, instr)
	op := dep.TxID() + ":0"
	assert.Equal(t, rfAmount, e.bal(constants.RefundHoldAccount))
	assert.Equal(t, strconv.FormatInt(rfAmount, 10), e.state(constants.SenderPendingPrefix+op))

	ok, msg := e.srProve(dep, proof)
	require.True(t, ok, msg)
	assert.Zero(t, e.bal(constants.RefundHoldAccount), "left the manual hold")
	assert.Equal(t, "", e.state(constants.RefundHoldPrefix+op))
	assert.Equal(t, "", e.state(constants.SenderPendingPrefix+op))
	assert.Equal(t, "", e.state(constants.SenderPrefix+dep.TxID()), "nothing left for a map: it was mapped")
	e.srHeldFor(sender, rfAmount)

	ok, _ = e.srProve(dep, proof)
	require.True(t, ok)
	assert.Equal(t, rfAmount, e.bal(constants.BtcRefundHoldAccount), "a second proof moves nothing twice")
}

// A hive: refund_to (Altera's automatic one for a Hive login) is no longer
// credited to that account's Magi balance: held until the sender is proven.
func TestSenderRefund_HiveRefundToIsHeldNotCredited(t *testing.T) {
	e := newRfEnv(t, mocks.MockRouterWasm)
	sender := refundBtcAddr(t)
	instr := swapInstr(rfSender)
	dep, proof := e.srSend(sender, instr)
	e.srMap(dep, instr)
	assert.Zero(t, e.bal(rfSender), "not credited to the hive account")
	assert.Equal(t, rfAmount, e.bal(constants.RefundHoldAccount))
	ok, msg := e.srProve(dep, proof)
	require.True(t, ok, msg)
	e.srHeldFor(sender, rfAmount)
}

// A Bitcoin refund_to (a Bitcoin wallet login) without a sender proof: held for
// that address and sent home from the hold, never on its Magi account.
func TestSenderRefund_BitcoinRefundToIsHeldForIt(t *testing.T) {
	e := newRfEnv(t, mocks.MockRouterWasm)
	login := refundBtcAddrOther(t)
	instr := ethSwapInstr(login)
	dep, _ := e.srSend(refundBtcAddr(t), instr)
	e.srMap(dep, instr)
	e.srHeldFor(login, rfAmount)
	r := e.call(rfSender, "sendHome", login)
	require.True(t, r.Success, "%s %s", r.Err, r.ErrMsg)
	assert.Zero(t, e.bal(rfDID(login)))
}

// A proven sender takes precedence over the instruction's refund_to.
func TestSenderRefund_ProvenSenderWinsOverRefundTo(t *testing.T) {
	e := newRfEnv(t, mocks.MockRouterWasm)
	sender, login := refundBtcAddr(t), refundBtcAddrOther(t)
	instr := ethSwapInstr(login)
	dep, proof := e.srSend(sender, instr)
	ok, msg := e.srProve(dep, proof)
	require.True(t, ok, msg)
	e.srMap(dep, instr)
	e.srHeldFor(sender, rfAmount)
	assert.Equal(t, "", e.state(constants.RefundablePrefix+login))
}

// A bad instruction's deposit is held, and a sender proof sends it home too.
func TestSenderRefund_BadInstructionHoldGoesToTheProvenSender(t *testing.T) {
	e := newRfEnv(t, mocks.MockRouterWasm)
	sender := refundBtcAddr(t)
	instr := "swap_to=contract:vsc1BdrQ6EtbQ64rq2PkPd21x4MaLnVRcJj85d&swap_asset_out=hbd"
	dep, proof := e.srSend(sender, instr)
	e.srMap(dep, instr)
	assert.Equal(t, rfAmount, e.bal(constants.RefundHoldAccount))
	ok, msg := e.srProve(dep, proof)
	require.True(t, ok, msg)
	e.srHeldFor(sender, rfAmount)
}

// The owner's manual release of a hold clears its sender mark: a later proof
// cannot move it a second time.
func TestSenderRefund_ReleasedHoldIsNotMovedAgain(t *testing.T) {
	e := newRfEnv(t, mocks.MockRouterWasm)
	sender := refundBtcAddr(t)
	instr := swapInstr("")
	dep, proof := e.srSend(sender, instr)
	e.srMap(dep, instr)
	op := dep.TxID() + ":0"
	r := e.call(rfOwner, "releaseHold", "o="+op+"&to="+rfSender)
	require.True(t, r.Success, "%s %s", r.Err, r.ErrMsg)
	assert.Equal(t, "", e.state(constants.SenderPendingPrefix+op))
	ok, msg := e.srProve(dep, proof)
	require.True(t, ok, msg)
	assert.Zero(t, e.bal(constants.BtcRefundHoldAccount), "nothing moved twice")
	assert.Equal(t, rfAmount, e.bal(rfSender))
}

// Proofs that do not prove the sender are refused and change nothing.
func TestSenderRefund_BadProofsAreRefused(t *testing.T) {
	sender := refundBtcAddr(t)
	instr := swapInstr("")
	t.Run("not the transaction the first input spends", func(t *testing.T) {
		e := newRfEnv(t, mocks.MockRouterWasm)
		dep, _ := e.srSend(sender, instr)
		other := srTx(t, nil, 1234, sender)
		ok, _ := e.srProve(dep, e.srBlock(other, 91))
		assert.False(t, ok)
		assert.Equal(t, "", e.state(constants.SenderPrefix+dep.TxID()))
	})
	t.Run("output index past the transaction", func(t *testing.T) {
		e := newRfEnv(t, mocks.MockRouterWasm)
		prev := srTx(t, nil, rfAmount, sender)
		proof := e.srBlock(prev, 90)
		dep := srTx(t, &wire.OutPoint{Hash: prev.TxHash(), Index: 3}, rfAmount, e.srDepositAddr(instr))
		ok, _ := e.srProve(dep, proof)
		assert.False(t, ok)
	})
	t.Run("header not stored", func(t *testing.T) {
		e := newRfEnv(t, mocks.MockRouterWasm)
		dep, proof := e.srSend(sender, instr)
		e.ct.StateSet(rfContract, constants.BlockPrefix+"90", "")
		ok, _ := e.srProve(dep, proof)
		assert.False(t, ok)
	})
	t.Run("the spent output is the vault's", func(t *testing.T) {
		e := newRfEnv(t, mocks.MockRouterWasm)
		// A deposit the vault indexed at 90, then a vault transaction spending it
		// that pays a deposit address: no user sender.
		vaultOut := srTx(t, nil, rfAmount, e.srDepositAddr("deposit_to="+rfSender))
		req := e.srBlock(vaultOut, 90)
		payload, err := tinyjson.Marshal(mapping.MapParams{TxData: &req, Instructions: []string{"deposit_to=" + rfSender}})
		require.NoError(t, err)
		require.True(t, e.call(rfOwner, "map", string(payload)).Success)
		dep := srTx(t, &wire.OutPoint{Hash: vaultOut.TxHash(), Index: 0}, rfAmount, e.srDepositAddr(instr))
		ok, msg := e.srProve(dep, req)
		assert.False(t, ok)
		assert.Contains(t, msg, "belongs to the vault")
	})
	t.Run("both encodings of the deposit", func(t *testing.T) {
		e := newRfEnv(t, mocks.MockRouterWasm)
		dep, proof := e.srSend(sender, instr)
		var buf bytes.Buffer
		require.NoError(t, dep.SerializeNoWitness(&buf))
		payload, err := tinyjson.Marshal(mapping.ProveSenderParams{
			DepositTxHex: hex.EncodeToString(buf.Bytes()), DepositTxB64: base64.StdEncoding.EncodeToString(buf.Bytes()), Sender: &proof})
		require.NoError(t, err)
		assert.False(t, e.call(rfOwner, "proveSender", string(payload)).Success)
	})
}

// One deposit transaction paying two swap addresses: both held parts go home.
func TestSenderRefund_TwoHeldOutputsBothGoHome(t *testing.T) {
	e := newRfEnv(t, mocks.MockRouterWasm)
	sender := refundBtcAddr(t)
	a, b := swapInstr(""), swapInstr("")+"&min_amount_out=7"
	prev := srTx(t, nil, 3*rfAmount, sender)
	proof := e.srBlock(prev, 90)
	dep := srTx(t, &wire.OutPoint{Hash: prev.TxHash(), Index: 0}, rfAmount, e.srDepositAddr(a), e.srDepositAddr(b))
	req := e.srBlock(dep, 100)
	payload, err := tinyjson.Marshal(mapping.MapParams{TxData: &req, Instructions: []string{a, b}})
	require.NoError(t, err)
	require.True(t, e.call(rfOwner, "map", string(payload)).Success)
	assert.Equal(t, 2*rfAmount, e.bal(constants.RefundHoldAccount))
	ok, msg := e.srProve(dep, proof)
	require.True(t, ok, msg)
	assert.Zero(t, e.bal(constants.RefundHoldAccount))
	assert.Equal(t, strconv.FormatInt(2*rfAmount, 10), e.state(constants.RefundHeldPrefix+sender))
	assert.Equal(t, 2*rfAmount, e.bal(constants.BtcRefundHoldAccount))
}

// A refund from before SENDER-REFUND-1 (on the address's own Magi account) is
// still sent home.
func TestSenderRefund_LegacyRefundOnTheAccountStillGoesHome(t *testing.T) {
	e := newRfEnv(t, mocks.MockRouterWasm)
	addr := refundBtcAddr(t)
	instr := swapInstr("")
	dep, _ := e.srSend(addr, instr) // any mapped deposit gives the vault coins to send from
	e.srMap(dep, instr)
	e.ct.StateSet(rfContract, constants.RefundablePrefix+addr, strconv.FormatInt(rfAmount, 10))
	r := e.call(rfOwner, "releaseHold", "o="+dep.TxID()+":0&to="+rfDID(addr)) // stands for a legacy credit
	require.True(t, r.Success, "%s %s", r.Err, r.ErrMsg)
	require.Equal(t, rfAmount, e.bal(rfDID(addr)))
	r = e.call(rfSender, "sendHome", addr)
	require.True(t, r.Success, "%s %s", r.Err, r.ErrMsg)
	assert.Less(t, e.bal(rfDID(addr)), rfAmount, "sent from the account")
}

// A Taproot (or P2WSH) sender has no Magi identity on the node, so its swap
// paid out on Ethereum could never come back to it: not attempted, the BTC goes
// back to the sender now (held, sent home).
func TestSenderRefund_TaprootSenderIsNotPaidOutOnEthereum(t *testing.T) {
	e := newRfEnv(t, mocks.MockRouterWasm)
	key := bytes.Repeat([]byte{0x33}, 32)
	tr, err := btcutil.NewAddressTaproot(key, regtestParams())
	require.NoError(t, err)
	sender := tr.EncodeAddress()
	instr := ethSwapInstr("")
	dep, proof := e.srSend(sender, instr)
	ok, msg := e.srProve(dep, proof)
	require.True(t, ok, msg)
	e.srMap(dep, instr)
	e.srHeldFor(sender, rfAmount)
}

// A held refund that can never be sent (not above the dust limit plus the Magi
// fee) is fee, THORChain's rule: sendHome moves it from the hold to the fee
// supply instead of leaving it there for good. A larger one is still sent.
func TestSenderRefund_DustRefundIsFee(t *testing.T) {
	e := newRfEnv(t, mocks.MockRouterWasm)
	addr := refundBtcAddr(t)
	e.ct.StateSet(rfContract, constants.BalancePrefix+constants.BtcRefundHoldAccount, encodeBalance(t, 400))
	e.ct.StateSet(rfContract, constants.RefundHeldPrefix+addr, "400")
	e.ct.StateSet(rfContract, constants.RefundablePrefix+addr, "400")
	e.ct.StateSet(rfContract, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{ActiveSupply: 400, UserSupply: 400, BaseFeeRate: 1})))
	r := e.call(rfSender, "sendHome", addr)
	require.True(t, r.Success, "%s %s", r.Err, r.ErrMsg)
	assert.True(t, hasLog(r, "sendhome|dust|t="+addr+"|a=400"), "dust log")
	assert.Zero(t, e.bal(constants.BtcRefundHoldAccount), "the dust left the hold")
	assert.Contains(t, []string{"", "0"}, e.state(constants.RefundHeldPrefix+addr))
	assert.Contains(t, []string{"", "0"}, e.state(constants.RefundablePrefix+addr))
	s := e.supply()
	assert.Equal(t, int64(400), s.ActiveSupply, "the sats stay in the vault")
	assert.Zero(t, s.UserSupply, "no longer anyone's")
	assert.Equal(t, int64(400), s.FeeSupply, "booked as fee")
	assert.Equal(t, s.ActiveSupply, s.UserSupply+s.FeeSupply)
}
