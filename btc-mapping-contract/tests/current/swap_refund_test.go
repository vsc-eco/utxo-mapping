package current_test

// Swap refunds: a deposit swap either completes, goes back to its sender
// (refund_to), or is held for a manual refund. It is never paid to swap_to, which
// may be a third party (an exchange, a payment processor) that would never get
// the BTC out of its Magi account. A bad instruction is held instead of reverting
// the whole map. sendHome returns BTC refunded to a Bitcoin address to that
// address, paid for by any caller. Needs the regtest dev.wasm (`make test`).

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"
	"btc-mapping-contract/tests/mocks"
)

const (
	rfContract  = "btc_mapping_refund"
	rfRouter    = "router_refund"
	rfOwner     = "hive:milo-hpr"
	rfSender    = "hive:refund-sender"
	rfRecipient = "hive:third-party"
	rfAmount    = int64(10_000)
)

// refundBtcAddr is a regtest P2WPKH address standing for the sender's own wallet.
func refundBtcAddr(t *testing.T) string {
	t.Helper()
	pub := append([]byte{0x02}, bytes.Repeat([]byte{0x11}, 32)...)
	a, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(pub), regtestParams())
	require.NoError(t, err)
	return a.EncodeAddress()
}

func rfDID(addr string) string { return constants.BtcDIDTestnetPrefix + addr }

type rfEnv struct {
	t  *testing.T
	ct *test_utils.ContractTest
	n  int
}

// newRfEnv seeds the mapping contract; routerWasm nil means no router registered.
func newRfEnv(t *testing.T, routerWasm []byte) *rfEnv {
	ctv := test_utils.NewContractTest()
	ct := &ctv
	t.Cleanup(func() { ct.DataLayer.Stop() })
	ct.RegisterContract(rfContract, rfOwner, ContractWasm)
	if routerWasm != nil {
		ct.RegisterContract(rfRouter, rfOwner, routerWasm)
		ct.StateSet(rfContract, constants.RouterContractIdKey, rfRouter)
	}
	ct.StateSet(rfContract, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(rfContract, constants.LastHeightKey, "102")
	ct.StateSet(rfContract, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(rfContract, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	activateTssKey(ct, rfContract)
	return &rfEnv{t: t, ct: ct}
}

func (e *rfEnv) call(caller, action string, payload string) test_utils.ContractTestCallResult {
	e.n++
	r := e.ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "rf-" + action + "-" + strconv.Itoa(e.n),
			BlockId:              "block:rf",
			Index:                e.n,
			OpIndex:              0,
			Timestamp:            "2026-11-14T00:00:00",
			RequiredAuths:        []string{caller},
			RequiredPostingAuths: []string{},
		},
		ContractId: rfContract,
		Action:     action,
		Payload:    json.RawMessage(payload),
		RcLimit:    1_000_000,
		Intents:    []contracts.Intent{},
		Caller:     caller,
	})
	dumpLogs(e.t, r.Logs)
	return r
}

// mapDeposit maps one deposit of rfAmount to the instruction's address and
// returns the outpoint label "<txid>:0".
func (e *rfEnv) mapDeposit(instruction string) (test_utils.ContractTestCallResult, string) {
	return e.mapDepositAt(instruction, 100)
}

// mapDepositAt maps at a given block height (each fixture is its own block).
func (e *rfEnv) mapDepositAt(instruction string, height uint32) (test_utils.ContractTestCallResult, string) {
	f := buildMapFixture(e.t, instruction, rfAmount, height)
	e.ct.StateSet(rfContract, constants.BlockPrefix+strconv.FormatUint(uint64(height), 10), decodeHex(e.t, f.BlockHeaderHex))
	raw, err := hex.DecodeString(f.RawTxHex)
	require.NoError(e.t, err)
	var tx wire.MsgTx
	require.NoError(e.t, tx.Deserialize(bytes.NewReader(raw)))
	payload, err := tinyjson.Marshal(mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight: height, RawTxHex: f.RawTxHex, MerkleProofHex: f.MerkleProofHex, TxIndex: f.TxIndex,
		},
		Instructions: []string{instruction},
	})
	require.NoError(e.t, err)
	return e.call(rfOwner, "map", string(payload)), tx.TxID() + ":0"
}

func (e *rfEnv) bal(account string) int64 {
	return decodeBalance(e.t, e.ct.StateGet(rfContract, constants.BalancePrefix+account))
}

func (e *rfEnv) state(key string) string { return e.ct.StateGet(rfContract, key) }

func (e *rfEnv) supply() mapping.SystemSupply {
	s, err := mapping.UnmarshalSupply([]byte(e.state(constants.SupplyKey)))
	require.NoError(e.t, err)
	return *s
}

func hasLog(r test_utils.ContractTestCallResult, sub string) bool {
	for _, out := range r.Logs {
		for _, l := range out.Logs {
			if strings.Contains(l, sub) {
				return true
			}
		}
	}
	return false
}

// After any map: the deposit is in supply, the contract's own account and the
// swap recipient hold nothing.
func (e *rfEnv) assertNothingToRecipientOrContract() {
	assert.Zero(e.t, e.bal(rfRecipient), "swap_to must never receive a refund")
	assert.Zero(e.t, e.bal("contract:"+rfContract), "the contract must not keep the deposit")
	s := e.supply()
	assert.Equal(e.t, rfAmount, s.ActiveSupply, "active supply counts the deposit")
	assert.Equal(e.t, rfAmount, s.UserSupply, "user supply counts the deposit")
}

func swapInstr(refundTo string) string {
	i := "swap_to=" + rfRecipient + "&swap_asset_out=hbd&destination_chain=HIVE"
	if refundTo != "" {
		i += "&refund_to=" + refundTo
	}
	return i
}

func TestSwapRefund_RouterFailureGoesToRefundTo(t *testing.T) {
	addr := refundBtcAddr(t)
	cases := []struct {
		name, refundTo, credited string
		btc                      bool
	}{
		{"hive account", rfSender, rfSender, false},
		{"bitcoin address", addr, rfDID(addr), true},
		{"bitcoin DID", rfDID(addr), rfDID(addr), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newRfEnv(t, mocks.MockRouterWasm) // router returns amount_out 0
			r, op := e.mapDeposit(swapInstr(tc.refundTo))
			require.True(t, r.Success, "map must succeed: %s %s", r.Err, r.ErrMsg)
			assert.Equal(t, rfAmount, e.bal(tc.credited), "the sender's refund target gets the deposit back")
			assert.True(t, hasLog(r, "swaprefund|t="+tc.credited+"|a="+strconv.FormatInt(rfAmount, 10)+"|r=zero amount out|o="+op))
			assert.True(t, hasLog(r, "map|t="+rfRecipient+"|"), "the map log is unchanged (indexer interface)")
			if tc.btc {
				assert.Equal(t, strconv.FormatInt(rfAmount, 10), e.state(constants.RefundablePrefix+addr), "refundable recorded for sendHome")
			}
			assert.Zero(t, e.bal(constants.RefundHoldAccount))
			e.assertNothingToRecipientOrContract()
		})
	}
}

func TestSwapRefund_NoUsableRefundToIsHeld(t *testing.T) {
	for _, refundTo := range []string{"", "did:pkh:eip155:1:0x52908400098527886E0F7030069857D2E4169EE7", "contract:vsc1BdrQ6EtbQ64rq2PkPd21x4MaLnVRcJj85d", "bc1qnotanaddress", "hive:x"} {
		t.Run("refund_to="+refundTo, func(t *testing.T) {
			e := newRfEnv(t, mocks.MockRouterWasm)
			r, op := e.mapDeposit(swapInstr(refundTo))
			require.True(t, r.Success, "map must succeed: %s %s", r.Err, r.ErrMsg)
			assert.Equal(t, rfAmount, e.bal(constants.RefundHoldAccount), "held for a manual refund")
			assert.Equal(t, strconv.FormatInt(rfAmount, 10), e.state(constants.RefundHoldPrefix+op))
			assert.True(t, hasLog(r, "swaphold|a="+strconv.FormatInt(rfAmount, 10)+"|r=zero amount out|o="+op))
			e.assertNothingToRecipientOrContract()
		})
	}
}

func TestSwapRefund_UnattemptableSwapGoesToRefundTo(t *testing.T) {
	cases := []struct {
		name, instruction string
		router            bool
		reason            string
	}{
		{"no asset out", "swap_to=" + rfRecipient + "&refund_to=" + rfSender, true, "asset out required to execute a swap"},
		{"no router registered", swapInstr(rfSender), false, "router contract not initialized"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var w []byte
			if tc.router {
				w = mocks.MockRouterWasm
			}
			e := newRfEnv(t, w)
			r, _ := e.mapDeposit(tc.instruction)
			require.True(t, r.Success, "map must succeed: %s %s", r.Err, r.ErrMsg)
			assert.Equal(t, rfAmount, e.bal(rfSender))
			assert.True(t, hasLog(r, "deposit-swap not attempted ("+tc.reason+")"))
			e.assertNothingToRecipientOrContract()
		})
	}
}

func TestSwapRefund_BadInstructionIsHeldNotReverted(t *testing.T) {
	cases := []struct{ name, instruction, reason string }{
		{"swap_to not a user", "swap_to=contract:vsc1BdrQ6EtbQ64rq2PkPd21x4MaLnVRcJj85d&swap_asset_out=hbd&refund_to=" + rfSender, "swap_to is not a user address"},
		{"btc payout", "swap_to=" + rfSender + "&swap_asset_out=hbd&destination_chain=btc", "output network cannot be btc"},
		{"no destination", "foo=bar", "no deposit_to or swap_to"},
		{"deposit_to invalid", "deposit_to=not:an-address", "deposit_to is not a magi address"},
		{"does not parse", "swap_to=%zz", "instruction does not parse"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newRfEnv(t, mocks.MockRouterWasm)
			r, op := e.mapDeposit(tc.instruction)
			require.True(t, r.Success, "a bad instruction must not revert the map: %s %s", r.Err, r.ErrMsg)
			assert.Equal(t, rfAmount, e.bal(constants.RefundHoldAccount))
			assert.True(t, hasLog(r, "swaphold|a="+strconv.FormatInt(rfAmount, 10)+"|r="+tc.reason+"|o="+op))
			assert.Zero(t, e.bal(rfSender), "a hold credits nobody")
			e.assertNothingToRecipientOrContract()
		})
	}
}

func TestSwapRefund_PlainDepositUnchanged(t *testing.T) {
	e := newRfEnv(t, mocks.MockRouterWasm)
	r, _ := e.mapDeposit("deposit_to=" + rfSender)
	require.True(t, r.Success, "%s %s", r.Err, r.ErrMsg)
	assert.Equal(t, rfAmount, e.bal(rfSender))
	assert.Zero(t, e.bal(constants.RefundHoldAccount))
	assert.False(t, hasLog(r, "swaprefund|"))
}

func TestSwapRefund_SendHomeReturnsBitcoinRefund(t *testing.T) {
	addr := refundBtcAddr(t)
	e := newRfEnv(t, mocks.MockRouterWasm)
	// Another user's coin in the vault: with the fee taken from the amount, coin
	// selection needs amount - vscFee + minerFee, more than a lone 10,000-sat coin.
	r, _ := e.mapDepositAt("deposit_to=hive:someone-else", 99)
	require.True(t, r.Success, "%s %s", r.Err, r.ErrMsg)
	r, _ = e.mapDeposit(swapInstr(addr))
	require.True(t, r.Success, "%s %s", r.Err, r.ErrMsg)
	require.Equal(t, rfAmount, e.bal(rfDID(addr)))

	// Refusals first: wrong network, no record.
	r = e.call("hive:keeper", "sendHome", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
	assert.False(t, r.Success, "a mainnet address on regtest is refused")
	r = e.call("hive:keeper", "sendHome", refundBtcAddrOther(t))
	assert.False(t, r.Success, "an address with nothing refundable is refused")
	assert.Contains(t, r.ErrMsg, "nothing refundable", "a bare address parses")
	r = e.call("hive:keeper", "sendHome", `"`+refundBtcAddrOther(t)+`"`)
	assert.False(t, r.Success, "an address with nothing refundable is refused")
	assert.Contains(t, r.ErrMsg, "nothing refundable", "a JSON-quoted address parses")

	// Any caller (it pays the RC) returns the refund to the address itself. The
	// mapping bot sends the address as a JSON string.
	before := e.supply()
	r = e.call("hive:keeper", "sendHome", `"`+addr+`"`)
	require.True(t, r.Success, "sendHome must succeed: %s %s", r.Err, r.ErrMsg)
	assert.True(t, hasLog(r, "sendhome|t="+addr+"|a="+strconv.FormatInt(rfAmount, 10)))
	// ACCT-1: the debit is the Magi fee + what is sent + the true miner fee; an
	// over-estimated miner fee stays with the owner and stays refundable.
	left := e.bal(rfDID(addr))
	assert.Less(t, left, int64(100), "only a fee-estimate surplus stays behind")
	if left > 0 {
		assert.Equal(t, strconv.FormatInt(left, 10), e.state(constants.RefundablePrefix+addr), "the surplus stays refundable")
	} else {
		assert.Equal(t, "", e.state(constants.RefundablePrefix+addr))
	}
	assert.NotEqual(t, "", e.state(constants.TxSpendsRegistryKey), "a withdrawal to the address is pending")
	after := e.supply()
	assert.Less(t, after.ActiveSupply, before.ActiveSupply, "the withdrawal leaves supply")
	assert.Zero(t, e.bal("hive:keeper"), "the caller gains nothing")

	r = e.call("hive:keeper", "sendHome", addr)
	assert.False(t, r.Success, "a second sendHome cannot send a sub-dust surplus")
	assert.Equal(t, left, e.bal(rfDID(addr)), "a refused sendHome moves nothing")
}

func refundBtcAddrOther(t *testing.T) string {
	pub := append([]byte{0x03}, bytes.Repeat([]byte{0x22}, 32)...)
	a, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(pub), regtestParams())
	require.NoError(t, err)
	return a.EncodeAddress()
}

func TestSwapRefund_ReleaseHoldIsOwnerOnly(t *testing.T) {
	e := newRfEnv(t, mocks.MockRouterWasm)
	r, op := e.mapDeposit(swapInstr(""))
	require.True(t, r.Success, "%s %s", r.Err, r.ErrMsg)
	require.Equal(t, rfAmount, e.bal(constants.RefundHoldAccount))

	in := "o=" + op + "&to=" + rfSender
	r = e.call(rfSender, "releaseHold", in)
	assert.False(t, r.Success, "only the owner releases a hold")
	r = e.call(rfOwner, "releaseHold", "o="+op+"&to=contract:vsc1BdrQ6EtbQ64rq2PkPd21x4MaLnVRcJj85d")
	assert.False(t, r.Success, "a hold is released only to a user address")

	r = e.call(rfOwner, "releaseHold", in)
	require.True(t, r.Success, "%s %s", r.Err, r.ErrMsg)
	assert.Equal(t, rfAmount, e.bal(rfSender))
	assert.Zero(t, e.bal(constants.RefundHoldAccount))
	assert.Equal(t, "", e.state(constants.RefundHoldPrefix+op))
	assert.True(t, hasLog(r, "holdrelease|t="+rfSender+"|a="+strconv.FormatInt(rfAmount, 10)+"|r=owner|o="+op))

	r = e.call(rfOwner, "releaseHold", in)
	assert.False(t, r.Success, "a hold is released once")
}

func TestSwapRefund_EvmPayoutNeedsAHiveRefundTo(t *testing.T) {
	addr := refundBtcAddr(t)
	eth := func(refundTo string) string {
		i := "swap_to=" + rfRecipient + "&swap_asset_out=eth&destination_chain=ETH"
		if refundTo != "" {
			i += "&refund_to=" + refundTo
		}
		return i
	}
	const reason = "a payout on ETH needs a hive: refund_to"

	t.Run("bitcoin refund address: back on Bitcoin, not attempted", func(t *testing.T) {
		e := newRfEnv(t, mocks.MockRouterWasm)
		r, _ := e.mapDeposit(eth(addr))
		require.True(t, r.Success, "%s %s", r.Err, r.ErrMsg)
		assert.True(t, hasLog(r, "deposit-swap not attempted ("+reason+")"))
		assert.Equal(t, rfAmount, e.bal(rfDID(addr)))
		assert.Equal(t, strconv.FormatInt(rfAmount, 10), e.state(constants.RefundablePrefix+addr))
		e.assertNothingToRecipientOrContract()
	})
	t.Run("no refund_to: held", func(t *testing.T) {
		e := newRfEnv(t, mocks.MockRouterWasm)
		r, _ := e.mapDeposit(eth(""))
		require.True(t, r.Success, "%s %s", r.Err, r.ErrMsg)
		assert.True(t, hasLog(r, "deposit-swap not attempted ("+reason+")"))
		assert.Equal(t, rfAmount, e.bal(constants.RefundHoldAccount))
		e.assertNothingToRecipientOrContract()
	})
	t.Run("hive refund_to: attempted", func(t *testing.T) {
		e := newRfEnv(t, mocks.MockRouterWasm) // zero output: refunded to the hive account
		r, _ := e.mapDeposit(eth(rfSender))
		require.True(t, r.Success, "%s %s", r.Err, r.ErrMsg)
		assert.False(t, hasLog(r, "deposit-swap not attempted"))
		assert.True(t, hasLog(r, "deposit-swap failed (zero amount out)"))
		assert.Equal(t, rfAmount, e.bal(rfSender))
		e.assertNothingToRecipientOrContract()
	})
}
