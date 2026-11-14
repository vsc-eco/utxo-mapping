package current_test

import (
	"dash-mapping-contract/contract/constants"
	"dash-mapping-contract/contract/mapping"
	"dash-mapping-contract/tests/mocks"
	"encoding/binary"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeBalance reverses encodeBalance / setAccBal's compact big-endian
// binary format so we can read the depositor's balance back out of state.
func decodeBalance(t *testing.T, raw string) int64 {
	t.Helper()
	if raw == "" {
		return 0
	}
	var buf [8]byte
	copy(buf[8-len(raw):], raw)
	return int64(binary.BigEndian.Uint64(buf[:]))
}

// Pentest finding BTC-C4: a router failure used to revert the whole map (coins
// stuck in the vault). The fix credited the swap's own deposit instead, but to
// swap_to, which may be a third party (an exchange, a payment processor): that
// is a delayed payment, not a refund. A deposit swap that does not complete now
// goes back to its sender (refund_to, a hive: account), or is held for a manual
// refund by the owner (releaseHold). Never to swap_to.
//
// The mock router (tests/mocks/mockrouter/) always answers amount_out "0", which
// drives the failure branch.

const (
	c4MappingId   = "mapping_for_btcc4"
	c4RouterId    = "mock_router_for_btcc4"
	c4Owner       = "hive:milo-hpr"
	c4SwapTo      = "hive:milo-receiver"
	c4RefundTo    = "hive:refund-sender"
	c4UtxoAmount  = int64(10_000)
	c4BlockHeight = uint32(100)
)

type c4Env struct {
	t  *testing.T
	ct test_utils.ContractTest
	n  int
}

func (e *c4Env) bal(acct string) int64 {
	return decodeBalance(e.t, e.ct.StateGet(c4MappingId, constants.BalancePrefix+acct))
}

func (e *c4Env) call(caller, action, payload string) test_utils.ContractTestCallResult {
	e.n++
	return e.ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "btcc4-" + action + "-" + strconv.Itoa(e.n),
			Index:                e.n,
			BlockId:              "block:btcc4",
			Timestamp:            "2026-05-07T00:00:00",
			RequiredAuths:        []string{caller},
			RequiredPostingAuths: []string{},
		},
		ContractId: c4MappingId,
		Action:     action,
		Payload:    json.RawMessage(payload),
		RcLimit:    1_000_000,
		Intents:    []contracts.Intent{},
		Caller:     caller,
	})
}

// c4Map maps one deposit to the address of instruction, with the mock router.
func c4Map(t *testing.T, instruction string) (*c4Env, test_utils.ContractTestCallResult) {
	t.Helper()
	fixture := buildMapFixture(t, instruction, c4UtxoAmount, c4BlockHeight)
	e := &c4Env{t: t, ct: test_utils.NewContractTest()}
	t.Cleanup(func() { e.ct.DataLayer.Stop() })
	e.ct.RegisterContract(c4MappingId, c4Owner, ContractWasm)
	e.ct.RegisterContract(c4RouterId, c4Owner, mocks.MockRouterWasm)
	e.ct.StateSet(c4MappingId, constants.RouterContractIdKey, c4RouterId)
	e.ct.StateSet(c4MappingId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	e.ct.StateSet(c4MappingId, constants.LastHeightKey, "100")
	e.ct.StateSet(c4MappingId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	e.ct.StateSet(c4MappingId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	e.ct.StateSet(c4MappingId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	payload, err := tinyjson.Marshal(mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    c4BlockHeight,
			RawTxHex:       fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex,
			TxIndex:        fixture.TxIndex,
		},
		Instructions: []string{instruction},
	})
	require.NoError(t, err)
	return e, e.call(c4Owner, "map", string(payload))
}

func c4Log(r test_utils.ContractTestCallResult, prefix string) string {
	for _, out := range r.Logs {
		for _, l := range out.Logs {
			if strings.HasPrefix(l, prefix) {
				return l
			}
		}
	}
	return ""
}

// c4Outpoint is the o=<txid>:<vout> field of a refund log line.
func c4Outpoint(line string) string {
	for _, f := range strings.Split(line, "|") {
		if strings.HasPrefix(f, "o=") {
			return strings.TrimPrefix(f, "o=")
		}
	}
	return ""
}

func TestBTCC4_RouterFailureRefundsTheSender(t *testing.T) {
	e, r := c4Map(t, "swap_to="+c4SwapTo+"&swap_asset_out=HBD&destination_chain=hive&refund_to="+c4RefundTo)
	require.True(t, r.Success, "map must not revert on a router failure: %s %s", r.Err, r.ErrMsg)
	assert.Equal(t, c4UtxoAmount, e.bal(c4RefundTo), "refunded to refund_to")
	assert.Zero(t, e.bal(c4SwapTo), "swap_to gets nothing from a swap that did not complete")
	assert.Zero(t, e.bal("contract:"+c4MappingId), "no self-credit left behind")
	assert.Zero(t, e.bal(constants.RefundHoldAccount))
	assert.NotEmpty(t, c4Log(r, "swaprefund|t="+c4RefundTo+"|a=10000|"))
}

func TestBTCC4_NoRefundToIsHeldAndOnlyTheOwnerReleasesIt(t *testing.T) {
	e, r := c4Map(t, "swap_to="+c4SwapTo+"&swap_asset_out=HBD&destination_chain=hive")
	require.True(t, r.Success, "%s %s", r.Err, r.ErrMsg)
	assert.Zero(t, e.bal(c4SwapTo), "a legacy instruction's failed swap is not paid to swap_to")
	assert.Equal(t, c4UtxoAmount, e.bal(constants.RefundHoldAccount), "held")
	assert.Zero(t, e.bal("contract:"+c4MappingId))
	hold := c4Log(r, "swaphold|")
	require.NotEmpty(t, hold)
	op := c4Outpoint(hold)
	require.NotEmpty(t, op)
	assert.Equal(t, "10000", e.ct.StateGet(c4MappingId, constants.RefundHoldPrefix+op))

	rel := "o=" + op + "&to=" + c4RefundTo
	r = e.call("hive:someone-else", "releaseHold", rel)
	assert.False(t, r.Success, "only the owner releases a hold")
	assert.Equal(t, c4UtxoAmount, e.bal(constants.RefundHoldAccount))

	r = e.call(c4Owner, "releaseHold", rel)
	require.True(t, r.Success, "%s %s", r.Err, r.ErrMsg)
	assert.Equal(t, c4UtxoAmount, e.bal(c4RefundTo), "released to the sender")
	assert.Zero(t, e.bal(constants.RefundHoldAccount))
	assert.Equal(t, "", e.ct.StateGet(c4MappingId, constants.RefundHoldPrefix+op))

	r = e.call(c4Owner, "releaseHold", rel)
	assert.False(t, r.Success, "a hold is released once")
}

func TestBTCC4_PayoutOnAnotherChainNeedsAHiveRefundTo(t *testing.T) {
	// With no hive: refund_to the router would refund a failed payout to this
	// contract: the swap is not attempted and the deposit is held.
	e, r := c4Map(t, "swap_to="+c4SwapTo+"&swap_asset_out=ETH&destination_chain=ETH")
	require.True(t, r.Success, "%s %s", r.Err, r.ErrMsg)
	assert.Equal(t, c4UtxoAmount, e.bal(constants.RefundHoldAccount))
	assert.Zero(t, e.bal(c4SwapTo))
	assert.Contains(t, c4Log(r, "swaphold|"), "needs a hive: refund_to")

	// With one, it is attempted, and the router's failure goes back to the sender.
	e, r = c4Map(t, "swap_to="+c4SwapTo+"&swap_asset_out=ETH&destination_chain=ETH&refund_to="+c4RefundTo)
	require.True(t, r.Success, "%s %s", r.Err, r.ErrMsg)
	assert.Equal(t, c4UtxoAmount, e.bal(c4RefundTo))
	assert.Zero(t, e.bal(constants.RefundHoldAccount))
}

func TestBTCC4_ARefundToThatIsNotAHiveAccountIsHeld(t *testing.T) {
	e, r := c4Map(t, "swap_to="+c4SwapTo+"&swap_asset_out=HBD&destination_chain=hive&refund_to=did:pkh:eip155:1:0x00000000000000000000000000000000000000a1")
	require.True(t, r.Success, "%s %s", r.Err, r.ErrMsg)
	assert.Equal(t, c4UtxoAmount, e.bal(constants.RefundHoldAccount))
	assert.Zero(t, e.bal(c4SwapTo))
}
