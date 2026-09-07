package current_test

import (
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"
	"btc-mapping-contract/tests/mocks"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// VR2-23 regression: a router that CONSUMES its allowance and then reports zero
// output must receive a refund of ZERO — and must never be paid out of another
// depositor's stranded credit.
//
// Background. On a swap-tagged deposit the mapping contract credits ITSELF
// ("contract:<id>"), grants the router an allowance for that amount, and calls it.
// When the router fails, the depositor is refunded. An earlier version of that
// refund decided HOW MUCH to return by reading the contract's own balance — but
// "contract:<id>" is a SHARED, PERSISTENT account across every deposit and every
// call. A deposit whose router succeeded without pulling leaves its credit
// stranded there, and that leftover could then fund a refund for a DIFFERENT
// deposit whose router had already drained it. Result: the same sats paid twice,
// with the shortfall silently taken from an uninvolved third party.
//
// The refund is now sized from the UNSPENT ALLOWANCE of THIS swap
// (checkAndDeductBalance decrements the allowance on every third-party pull), so
// provenance is per-deposit and a leftover cannot mask a drain.
func TestVR223_DrainingRouterGetsNoRefundAndCannotRaidStrandedCredit(t *testing.T) {
	// Must match the ids compiled into tests/mocks/mockdrainrouter/main.go.
	const btcContractId = "btc_map_drain_test"
	const attacker = "hive:evildrain"
	const routerContractId = "mock_drain_router"

	const swapRecipient = "hive:milo-receiver"
	const instruction = "swap_to=" + swapRecipient + "&swap_asset_out=HBD&destination_chain=hive"
	const blockHeight = uint32(100)
	// Must equal the mock's hardcoded pullAmount so it drains the FULL allowance.
	const utxoAmount int64 = 333_333
	// An unrelated deposit's stranded credit, sitting in the shared contract account.
	const strandedCredit int64 = 777_777

	fixture := buildMapFixture(t, instruction, utxoAmount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })

	ct.RegisterContract(btcContractId, "hive:milo-hpr", ContractWasm)
	ct.RegisterContract(routerContractId, "hive:milo-hpr", mocks.MockDrainRouterWasm)
	ct.StateSet(btcContractId, constants.RouterContractIdKey, routerContractId)

	ct.StateSet(btcContractId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(btcContractId, constants.LastHeightKey, "102")
	ct.StateSet(btcContractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	ct.StateSet(btcContractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(btcContractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	// The masking condition: an earlier deposit's credit stranded in the SHARED
	// contract account. This is what an aggregate-balance refund would raid.
	selfAddr := "contract:" + btcContractId
	ct.StateSet(btcContractId, constants.BalancePrefix+selfAddr, encodeBalance(t, strandedCredit))

	params := mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    blockHeight,
			RawTxHex:       fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex,
			TxIndex:        fixture.TxIndex,
		},
		Instructions: []string{instruction},
	}
	payload, err := tinyjson.Marshal(params)
	require.NoError(t, err)

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: "vr2-23-drain-tx", BlockId: "block:vr223", Index: 0, OpIndex: 0,
			Timestamp: "2026-09-07T00:00:00", RequiredAuths: []string{"hive:milo-hpr"},
			RequiredPostingAuths: []string{},
		},
		ContractId: btcContractId, Action: "map", Payload: payload,
		RcLimit: 10000, Intents: []contracts.Intent{}, Caller: "hive:milo-hpr",
	})
	require.True(t, r.Success, "map should succeed; err=%q msg=%q", r.Err, r.ErrMsg)

	// The router really did take the money — an ordinary transferFrom against the
	// allowance it was granted. That is the precondition, not the bug.
	attackerBal := decodeBalance(t, ct.StateGet(btcContractId, constants.BalancePrefix+attacker))
	require.Equal(t, utxoAmount, attackerBal,
		"fixture precondition: the draining router must actually have pulled the allowance")

	// THE REGRESSION ASSERTIONS.
	// 1. No refund: the router consumed the whole allowance, so nothing of THIS
	//    deposit remains to return. Paying anyway would pay the same sats twice.
	depositorBal := decodeBalance(t, ct.StateGet(btcContractId, constants.BalancePrefix+swapRecipient))
	assert.Zero(t, depositorBal,
		"a router that consumed the full allowance must produce a ZERO refund; "+
			"got %d — the contract paid the same sats twice", depositorBal)

	// 2. And the unrelated stranded credit must be untouched. This is the part
	//    that made the old behaviour a third-party fund-extraction rather than a
	//    mere accounting slip.
	selfBal := decodeBalance(t, ct.StateGet(btcContractId, constants.BalancePrefix+selfAddr))
	assert.Equal(t, strandedCredit, selfBal,
		"an unrelated depositor's stranded credit must NOT fund this refund; "+
			"got %d, want %d", selfBal, strandedCredit)
}
