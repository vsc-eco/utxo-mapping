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

// VR2-20 regression: the DEX router id is set-once on EVERY network, including
// testnet and regtest builds.
//
// Background. `registerRouter` used to write RouterContractIdKey whenever the
// key was empty OR the binary was built for a testnet/regtest network
// (contract/main.go). The two other set-once keys relaxed the same way (primary
// and backup public keys) are re-derived from the vault list on every init, so
// re-pointing them does not stick. The ROUTER id has no such backstop: it is
// read straight off state on the deposit path, and on a swap-tagged deposit the
// contract credits ITSELF with the freshly mapped, chain-backed amount and then
// grants the registered router an ALLOWANCE over exactly that credit before
// calling it.
//
// So on any build carrying the testnet flag, re-pointing the router handed an
// arbitrary contract a live spend authority over real deposits — and, because a
// router that returns a plausible non-zero `amount_out` is treated as SUCCESS
// and therefore committed, the theft is not rolled back. Mainnet was never
// exposed by this path (the key is set once there), but that is exactly the
// problem: testnet could not prove what mainnet enforces, and any build shipped
// with the flag set was drainable.
//
// This test runs against the regtest (`dev`) wasm — the build where the bypass
// used to be live — so it is a genuine red-before for the fix.
func TestVR220_RouterIdIsSetOnceEvenOnTestnetBuilds(t *testing.T) {
	// Ids are fixed at build time inside mockdrainrouter, so the mapping
	// contract must be registered under the id that mock expects.
	const btcContractId = "btc_map_drain_test"
	const attacker = "hive:evildrain"

	const honestRouterId = "mock_router"
	const attackerRouterId = "mock_drain_router"

	const owner = "hive:milo-hpr"
	const swapRecipient = "hive:milo-receiver"
	const instruction = "swap_to=" + swapRecipient + "&swap_asset_out=HBD&destination_chain=hive"
	const blockHeight = uint32(100)
	// Equals the drain mock's hardcoded pull, so a successful re-point would
	// take the entire deposit.
	const utxoAmount int64 = 333_333

	fixture := buildMapFixture(t, instruction, utxoAmount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })

	ct.RegisterContract(btcContractId, owner, ContractWasm)
	ct.RegisterContract(honestRouterId, owner, mocks.MockRouterWasm)
	ct.RegisterContract(attackerRouterId, owner, mocks.MockDrainRouterWasm)

	ct.StateSet(btcContractId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(btcContractId, constants.LastHeightKey, "102")
	ct.StateSet(btcContractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	ct.StateSet(btcContractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(btcContractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	registerRouter := func(txId, routerId string) test_utils.ContractTestCallResult {
		return ct.Call(stateEngine.TxVscCallContract{
			Self: stateEngine.TxSelf{
				TxId: txId, BlockId: "block:vr220", Index: 0, OpIndex: 0,
				Timestamp: "2026-09-07T00:00:00", RequiredAuths: []string{owner},
				RequiredPostingAuths: []string{},
			},
			ContractId: btcContractId, Action: "registerRouter",
			Payload: []byte(`{"router_contract":"` + routerId + `"}`),
			RcLimit: 10000, Intents: []contracts.Intent{}, Caller: owner,
		})
	}

	// The legitimate, first registration still works — the fix must not break
	// bring-up on any network.
	first := registerRouter("vr2-20-register-honest", honestRouterId)
	require.True(t, first.Success, "first registerRouter must succeed; err=%q msg=%q", first.Err, first.ErrMsg)
	require.Equal(t, honestRouterId, ct.StateGet(btcContractId, constants.RouterContractIdKey),
		"fixture precondition: the honest router must be the registered one")

	// THE ATTACK: the owner key (or anyone who has taken it) re-points the
	// router at a contract that will pull the allowance it is about to be
	// granted.
	repoint := registerRouter("vr2-20-repoint-attacker", attackerRouterId)

	// ASSERTION 1 — the re-point does not take effect. Re-registration is a
	// reported no-op rather than an abort, matching the existing
	// already-registered behaviour on mainnet.
	assert.Equal(t, honestRouterId, ct.StateGet(btcContractId, constants.RouterContractIdKey),
		"router id must be set-once on EVERY network; a testnet/regtest build "+
			"re-pointed it to %q", attackerRouterId)
	assert.Contains(t, repoint.Ret, "already registered",
		"a refused re-point must say so instead of silently doing nothing")

	// ASSERTION 2 — and the value path really is unaffected. Drive an actual
	// swap-tagged deposit: the allowance must be granted to the ORIGINAL router,
	// so the attacker's contract never gets to pull anything.
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
			TxId: "vr2-20-map-tx", BlockId: "block:vr220", Index: 1, OpIndex: 0,
			Timestamp: "2026-09-07T00:00:00", RequiredAuths: []string{owner},
			RequiredPostingAuths: []string{},
		},
		ContractId: btcContractId, Action: "map", Payload: payload,
		RcLimit: 10000, Intents: []contracts.Intent{}, Caller: owner,
	})
	require.True(t, r.Success, "map should succeed; err=%q msg=%q", r.Err, r.ErrMsg)

	attackerBal := decodeBalance(t, ct.StateGet(btcContractId, constants.BalancePrefix+attacker))
	assert.Zero(t, attackerBal,
		"the re-pointed router must never receive an allowance over a deposit; "+
			"it drained %d", attackerBal)

	// The honest mock reports zero output without pulling, so the depositor is
	// made whole by the BTC-C4 refund. That confirms the deposit went down the
	// ORIGINAL router's path rather than being lost or double-counted.
	depositorBal := decodeBalance(t, ct.StateGet(btcContractId, constants.BalancePrefix+swapRecipient))
	assert.Equal(t, utxoAmount, depositorBal,
		"deposit must have been routed through the original router and refunded")
}
