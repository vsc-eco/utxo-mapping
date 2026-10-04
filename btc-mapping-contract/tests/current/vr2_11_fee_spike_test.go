package current_test

import (
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/require"
)

// VR2-11 end to end: a fee spike must not deadlock a rotation.
//
// The oracle rate here is 500 sat/vB, so the ~146 vB sweep of a 100,000-sat
// residual would cost ~73,000 — more than half the tranche. buildMigrationTransaction
// refused that (the V5-4 ceiling, which stops a rogue oracle rate burning a tranche
// on miner fees), and write-off correctly declined to touch the residual because it
// IS affordable at the protocol minimum. So nothing moved: NN#3 kept refusing the
// next rotation and the committee's bond stayed locked, until fees happened to
// fall. No attacker needed — a fee spike was enough.
//
// The builder now derives the highest rate that fits under the SAME ceiling rather
// than insisting on the oracle's. The ceiling itself is untouched, which is why
// this is not a weakening of V5-4: the fee still cannot exceed half the tranche.
//
// This is the wiring test. The arithmetic is pinned separately in
// contract/mapping/vr2_11_fee_window_test.go, but arithmetic passing proves
// nothing about whether the builder calls it.
func TestVR211_FeeSpikeDoesNotDeadlockTheSweep(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const amount = int64(100000)
	const blockHeight = uint32(100)
	fixture := buildMapFixture(t, instruction, amount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	// FeeSupply reserve seeded so the sweep's miner fee is funded from the reserve (X-2),
	// not user principal.
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 500, FeeSupply: 100000})))
	ct.StateSet(contractId, constants.LastHeightKey, "102")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	seedActiveGen0(t, &ct, contractId, owner)

	// Deposit to gen-0 (active) → one confirmed gen-0 UTXO.
	params := mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight: blockHeight, RawTxHex: fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex, TxIndex: fixture.TxIndex,
		},
		Instructions: []string{instruction},
	}
	payload, err := tinyjson.Marshal(params)
	require.NoError(t, err)
	require.True(t, ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "map-dep", BlockId: "block:map", Index: 70, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "map", Payload: payload,
		RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: owner,
	}).Success)

	// Rotate: gen-0 → retiring, gen-1 → active.
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "activateKey", []byte("")).Err)

	regBefore, _ := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.Len(t, regBefore, 1, "one confirmed gen-0 deposit UTXO before migration")

	// Precondition: at the oracle's own rate this sweep is unaffordable under the
	// ceiling. If this stops being true the test is no longer exercising the bug.
	supplyRaw := ct.StateGet(contractId, constants.SupplyKey)
	supply, err := mapping.UnmarshalSupply([]byte(supplyRaw))
	require.NoError(t, err)
	require.Equal(t, int64(500), supply.BaseFeeRate,
		"fixture precondition: the oracle rate must be spiked")

	// THE ASSERTION: the sweep proceeds instead of deferring forever.
	r := callKeyAction(t, &ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, r.Err,
		"a sweep affordable at a lower rate must proceed rather than deadlock the "+
			"rotation until fees fall; got %s", r.ErrMsg)
	require.NotEmpty(t, r.Ret, "the sweep must produce a txid")

	// And the rotation is unblocked: gen-0 has moved off Retiring, which is what
	// releases NN#3 and eventually the bond.
	vaults, _, _ := loadVaults(t, &ct, contractId)
	require.Equal(t, mapping.VaultStatusDraining, vaults[0].Status,
		"gen-0 must move to draining once its sweep is in flight")
}
