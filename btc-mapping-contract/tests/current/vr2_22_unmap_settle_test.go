package current_test

import (
	"fmt"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/require"
)

// VR2-22, withdrawal half: an unmap must actually SETTLE when its spend confirms.
//
// The suite previously proved only the migration-sweep half. Both settle paths sit
// below the same empty-promotion guard in HandleConfirmSpend, and both register
// NOTHING at build — an unmap indexes its change inside settleUnmap, exactly as a
// sweep indexes its output inside settleMigrationSweep. Nothing else populates the
// unconfirmed pool either (allocateUnconfirmedId has no callers), so before the fix
// the guard fired on an unmap confirm too and settleUnmap was unreachable.
//
// That is the higher-traffic half: without it a withdrawal's inputs are never
// deleted, so the contract keeps believing it owns coins already spent on Bitcoin,
// and the change output is never indexed at all.
//
// Reverting only the unmap half of the guard fix left the entire suite green, so
// this test exists to make that half fail loudly.
func TestVR222_UnmapSettlesOnConfirm(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const deposit = int64(100_000)
	const blockHeight = uint32(100)
	const withdraw = int64(40_000)

	fixture := buildMapFixture(t, instruction, deposit, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1, FeeSupply: 100_000})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	seedActiveGen0(t, &ct, contractId, owner)

	// Deposit -> one confirmed UTXO + a credited balance.
	mp, err := tinyjson.Marshal(mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight: blockHeight, RawTxHex: fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex, TxIndex: fixture.TxIndex,
		},
		Instructions: []string{instruction},
	})
	require.NoError(t, err)
	require.True(t, ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "map-dep", BlockId: "block:map", Index: 70, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "map", Payload: mp,
		RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: owner}).Success)

	registryBefore := ct.StateGet(contractId, constants.UtxoRegistryKey)
	require.NotEmpty(t, registryBefore, "the deposit must have registered a UTXO")

	// Withdraw a portion -> builds the spend, writes the "us-" record, reserves inputs.
	unmapPayload, err := tinyjson.Marshal(mapping.TransferParams{
		Amount: fmt.Sprintf("%d", withdraw),
		To:     regtestDestAddress(t),
	})
	require.NoError(t, err)
	require.True(t, ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "unmap-1", BlockId: "block:unmap", Index: 71, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "unmap", Payload: unmapPayload,
		RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: owner}).Success)

	txids, err := mapping.UnmarshalTxSpendsRegistry([]byte(ct.StateGet(contractId, constants.TxSpendsRegistryKey)))
	require.NoError(t, err)
	require.Len(t, txids, 1, "exactly one pending withdrawal expected")
	unmapTxId := txids[0]

	require.NotEmpty(t, ct.StateGet(contractId, constants.PendingUnmapPrefix+unmapTxId),
		"fixture precondition: the unmap must have written its \"us-\" settle record")

	// THE REGRESSION POINT: confirming the withdrawal must actually settle it.
	// Before the guard fix this returned "no unconfirmed outputs matched the
	// provided indices", because an unmap promotes nothing — it indexes its change
	// inside settleUnmap, which the guard prevented from ever running.
	res := confirmMigrationSweep(t, &ct, contractId, owner, unmapTxId, 101)
	require.True(t, res.Success,
		"confirming an unmap must reach settleUnmap; err=%q msg=%q", res.Err, res.ErrMsg)

	// Settled: the "us-" record is consumed, so a replay cannot settle twice.
	require.Empty(t, ct.StateGet(contractId, constants.PendingUnmapPrefix+unmapTxId),
		"settleUnmap must consume its \"us-\" record")

	// And the registry actually changed: the spent input is gone and the change is
	// indexed. If settleUnmap never ran, the registry would be byte-identical and
	// the contract would still believe it owns an outpoint already spent on L1.
	registryAfter := ct.StateGet(contractId, constants.UtxoRegistryKey)
	require.NotEqual(t, registryBefore, registryAfter,
		"the UTXO registry must change at settle: spent input deleted, change indexed")
}
