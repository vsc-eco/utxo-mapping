package current_test

import (
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/require"
	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"
)

// Funds only ever move to a vault key the TSS group has proven it holds.
//
// activateKey needs the node's check-signature flag to read "1": the new key has
// signed once, with more than 2/3 of the committee that made it. A node that
// sends no flag (below vault-rotation-v2) is refused too; until this change it
// skipped the check.
func TestActivateKey_NeedsAVerifiedCheckSignatureFromTheNode(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	seedActiveGen0(t, &ct, contractId, owner)

	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)

	ct.VaultRotationV2 = false // node below v2: three-field TssGetKey, no flag
	r := callKeyAction(t, &ct, contractId, owner, "activateKey", []byte(""))
	require.NotEmpty(t, r.Err, "a node that cannot report the check-signature must not let a key activate")
	require.Contains(t, r.ErrMsg, "check-signature")

	ct.VaultRotationV2 = true
	setTssKeyProof(t, &ct, contractId, "mainv1", Gen1PrimaryHex, 1, false)
	r = callKeyAction(t, &ct, contractId, owner, "activateKey", []byte(""))
	require.NotEmpty(t, r.Err, "a key that has not signed yet must not activate")
	require.Contains(t, r.ErrMsg, "check-signature")

	setTssKeyProof(t, &ct, contractId, "mainv1", Gen1PrimaryHex, 1, true)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "activateKey", []byte("")).Err)
	vaults, _, activeGen := loadVaults(t, &ct, contractId)
	require.Equal(t, uint32(1), activeGen)
	require.Equal(t, mapping.VaultStatusRetiring, vaults[0].Status)
}

// migrateVault moves funds into the active key only once the node reports it has
// been reshared since its keygen (consensus 0.11.0 fifth TssGetKey field). On
// testnet (2026-10-11) the first sweep into gen 2 was built in the epoch its key
// was made, before any reshare.
func TestMigrateVault_WaitsForTheActiveKeysFirstReshare(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const amount = int64(100000)
	const blockHeight = uint32(100)
	fixture := buildMapFixture(t, instruction, amount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1, FeeSupply: 100000})))
	ct.StateSet(contractId, constants.LastHeightKey, "102")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	seedActiveGen0(t, &ct, contractId, owner)

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

	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "activateKey", []byte("")).Err)

	stillRetiring := func(why string) {
		t.Helper()
		vaults, _, _ := loadVaults(t, &ct, contractId)
		require.Equal(t, mapping.VaultStatusRetiring, vaults[0].Status, why)
		require.Empty(t, ct.StateGet(contractId, constants.TxSpendsRegistryKey), why)
	}

	// The new key was made this epoch: epoch == keygen epoch.
	setTssKeyProof(t, &ct, contractId, "mainv1", Gen1PrimaryHex, 0, true)
	r := callKeyAction(t, &ct, contractId, owner, "migrateVault", []byte(""))
	require.NotEmpty(t, r.Err, "no funds may move into a key that has never been reshared")
	require.Contains(t, r.ErrMsg, "has not been reshared")
	stillRetiring("nothing moved")

	// Reshared, but the node is below 0.11.0 and cannot say so.
	setTssKeyProof(t, &ct, contractId, "mainv1", Gen1PrimaryHex, 1, true)
	ct.KeyReshared = false
	r = callKeyAction(t, &ct, contractId, owner, "migrateVault", []byte(""))
	require.NotEmpty(t, r.Err, "without the node's reshare flag nothing moves")
	stillRetiring("nothing moved")

	// Reshared and reported: the first tranche goes.
	ct.KeyReshared = true
	r = callKeyAction(t, &ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, r.Err, "a reshared key takes the migration; got %s", r.ErrMsg)
	require.NotEmpty(t, r.Ret)
	vaults, _, _ := loadVaults(t, &ct, contractId)
	require.Equal(t, mapping.VaultStatusDraining, vaults[0].Status)
}
