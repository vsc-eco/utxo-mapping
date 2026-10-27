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

// VR2-12: a rotation activates only once its key has been reshared into a
// committee. The reshare happens while the old generation is still ACTIVE and
// serving, so migrateVault can run right after activation and the only window
// users see is the sweep.
func TestActivateKey_RotationWaitsForTheNewKeysFirstReshare(t *testing.T) {
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

	oldStillServing := func(why string) {
		t.Helper()
		vaults, _, activeGen := loadVaults(t, &ct, contractId)
		require.Equal(t, uint32(0), activeGen, why)
		require.Equal(t, mapping.VaultStatusActive, vaults[0].Status, why)
		require.Equal(t, mapping.VaultStatusPending, vaults[1].Status, why)
	}

	// Check-signed but made this epoch: not reshared yet.
	setTssKeyProof(t, &ct, contractId, "mainv1", Gen1PrimaryHex, 0, true)
	r := callKeyAction(t, &ct, contractId, owner, "activateKey", []byte(""))
	require.NotEmpty(t, r.Err, "a rotation must not activate a key that has never been reshared")
	require.Contains(t, r.ErrMsg, "VR2-12")
	oldStillServing("refused activation leaves gen-0 active")

	// Reshared, but the node is below 0.11.0 and cannot say so.
	setTssKeyProof(t, &ct, contractId, "mainv1", Gen1PrimaryHex, 1, true)
	ct.KeyReshared = false
	r = callKeyAction(t, &ct, contractId, owner, "activateKey", []byte(""))
	require.NotEmpty(t, r.Err, "without the node's reshare flag no rotation activates")
	require.Contains(t, r.ErrMsg, "VR2-12")
	oldStillServing("refused activation leaves gen-0 active")

	// The check-signature gate still comes first: reshared but never check-signed.
	ct.KeyReshared = true
	setTssKeyProof(t, &ct, contractId, "mainv1", Gen1PrimaryHex, 1, false)
	r = callKeyAction(t, &ct, contractId, owner, "activateKey", []byte(""))
	require.NotEmpty(t, r.Err)
	require.Contains(t, r.ErrMsg, "check-signature")
	oldStillServing("refused activation leaves gen-0 active")

	// Reshared and reported: activation goes, and migration starts at once.
	setTssKeyProof(t, &ct, contractId, "mainv1", Gen1PrimaryHex, 1, true)
	r = callKeyAction(t, &ct, contractId, owner, "activateKey", []byte(""))
	require.Empty(t, r.Err, "a reshared, check-signed key activates; got %s", r.ErrMsg)
	vaults, _, activeGen := loadVaults(t, &ct, contractId)
	require.Equal(t, uint32(1), activeGen)
	require.Equal(t, mapping.VaultStatusRetiring, vaults[0].Status)

	r = callKeyAction(t, &ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, r.Err, "migration needs no further wait after a VR2-12 activation; got %s", r.ErrMsg)
	vaults, _, _ = loadVaults(t, &ct, contractId)
	require.Equal(t, mapping.VaultStatusDraining, vaults[0].Status)
}

// Genesis has no predecessor and cannot have been reshared: it is exempt and
// still auto-activates on registerPublicKey with a keygen-epoch key.
func TestGenesisActivate_ExemptFromTheReshareGate(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	seedTssKey(t, &ct, contractId, "main", TestPrimaryPubKeyHex)
	setTssKeyProof(t, &ct, contractId, "main", TestPrimaryPubKeyHex, 0, true) // keygen epoch: not reshared

	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err)
	r := callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, TestPrimaryPubKeyHex, TestBackupPubKeyHex))
	require.Empty(t, r.Err, "genesis registration must not wait for a reshare; got %s", r.ErrMsg)
	vaults, _, activeGen := loadVaults(t, &ct, contractId)
	require.Len(t, vaults, 1)
	require.Equal(t, mapping.VaultStatusActive, vaults[0].Status)
	require.Equal(t, uint32(0), activeGen)
}
