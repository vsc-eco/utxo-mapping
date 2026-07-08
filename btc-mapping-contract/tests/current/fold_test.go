package current_test

import (
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
)

// callMigrate invokes the owner-only `migrate` export.
func callMigrate(t *testing.T, ct *test_utils.ContractTest, contractId, owner string) test_utils.ContractTestCallResult {
	t.Helper()
	return ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: "foldtx", BlockId: "block:fold", Index: 1, OpIndex: 0,
			Timestamp:     "2025-10-14T00:00:00",
			RequiredAuths: []string{owner}, RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "migrate",
		Payload:    []byte(""),
		RcLimit:    1000000,
		Intents:    []contracts.Intent{},
		Caller:     owner,
	})
}

// TestMigrateV2FoldGen0 verifies the S1.1 gen-0 fold: migrate() folds the legacy
// single-slot pubkey/backupkey into generation 0 of the vault list, byte-identically,
// and sets the counters. This is the load-bearing, brick-risk step — a wrong gen-0
// would break address derivation the moment S1.2 reads it.
func TestMigrateV2FoldGen0(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	owner := "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)

	primary := decodeHex(t, TestPrimaryPubKeyHex)
	backup := decodeHex(t, TestBackupPubKeyHex)
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, primary)
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, backup)
	ct.StateSet(contractId, constants.MigrateVersionKey, "1") // pre-S1 contract at v1

	r := callMigrate(t, &ct, contractId, owner)
	require.Empty(t, r.Err, "migrate should succeed")

	// Vault registry now holds exactly one entry = generation 0, keys byte-identical.
	rawVault := ct.StateGet(contractId, constants.VaultRegistryKey)
	require.NotEmpty(t, rawVault, "vault registry must be populated after fold")
	vaults, err := mapping.UnmarshalVaultRegistry([]byte(rawVault))
	require.NoError(t, err)
	require.Len(t, vaults, 1, "exactly one generation folded")
	g0 := vaults[0]
	assert.Equal(t, uint32(0), g0.Generation)
	assert.Equal(t, mapping.VaultStatusActive, g0.Status)
	assert.Equal(t, uint32(0), g0.Predecessor)
	assert.Equal(t, primary, string(g0.Primary[:]), "gen-0 primary must byte-match the live key")
	assert.Equal(t, backup, string(g0.Backup[:]), "gen-0 backup must byte-match the live key")

	// Counters: next gen = 1, active gen = 0; version bumped.
	assert.Equal(t, string([]byte{0, 0, 0, 1}), ct.StateGet(contractId, constants.VaultNextGenKey))
	assert.Equal(t, string([]byte{0, 0, 0, 0}), ct.StateGet(contractId, constants.VaultActiveGenKey))
	assert.Equal(t, "2", ct.StateGet(contractId, constants.MigrateVersionKey))

	// Legacy single slots kept readable (defense / fallback).
	assert.Equal(t, primary, ct.StateGet(contractId, constants.PrimaryPublicKeyStateKey))
	assert.Equal(t, backup, ct.StateGet(contractId, constants.BackupPublicKeyStateKey))
}

// TestMigrateV2FoldFailSafe verifies the fail-safe guard: if the vault list is
// ALREADY populated (e.g. a rotation happened and the string-version compare
// misfires at v10+, or migrate is re-run), the fold must NOT overwrite it — that
// would strand a real successor generation's funds.
func TestMigrateV2FoldFailSafe(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	owner := "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)

	primary := decodeHex(t, TestPrimaryPubKeyHex)
	backup := decodeHex(t, TestBackupPubKeyHex)
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, primary)
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, backup)

	// Simulate a post-rotation state: a 2-generation vault list already exists,
	// and the version has (incorrectly) been left below "2".
	var g0, g1 mapping.Vault
	g0.Generation = 0
	copy(g0.Primary[:], primary)
	copy(g0.Backup[:], backup)
	g0.Status = mapping.VaultStatusRetiring
	g1.Generation = 1
	copy(g1.Primary[:], primary) // dummy distinct entry for the test
	copy(g1.Backup[:], backup)
	g1.Status = mapping.VaultStatusActive
	g1.Predecessor = 0
	existing := mapping.MarshalVaultRegistry(mapping.VaultRegistry{g0, g1})
	ct.StateSet(contractId, constants.VaultRegistryKey, string(existing))
	ct.StateSet(contractId, constants.MigrateVersionKey, "1")

	r := callMigrate(t, &ct, contractId, owner)
	require.Empty(t, r.Err)

	// The 2-entry vault list must be preserved untouched (NOT clobbered to gen-0).
	rawVault := ct.StateGet(contractId, constants.VaultRegistryKey)
	assert.Equal(t, string(existing), rawVault, "fold must not overwrite an existing vault list")
	vaults, err := mapping.UnmarshalVaultRegistry([]byte(rawVault))
	require.NoError(t, err)
	require.Len(t, vaults, 2, "existing 2-generation list preserved")
	assert.Equal(t, "2", ct.StateGet(contractId, constants.MigrateVersionKey), "version still advances")
}

// TestS12VaultListIsSourceOfTruth proves the S1.2 read-switch: with the legacy
// single slots holding the WRONG (swapped) key pairing and the vault-list gen-0
// holding the CORRECT pairing, a deposit still credits — which is only possible if
// deposit-address derivation reads the VAULT LIST, not the legacy slots.
func TestS12VaultListIsSourceOfTruth(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const blockHeight = uint32(100)
	fixture := buildMapFixture(t, instruction, 10000, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	owner := "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))

	// Legacy slots: WRONG (swapped) pairing. If the code read these, the derived
	// deposit address would not match the fixture and nothing would be credited.
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))

	// Vault list gen-0: CORRECT pairing (what the fixture pays to).
	var g0 mapping.Vault
	g0.Generation = 0
	copy(g0.Primary[:], decodeHex(t, TestPrimaryPubKeyHex))
	copy(g0.Backup[:], decodeHex(t, TestBackupPubKeyHex))
	g0.Status = mapping.VaultStatusActive
	ct.StateSet(contractId, constants.VaultRegistryKey, string(mapping.MarshalVaultRegistry(mapping.VaultRegistry{g0})))
	ct.StateSet(contractId, constants.VaultNextGenKey, string([]byte{0, 0, 0, 1}))
	ct.StateSet(contractId, constants.VaultActiveGenKey, string([]byte{0, 0, 0, 0}))

	params := mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight: blockHeight, RawTxHex: fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex, TxIndex: fixture.TxIndex,
		},
		Instructions: []string{instruction},
	}
	payload, err := tinyjson.Marshal(params)
	require.NoError(t, err)

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: "s12map", BlockId: "block:map", Index: 1, OpIndex: 0,
			Timestamp:     "2025-10-14T00:00:00",
			RequiredAuths: []string{owner}, RequiredPostingAuths: []string{},
		},
		ContractId: contractId, Action: "map", Payload: payload,
		RcLimit: 100000, Intents: []contracts.Intent{}, Caller: owner,
	})
	require.Empty(t, r.Err, "map should succeed")
	require.True(t, r.Success)

	// Credited ONLY if the deposit address came from the VAULT-LIST gen-0 keys.
	bal := ct.StateGet(contractId, constants.BalancePrefix+owner)
	assert.NotEmpty(t, bal, "deposit must credit via vault-list keys, not the wrong legacy slots")
}

// TestMigrateV2NumericVersionNoRegression verifies the council-F3 fix: at a future
// migration version "10", the numeric compare must NOT re-enter the v2 block, so the
// version counter is NOT regressed and the (real, 2-gen) vault list is untouched.
func TestMigrateV2NumericVersionNoRegression(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	owner := "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	primary := decodeHex(t, TestPrimaryPubKeyHex)
	backup := decodeHex(t, TestBackupPubKeyHex)
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, primary)
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, backup)
	var g0, g1 mapping.Vault
	g0.Generation = 0
	copy(g0.Primary[:], primary)
	copy(g0.Backup[:], backup)
	g0.Status = mapping.VaultStatusRetiring
	g1.Generation = 1
	copy(g1.Primary[:], primary)
	copy(g1.Backup[:], backup)
	g1.Status = mapping.VaultStatusActive
	existing := mapping.MarshalVaultRegistry(mapping.VaultRegistry{g0, g1})
	ct.StateSet(contractId, constants.VaultRegistryKey, string(existing))
	ct.StateSet(contractId, constants.MigrateVersionKey, "10")

	r := callMigrate(t, &ct, contractId, owner)
	require.Empty(t, r.Err)
	assert.Equal(t, "10", ct.StateGet(contractId, constants.MigrateVersionKey), "version must NOT regress from 10 to 2")
	assert.Equal(t, string(existing), ct.StateGet(contractId, constants.VaultRegistryKey), "vault list untouched")
}

// TestVaultRegistryRoundTripAllFields round-trips every Vault field incl. Predecessor
// + the three heights (S5 grace data) that no other test asserts symmetric.
func TestVaultRegistryRoundTripAllFields(t *testing.T) {
	in := mapping.VaultRegistry{{
		Generation: 7, Status: mapping.VaultStatusDraining, Predecessor: 6,
		CreatedHeight: 111, ActivatedHeight: 222, RetiredHeight: 333,
	}}
	copy(in[0].Primary[:], decodeHex(t, TestPrimaryPubKeyHex))
	copy(in[0].Backup[:], decodeHex(t, TestBackupPubKeyHex))
	out, err := mapping.UnmarshalVaultRegistry(mapping.MarshalVaultRegistry(in))
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, in[0], out[0], "all fields incl. Predecessor + heights must round-trip")
}

// TestUtxoBackwardCompatGeneration proves the migration-critical backward-compat read:
// a new blob round-trips its Generation; a pre-S1 blob (no trailing 4 bytes) reads as 0.
func TestUtxoBackwardCompatGeneration(t *testing.T) {
	const txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	u := &mapping.Utxo{TxId: txid, Vout: 3, Amount: 5000, PkScript: []byte{1, 2, 3}, Tag: []byte{9, 9}, Generation: 5}
	blob := mapping.MarshalUtxo(u)
	got, err := mapping.UnmarshalUtxo(blob)
	require.NoError(t, err)
	assert.Equal(t, uint32(5), got.Generation, "new blob round-trips Generation")
	// Trim the trailing 4-byte Generation → a pre-S1 blob → must read as 0.
	pre := blob[:len(blob)-4]
	gotPre, err := mapping.UnmarshalUtxo(pre)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), gotPre.Generation, "pre-S1 blob (no Generation bytes) reads as 0")
	assert.Equal(t, txid, gotPre.TxId)
	assert.Equal(t, int64(5000), gotPre.Amount)
}
