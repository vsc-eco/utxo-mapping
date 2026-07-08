package current_test

import (
	"encoding/binary"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/require"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	tss "vsc-node/modules/db/vsc/tss"
)

// S1.3 generation lifecycle — harness tests over the real WASM: the full rotation
// ceremony (mint -> register -> activate -> retire) plus every failure state the
// never-brick directive calls out (keygen already in flight, keygen incomplete,
// broken lineage, discard/re-mint of a stalled keygen). These exercise real
// dispatch + real state, not the stubbed host.

const (
	// Distinct valid secp256k1 compressed pubkeys (3G, 4G) for a second generation,
	// so rotation tests can prove gen-1's keys differ from gen-0's (G, 2G).
	Gen1PrimaryHex = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
	Gen1BackupHex  = "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"
)

func callKeyAction(t *testing.T, ct *test_utils.ContractTest, contractId, owner, action string, payload []byte) test_utils.ContractTestCallResult {
	t.Helper()
	return ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: "tx-" + action, BlockId: "block:" + action, Index: 1, OpIndex: 0,
			Timestamp:     "2025-10-14T00:00:00",
			RequiredAuths: []string{owner}, RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     action,
		Payload:    payload,
		RcLimit:    1000000,
		Intents:    []contracts.Intent{},
		Caller:     owner,
	})
}

func loadVaults(t *testing.T, ct *test_utils.ContractTest, contractId string) (mapping.VaultRegistry, uint32, uint32) {
	t.Helper()
	var vaults mapping.VaultRegistry
	if raw := ct.StateGet(contractId, constants.VaultRegistryKey); len(raw) > 0 {
		v, err := mapping.UnmarshalVaultRegistry([]byte(raw))
		require.NoError(t, err)
		vaults = v
	}
	var nextGen, activeGen uint32
	if s := ct.StateGet(contractId, constants.VaultNextGenKey); len(s) == 4 {
		nextGen = binary.BigEndian.Uint32([]byte(s))
	}
	if s := ct.StateGet(contractId, constants.VaultActiveGenKey); len(s) == 4 {
		activeGen = binary.BigEndian.Uint32([]byte(s))
	}
	return vaults, nextGen, activeGen
}

func regKeyPayload(t *testing.T, primary, backup string) []byte {
	t.Helper()
	in, err := tinyjson.Marshal(mapping.RegisterKeyParams{PrimaryPubKey: primary, BackupPubKey: backup})
	require.NoError(t, err)
	return in
}

func u32be(n uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return string(b[:])
}

// seedTssKeys pre-registers the given keyIds in the mock TSS keystore so that the
// harness's tss_v2.create_key binding does not trap. (Production TssCreateKey treats
// a not-yet-existing key as "create it", keyed on mongo.ErrNoDocuments; the mock's
// FindKey returns a generic error instead, which the binding maps to a runtime
// error — the documented "createKey may fail in test environment" limitation. With
// the key pre-seeded FindKey returns nil -> the binding returns "already_exists" ->
// Ok, and createKey's state mutation runs identically.) createKey ONLY reaches the
// TSS call after MintNextGeneration succeeds, so refused mints need no seed.
func seedTssKeys(t *testing.T, ct *test_utils.ContractTest, contractId string, keyIds ...string) {
	t.Helper()
	for _, k := range keyIds {
		require.NoError(t, ct.Tss.Keys.SetKey(tss.TssKey{Id: contractId + "-" + k, Algo: tss.EcdsaType}))
	}
}

// seedActiveGen0 puts the contract in the post-fold state: gen-0 ACTIVE with the
// legacy flat keys, NextGen=1, ActiveGen=0 — the mainnet starting point. It also
// pre-seeds the successor TSS keys (main-v1, main-v2) so the rotation tests' later
// createKey calls do not trap on the mock (see seedTssKeys). Seeding unused key ids
// is inert.
func seedActiveGen0(t *testing.T, ct *test_utils.ContractTest, contractId, owner string) {
	t.Helper()
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	ct.StateSet(contractId, constants.MigrateVersionKey, "1")
	seedTssKeys(t, ct, contractId, "mainv1", "mainv2")
	r := callKeyAction(t, ct, contractId, owner, "migrate", []byte(""))
	require.Empty(t, r.Err, "fold migrate should succeed")
	vaults, nextGen, activeGen := loadVaults(t, ct, contractId)
	require.Len(t, vaults, 1)
	require.Equal(t, mapping.VaultStatusActive, vaults[0].Status)
	require.Equal(t, uint32(1), nextGen)
	require.Equal(t, uint32(0), activeGen)
}

// TestGenesisMintActivate — fresh deploy: createKey mints gen-0 PENDING, then
// registerPublicKey fills its keys and AUTO-ACTIVATES it (genesis has no
// predecessor / no funds to sweep). Flat keys are written for gen-0 (back-compat).
func TestGenesisMintActivate(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	seedTssKeys(t, &ct, contractId, "main") // genesis mints gen-0 ("main")

	r := callKeyAction(t, &ct, contractId, owner, "createKey", []byte(""))
	require.Empty(t, r.Err, "genesis createKey should succeed")
	vaults, nextGen, activeGen := loadVaults(t, &ct, contractId)
	require.Len(t, vaults, 1)
	require.Equal(t, uint32(0), vaults[0].Generation)
	require.Equal(t, mapping.VaultStatusPending, vaults[0].Status)
	require.Equal(t, uint32(1), nextGen)
	require.Equal(t, uint32(0), activeGen)
	require.Equal(t, mapping.CompressedPubKey{}, vaults[0].Primary, "no keys until registerPublicKey")

	r = callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, TestPrimaryPubKeyHex, TestBackupPubKeyHex))
	require.Empty(t, r.Err, "registerPublicKey should succeed")
	vaults, _, activeGen = loadVaults(t, &ct, contractId)
	require.Len(t, vaults, 1)
	require.Equal(t, mapping.VaultStatusActive, vaults[0].Status, "genesis gen-0 must auto-activate once both keys set")
	require.Equal(t, uint32(0), activeGen)
	require.Equal(t, decodeHex(t, TestPrimaryPubKeyHex), string(vaults[0].Primary[:]))
	require.Equal(t, decodeHex(t, TestPrimaryPubKeyHex), ct.StateGet(contractId, constants.PrimaryPublicKeyStateKey), "flat keys written for gen-0")
}

// TestRotationMintActivateRetire — the core rotation over a post-fold gen-0:
// createKey -> gen-1 PENDING bound to gen-0; registerPublicKey fills gen-1 keys
// (stays pending, flat gen-0 keys untouched); activateKey -> gen-1 ACTIVE, gen-0
// RETIRING (keeps its keys, never-brick).
func TestRotationMintActivateRetire(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	seedActiveGen0(t, &ct, contractId, owner)

	r := callKeyAction(t, &ct, contractId, owner, "createKey", []byte(""))
	require.Empty(t, r.Err)
	vaults, nextGen, activeGen := loadVaults(t, &ct, contractId)
	require.Len(t, vaults, 2)
	require.Equal(t, uint32(1), vaults[1].Generation)
	require.Equal(t, mapping.VaultStatusPending, vaults[1].Status)
	require.Equal(t, uint32(0), vaults[1].Predecessor, "lineage: gen-1 predecessor = active gen-0")
	require.Equal(t, uint32(2), nextGen)
	require.Equal(t, uint32(0), activeGen, "active gen unchanged during keygen")
	require.Equal(t, mapping.VaultStatusActive, vaults[0].Status, "gen-0 still active while gen-1 pending")

	r = callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, Gen1BackupHex))
	require.Empty(t, r.Err)
	vaults, _, activeGen = loadVaults(t, &ct, contractId)
	require.Equal(t, mapping.VaultStatusPending, vaults[1].Status, "gen-1 stays pending until explicit activate")
	require.Equal(t, uint32(0), activeGen)
	require.Equal(t, decodeHex(t, Gen1PrimaryHex), string(vaults[1].Primary[:]))
	require.Equal(t, decodeHex(t, TestPrimaryPubKeyHex), ct.StateGet(contractId, constants.PrimaryPublicKeyStateKey), "gen-1 registration must NOT clobber gen-0 flat keys")

	r = callKeyAction(t, &ct, contractId, owner, "activateKey", []byte(""))
	require.Empty(t, r.Err)
	vaults, _, activeGen = loadVaults(t, &ct, contractId)
	require.Equal(t, mapping.VaultStatusRetiring, vaults[0].Status, "predecessor gen-0 retires")
	require.Equal(t, mapping.VaultStatusActive, vaults[1].Status)
	require.Equal(t, uint32(1), activeGen)
	require.Equal(t, decodeHex(t, TestPrimaryPubKeyHex), string(vaults[0].Primary[:]), "retiring gen-0 STILL holds its keys (can still sweep)")
}

// TestMintRefusesSecondPending — at most one keygen in flight: a second createKey
// while a pending vault exists must abort, leaving the list unchanged.
func TestMintRefusesSecondPending(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	seedActiveGen0(t, &ct, contractId, owner)

	r := callKeyAction(t, &ct, contractId, owner, "createKey", []byte(""))
	require.Empty(t, r.Err)
	r = callKeyAction(t, &ct, contractId, owner, "createKey", []byte(""))
	require.NotEmpty(t, r.Err, "second createKey must abort while a pending keygen exists")
	vaults, nextGen, _ := loadVaults(t, &ct, contractId)
	require.Len(t, vaults, 2, "no third vault appended")
	require.Equal(t, uint32(2), nextGen, "nextGen not advanced by the refused mint")
}

// TestActivateRefusesIncompleteKeygen — activate must abort when the pending vault
// has no keys yet, leaving the live gen-0 active.
func TestActivateRefusesIncompleteKeygen(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	seedActiveGen0(t, &ct, contractId, owner)

	r := callKeyAction(t, &ct, contractId, owner, "createKey", []byte(""))
	require.Empty(t, r.Err)
	r = callKeyAction(t, &ct, contractId, owner, "activateKey", []byte(""))
	require.NotEmpty(t, r.Err, "activate must abort when the pending vault has no keys")
	vaults, _, activeGen := loadVaults(t, &ct, contractId)
	require.Equal(t, mapping.VaultStatusActive, vaults[0].Status, "gen-0 stays active")
	require.Equal(t, mapping.VaultStatusPending, vaults[1].Status)
	require.Equal(t, uint32(0), activeGen)
}

// TestActivateRefusesBrokenLineage — a pending vault whose predecessor does NOT
// match the active generation must not activate (NN#12). Injected directly to model
// a rogue successor a thief might try to slip in.
func TestActivateRefusesBrokenLineage(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	seedActiveGen0(t, &ct, contractId, owner)

	vaults, _, _ := loadVaults(t, &ct, contractId)
	bad := mapping.Vault{Generation: 1, Status: mapping.VaultStatusPending, Predecessor: 5} // wrong: should be 0
	copy(bad.Primary[:], decodeHex(t, Gen1PrimaryHex))
	copy(bad.Backup[:], decodeHex(t, Gen1BackupHex))
	vaults = append(vaults, bad)
	ct.StateSet(contractId, constants.VaultRegistryKey, string(mapping.MarshalVaultRegistry(vaults)))
	ct.StateSet(contractId, constants.VaultNextGenKey, u32be(2))

	r := callKeyAction(t, &ct, contractId, owner, "activateKey", []byte(""))
	require.NotEmpty(t, r.Err, "activate must abort on broken lineage (predecessor 5 != active gen 0)")
	vaults, _, activeGen := loadVaults(t, &ct, contractId)
	require.Equal(t, mapping.VaultStatusActive, vaults[0].Status, "gen-0 stays active after refused activation")
	require.Equal(t, uint32(0), activeGen)
}

// TestDiscardPendingReMintMonotonic — discard a stalled keygen, then re-mint gets a
// FRESH generation number (never reuses the discarded one) — a partially-completed
// keygen can't collide with the new one.
func TestDiscardPendingReMintMonotonic(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	seedActiveGen0(t, &ct, contractId, owner)

	r := callKeyAction(t, &ct, contractId, owner, "createKey", []byte(""))
	require.Empty(t, r.Err)
	_, nextGen, _ := loadVaults(t, &ct, contractId)
	require.Equal(t, uint32(2), nextGen)

	r = callKeyAction(t, &ct, contractId, owner, "discardPendingKey", []byte(""))
	require.Empty(t, r.Err)
	vaults, nextGen, _ := loadVaults(t, &ct, contractId)
	require.Len(t, vaults, 1, "pending gen-1 discarded")
	require.Equal(t, mapping.VaultStatusActive, vaults[0].Status, "active gen-0 untouched")
	require.Equal(t, uint32(2), nextGen, "nextGen NOT rolled back (monotonic)")

	r = callKeyAction(t, &ct, contractId, owner, "createKey", []byte(""))
	require.Empty(t, r.Err)
	vaults, nextGen, _ = loadVaults(t, &ct, contractId)
	require.Len(t, vaults, 2)
	require.Equal(t, uint32(2), vaults[1].Generation, "re-mint gets a FRESH gen number, never reuses gen-1")
	require.Equal(t, uint32(3), nextGen)
}

// TestDiscardRefusesNoPending — discard must abort when there is no pending vault,
// never touching an active/retiring (fund-holding) vault.
func TestDiscardRefusesNoPending(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	seedActiveGen0(t, &ct, contractId, owner)

	r := callKeyAction(t, &ct, contractId, owner, "discardPendingKey", []byte(""))
	require.NotEmpty(t, r.Err, "discard must abort when there is no pending vault")
	vaults, _, _ := loadVaults(t, &ct, contractId)
	require.Len(t, vaults, 1)
	require.Equal(t, mapping.VaultStatusActive, vaults[0].Status, "active gen-0 untouched by refused discard")
}

// TestRenewKeyUsesActiveGen — after a rotation renewKey renews the ACTIVE gen's key
// (main-v1), not the retiring legacy "main".
func TestRenewKeyUsesActiveGen(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	seedActiveGen0(t, &ct, contractId, owner)

	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, Gen1BackupHex)).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "activateKey", []byte("")).Err)

	r := callKeyAction(t, &ct, contractId, owner, "renewKey", []byte(""))
	require.Empty(t, r.Err)
	require.Contains(t, r.Ret, "mainv1", "renewKey must renew the ACTIVE gen's key, not the retiring main")
}
