package current_test

import (
	"encoding/hex"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Four distinct, valid compressed secp256k1 points: the pair an operator MEANT to
// register, and the pair they registered by mistake.
const (
	wrongPrimaryHex = "0242f9da15eae56fe6aca65136738905c0afdb2c4edf379e107b3b00b98c7fc9f0"
	wrongBackupHex  = "0332e9f22cfa2f6233c059c4d54700e3d00df3d7f55e3ea16207b860360446634f"
)

// hexOf renders raw key bytes the way the test constants are written.
func hexOf(b []byte) string { return hex.EncodeToString(b) }

func registerKeys(t *testing.T, ct *test_utils.ContractTest, contractId, owner, txId, primaryHex, backupHex string) test_utils.ContractTestCallResult {
	t.Helper()
	return ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: txId, BlockId: "block:vr221", Index: 0, OpIndex: 0,
			Timestamp: "2026-09-07T00:00:00", RequiredAuths: []string{owner},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId, Action: "registerPublicKey",
		Payload: []byte(`{"primary_public_key":"` + primaryHex + `","backup_public_key":"` + backupHex + `"}`),
		RcLimit: 1000000, Intents: []contracts.Intent{}, Caller: owner,
	})
}

// loadGen0 returns the lone vault-list entry, failing the test if the list does not
// hold exactly one.
func loadGen0(t *testing.T, ct *test_utils.ContractTest, contractId string) mapping.Vault {
	t.Helper()
	raw := ct.StateGet(contractId, constants.VaultRegistryKey)
	require.NotEmpty(t, raw, "vault registry should be populated")
	vaults, err := mapping.UnmarshalVaultRegistry([]byte(raw))
	require.NoError(t, err)
	require.Len(t, vaults, 1, "expected exactly one vault (generation 0)")
	return vaults[0]
}

// VR2-21 regression: on a contract that provably holds NO value, an operator who
// registered the WRONG vault key pair can still correct it — and the correction
// reaches generation 0, not just the legacy flat slots.
//
// Background. `FoldLegacyGen0IfNeeded` runs at the top of every key-ceremony op. It
// freezes whatever flat key pair happens to exist into vaults[0] as Active with a
// self-referential predecessor, and `IntializeContractState` then resolves the
// contract's public keys FROM the vault list. The fold was written as a migration
// primitive — adopt an existing funded vault's real key pair — but it fires on ANY
// second registration, including the "I typed the wrong key, let me fix it before we
// go live" case. It fires FIRST, on the correction call itself, so the corrected flat
// key that gets written afterwards is dead state: the vault list already won.
//
// The backup key is the half with no escape at all. A rotation cannot introduce a new
// backup: MintNextGeneration pins every successor's backup to the active vault's
// (the F1 fix, vault_lifecycle.go:255-262) and RegisterVaultKeys then rejects any
// different backup as immutable. So a wrong backup folded into generation 0 is
// inherited by EVERY future generation, permanently. The wrong PRIMARY can at least
// be rotated out; the wrong backup cannot.
//
// The fix does not weaken the fold — it still fires, and still adopts a funded
// vault's keys byte-identically. It replaces the build-flag escape on the key writes
// with a question about value: while the contract holds no UTXOs and no supply,
// nobody's coins ride on the current pair, so the pair is still correctable, on every
// network including mainnet. The moment any value exists, the keys freeze.
func TestVR221_WrongGenesisKeysAreCorrectableWhileNoValueIsAtRisk(t *testing.T) {
	const contractId = "vr221_fresh"
	const owner = "hive:milo-hpr"

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	ct.RegisterContract(contractId, owner, ContractWasm)

	// A fresh deploy: fee rate configured, but no UTXOs and no supply.
	ct.StateSet(contractId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))

	// The TSS ceremony ran and produced the key the operator MEANT to register.
	// This is the realistic shape of the mistake: the true key exists, and what got
	// typed into registerPublicKey does not match it.
	seedTssKey(t, &ct, contractId, mapping.VaultKeyId(0), TestPrimaryPubKeyHex)

	// The mistake.
	first := registerKeys(t, &ct, contractId, owner, "vr2-21-wrong", wrongPrimaryHex, wrongBackupHex)
	require.True(t, first.Success, "first registration should succeed; err=%q msg=%q", first.Err, first.ErrMsg)
	require.Equal(t, decodeHex(t, wrongPrimaryHex), ct.StateGet(contractId, constants.PrimaryPublicKeyStateKey),
		"fixture precondition: the wrong primary must be the registered one")

	// The correction. This is the call that folds today.
	second := registerKeys(t, &ct, contractId, owner, "vr2-21-correct", TestPrimaryPubKeyHex, TestBackupPubKeyHex)
	require.True(t, second.Success, "correction should succeed; err=%q msg=%q", second.Err, second.ErrMsg)

	// ASSERTION 1 — the flat slots carry the corrected pair.
	assert.Equal(t, decodeHex(t, TestPrimaryPubKeyHex), ct.StateGet(contractId, constants.PrimaryPublicKeyStateKey),
		"flat primary should be corrected")
	assert.Equal(t, decodeHex(t, TestBackupPubKeyHex), ct.StateGet(contractId, constants.BackupPublicKeyStateKey),
		"flat backup should be corrected")

	// ASSERTION 2 — and so does generation 0, which is what address derivation and
	// every future generation actually read. Without this the correction is cosmetic.
	gen0 := loadGen0(t, &ct, contractId)
	assert.Equal(t, decodeHex(t, TestPrimaryPubKeyHex), string(gen0.Primary[:]),
		"generation 0 must carry the CORRECTED primary, not the frozen mistake")
	assert.Equal(t, decodeHex(t, TestBackupPubKeyHex), string(gen0.Backup[:]),
		"generation 0 must carry the CORRECTED backup — this is the half a rotation "+
			"can never fix, because every successor inherits the active vault's backup")
}

// The guard. Once the contract holds value, the key pair is frozen on every network:
// coins are riding on the addresses derived from it, and re-pointing would strand
// them. This is the property that makes the correction path safe to allow at all,
// so it is asserted as its own case rather than trusted.
func TestVR221_KeysFreezeOnceTheContractHoldsValue(t *testing.T) {
	const contractId = "vr221_funded"
	const owner = "hive:milo-hpr"

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	ct.RegisterContract(contractId, owner, ContractWasm)

	ct.StateSet(contractId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))

	first := registerKeys(t, &ct, contractId, owner, "vr2-21-funded-first", wrongPrimaryHex, wrongBackupHex)
	require.True(t, first.Success, "first registration should succeed; err=%q msg=%q", first.Err, first.ErrMsg)

	// Someone deposited. The vault now backs real coins.
	ct.StateSet(contractId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{
			ActiveSupply: 500_000, UserSupply: 500_000, BaseFeeRate: 1,
		})))

	second := registerKeys(t, &ct, contractId, owner, "vr2-21-funded-second", TestPrimaryPubKeyHex, TestBackupPubKeyHex)
	require.True(t, second.Success, "a refused re-registration reports, it does not abort")
	assert.Contains(t, second.Ret, "already registered",
		"the refusal must be reported, not silent")

	assert.Equal(t, decodeHex(t, wrongPrimaryHex), ct.StateGet(contractId, constants.PrimaryPublicKeyStateKey),
		"a funded contract's flat primary must be immutable")
	assert.Equal(t, decodeHex(t, wrongBackupHex), ct.StateGet(contractId, constants.BackupPublicKeyStateKey),
		"a funded contract's flat backup must be immutable")

	gen0 := loadGen0(t, &ct, contractId)
	assert.Equal(t, decodeHex(t, wrongPrimaryHex), string(gen0.Primary[:]),
		"a funded contract's generation 0 must be immutable — coins are riding on it")
	assert.Equal(t, decodeHex(t, wrongBackupHex), string(gen0.Backup[:]),
		"a funded contract's generation 0 backup must be immutable")
}

// The gate that keeps the correction path from becoming a key-substitution
// primitive.
//
// "Currently holds no value" is a point-in-time fact, not "was never used". A
// live, never-rotated vault sits at exactly one Active genesis generation, and it
// transiently reaches zero UTXOs and zero supply every time the last outstanding
// withdrawal clears. Without this gate that window would let the owner key swap
// the vault's spending primary for a self-generated one — and the deposit script
// is a bare OP_IF <primary> OP_CHECKSIG, so Bitcoin has no notion of "this pubkey
// must belong to a TSS quorum". Every subsequent deposit would be unilaterally
// spendable by whoever supplied the replacement.
//
// That would be a strictly new capability, and the wrong kind: rotation already
// exists and routes through attestPrimaryKey, so it CANNOT introduce an unattested
// primary. The correction path must not become the exception.
//
// A generation whose primary IS the ceremony output is therefore frozen outright.
func TestVR221_ACeremonyBackedGenesisKeyIsNeverCorrectable(t *testing.T) {
	const contractId = "vr221_tssbacked"
	const owner = "hive:milo-hpr"

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	ct.RegisterContract(contractId, owner, ContractWasm)

	ct.StateSet(contractId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))

	// The post-fold mainnet shape: gen-0 Active, its primary IS the ceremony output.
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	ct.StateSet(contractId, constants.MigrateVersionKey, "1")
	seedTssKey(t, &ct, contractId, mapping.VaultKeyId(0), TestPrimaryPubKeyHex)
	require.Empty(t, callMigrate(t, &ct, contractId, owner).Err, "fold should succeed")

	seeded := loadGen0(t, &ct, contractId)
	require.Equal(t, TestPrimaryPubKeyHex, hexOf(seeded.Primary[:]),
		"fixture precondition: gen-0 must agree with the ceremony output")

	// The contract holds nothing, so the value gate alone would permit this.
	swap := registerKeys(t, &ct, contractId, owner, "vr2-21-tss-swap", wrongPrimaryHex, wrongBackupHex)
	require.True(t, swap.Success, "a refused correction reports, it does not abort")

	gen0 := loadGen0(t, &ct, contractId)
	assert.Equal(t, TestPrimaryPubKeyHex, hexOf(gen0.Primary[:]),
		"a ceremony-backed generation's primary must NEVER be swapped; an empty "+
			"balance is not permission to re-point the vault's spending key")
	assert.Equal(t, TestBackupPubKeyHex, hexOf(gen0.Backup[:]),
		"and its backup must not be swapped either — the CSV branch is a spending path too")
	assert.NotContains(t, swap.Ret, "generation 0 corrected",
		"the refusal must not report a correction it did not make")
}

// Where a ceremony output exists, the ONLY correction permitted is the one that
// makes the generation agree with it. An operator who mistyped cannot use the
// correction path to install some third key of their choosing.
func TestVR221_CorrectionMustAgreeWithTheCeremonyOutput(t *testing.T) {
	const contractId = "vr221_thirdkey"
	const owner = "hive:milo-hpr"

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	ct.RegisterContract(contractId, owner, ContractWasm)

	ct.StateSet(contractId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	seedTssKey(t, &ct, contractId, mapping.VaultKeyId(0), TestPrimaryPubKeyHex)

	first := registerKeys(t, &ct, contractId, owner, "vr2-21-third-first", wrongPrimaryHex, wrongBackupHex)
	require.True(t, first.Success, "first registration should succeed; err=%q msg=%q", first.Err, first.ErrMsg)

	// A third key: neither what was registered nor what the ceremony produced.
	const thirdPrimaryHex = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	second := registerKeys(t, &ct, contractId, owner, "vr2-21-third-swap", thirdPrimaryHex, wrongBackupHex)
	require.True(t, second.Success, "a refused correction reports, it does not abort")

	gen0 := loadGen0(t, &ct, contractId)
	assert.Equal(t, wrongPrimaryHex, hexOf(gen0.Primary[:]),
		"the correction path may only make a generation AGREE with its ceremony "+
			"output; it must not install an arbitrary third key")
}

// VR2-21, second gap — found by the devnet campaign, not by reading.
//
// The value gate alone is not enough. Once the genesis generation has ACTIVATED
// there is no pending vault left, so RegisterVaultKeys returns a clean no-op
// rather than refusing, and on an empty contract the value gate permits the
// write. A second registerPublicKey with a different key therefore overwrote the
// flat slot while the vault list kept the real one.
//
// That divergence is not cosmetic. The devnet ledger recorded exactly this state
// as leaving a generation unactivatable even after the correct key was restored:
// the vault list is the source of truth for address derivation, but a flat slot
// disagreeing with it poisons activation downstream. On a mainnet build the flat
// slots were never rewritable, so the bug was invisible there — which is why it
// took a regtest devnet run to surface it, and is the same
// testnet-cannot-prove-what-mainnet-enforces shape as VR2-20.
func TestVR221_FlatKeyCannotDisagreeWithTheActiveGeneration(t *testing.T) {
	const contractId = "vr221_flatdiverge"
	const owner = "hive:milo-hpr"

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	ct.RegisterContract(contractId, owner, ContractWasm)

	ct.StateSet(contractId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))

	// An ACTIVE generation 0 holding the real pair, with the flat slots mirroring
	// it — the state a completed genesis bring-up leaves behind.
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	ct.StateSet(contractId, constants.MigrateVersionKey, "1")
	seedTssKey(t, &ct, contractId, mapping.VaultKeyId(0), TestPrimaryPubKeyHex)
	require.Empty(t, callMigrate(t, &ct, contractId, owner).Err, "fold should succeed")
	activeGen := loadGen0(t, &ct, contractId)
	require.Equal(t, TestPrimaryPubKeyHex, hexOf(activeGen.Primary[:]),
		"fixture precondition: an Active generation holds the real pair")

	// The contract is empty, so the VALUE gate alone would allow this write.
	r := registerKeys(t, &ct, contractId, owner, "vr2-21-flat-diverge", wrongPrimaryHex, wrongBackupHex)
	require.True(t, r.Success, "a refused write reports, it does not abort")

	assert.Equal(t, decodeHex(t, TestPrimaryPubKeyHex),
		ct.StateGet(contractId, constants.PrimaryPublicKeyStateKey),
		"the flat primary must not be allowed to disagree with the active generation")
	assert.Equal(t, decodeHex(t, TestBackupPubKeyHex),
		ct.StateGet(contractId, constants.BackupPublicKeyStateKey),
		"nor the flat backup")

	// Re-registering the SAME pair stays a legitimate no-op: mirroring is allowed,
	// only disagreement is refused.
	same := registerKeys(t, &ct, contractId, owner, "vr2-21-flat-mirror", TestPrimaryPubKeyHex, TestBackupPubKeyHex)
	require.True(t, same.Success, "re-registering the identical pair must remain accepted")
	assert.Equal(t, decodeHex(t, TestPrimaryPubKeyHex),
		ct.StateGet(contractId, constants.PrimaryPublicKeyStateKey))
}
