package current_test

// SHADOW fix. Before it, HandleMigrateVault targeted the FIRST Retiring vault, else the
// FIRST Draining vault, even when that generation held nothing, so an empty older
// superseded generation shadowed a funded newer one ("nothing to migrate for generation
// <old>", nil error) and the newer generation's funds never moved. An empty RETIRING
// generation also had no way out of RETIRING, so it was never purged and its committee's
// consensus bonds stayed locked. The fix targets the first FUNDED superseded generation,
// and retireVault moves an empty RETIRING generation to INACTIVE like an empty DRAINING
// one.

import (
	"strconv"
	"strings"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"github.com/stretchr/testify/require"

	"vsc-node/lib/test_utils"
)

const shadowGen2PrimaryHex = "0242f9da15eae56fe6aca65136738905c0afdb2c4edf379e107b3b00b98c7fc9f0"

const shadowNothingGen0 = "nothing to migrate for generation 0"

// newOneRotationCT rotates gen-0 (holding exactly `gen0`, possibly nothing) out through
// the real ops: gen-0 RETIRING, gen-1 ACTIVE, and a fee reserve on gen-1.
func newOneRotationCT(t *testing.T, gen0 []utxoSeed) (*test_utils.ContractTest, string, string) {
	t.Helper()
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "102")
	seedActiveGen0(t, &ct, contractId, owner)
	if len(gen0) > 0 {
		seedGenUtxos(t, &ct, contractId, 0, gen0)
		var total int64
		for _, s := range gen0 {
			total += s.amount
		}
		ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
			ActiveSupply: total, UserSupply: total, BaseFeeRate: 1,
		})))
	}
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	r := callKeyAction(t, &ct, contractId, owner, "activateKey", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	vaults, _, activeGen := loadVaults(t, &ct, contractId)
	require.Equal(t, uint32(1), activeGen)
	require.Equal(t, mapping.VaultStatusRetiring, vaultByGen(t, vaults, 0).Status)
	seedReserve(t, &ct, contractId, 1, h2ReserveId, 100_000)
	return &ct, contractId, owner
}

// newShadowCT rotates twice through the real ops with gen-0 empty the whole time: gen-0
// retires holding nothing, users fund gen-1, NN#3 admits the gen-2 createKey (it counts
// funds, and gen-0 has none), and gen-2 activates. It ends with gen-0 RETIRING (empty),
// gen-1 RETIRING (two 900k UTXOs, so the 1M canary tranche takes one), gen-2 ACTIVE, and
// a fee reserve on gen-2.
func newShadowCT(t *testing.T) (*test_utils.ContractTest, string, string) {
	t.Helper()
	return newShadowCTWith(t, []utxoSeed{{1100, 900_000}, {1101, 900_000}})
}

// newShadowCTWith is newShadowCT with gen-1 holding exactly `gen1` (possibly nothing).
func newShadowCTWith(t *testing.T, gen1 []utxoSeed) (*test_utils.ContractTest, string, string) {
	t.Helper()
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "102")
	seedActiveGen0(t, &ct, contractId, owner)
	seedTssKey(t, &ct, contractId, "mainv2", shadowGen2PrimaryHex)

	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	r := callKeyAction(t, &ct, contractId, owner, "activateKey", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)

	if len(gen1) > 0 {
		seedGenUtxos(t, &ct, contractId, 1, gen1)
		var total int64
		for _, s := range gen1 {
			total += s.amount
		}
		ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
			ActiveSupply: total, UserSupply: total, BaseFeeRate: 1,
		})))
	}

	r = callKeyAction(t, &ct, contractId, owner, "createKey", []byte(""))
	require.Empty(t, r.Err, "NN#3 must admit the next rotation while the superseded gen-0 is empty: %s", r.ErrMsg)
	r = callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, shadowGen2PrimaryHex, ""))
	require.Empty(t, r.Err, r.ErrMsg)
	r = callKeyAction(t, &ct, contractId, owner, "activateKey", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)

	vaults, _, activeGen := loadVaults(t, &ct, contractId)
	require.Equal(t, uint32(2), activeGen)
	require.Equal(t, mapping.VaultStatusRetiring, vaultByGen(t, vaults, 0).Status)
	require.Equal(t, mapping.VaultStatusRetiring, vaultByGen(t, vaults, 1).Status)
	seedReserve(t, &ct, contractId, 2, h2ReserveId, 100_000)
	return &ct, contractId, owner
}

func setGenStatus(t *testing.T, ct *test_utils.ContractTest, contractId string, gen uint32, st mapping.VaultStatus) {
	t.Helper()
	vaults, _, _ := loadVaults(t, ct, contractId)
	for i := range vaults {
		if vaults[i].Generation == gen {
			vaults[i].Status = st
		}
	}
	ct.StateSet(contractId, constants.VaultRegistryKey, string(mapping.MarshalVaultRegistry(vaults)))
}

func gen1Ids(t *testing.T, ct *test_utils.ContractTest, contractId string) []uint16 {
	t.Helper()
	var out []uint16
	for id := range registryIds(t, ct, contractId) {
		if id == 1100 || id == 1101 {
			out = append(out, id)
		}
	}
	return out
}

// appendGenUtxo adds one UTXO tagged to gen, as a matched deposit would, and credits it to
// ActiveSupply/UserSupply so I1 and I2 still hold.
func appendGenUtxo(t *testing.T, ct *test_utils.ContractTest, contractId string, gen uint32, id uint16, amount int64) {
	t.Helper()
	var reg mapping.UtxoRegistry
	if raw := ct.StateGet(contractId, constants.UtxoRegistryKey); len(raw) > 0 {
		r, err := mapping.UnmarshalUtxoRegistry([]byte(raw))
		require.NoError(t, err)
		reg = r
	}
	reg = append(reg, mapping.UtxoRegistryEntry{Id: id, Amount: amount})
	u := mapping.Utxo{TxId: strings.Repeat("cd", 32), Vout: uint32(id), Amount: amount, Generation: gen}
	blob := mapping.MarshalUtxo(&u)
	require.NotNil(t, blob)
	ct.StateSet(contractId, constants.UtxoPrefix+strconv.FormatUint(uint64(id), 16), string(blob))
	ct.StateSet(contractId, constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(reg)))
	sup := loadSupply(t, ct, contractId)
	sup.ActiveSupply += amount
	sup.UserSupply += amount
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&sup)))
}

func lastHeight(t *testing.T, ct *test_utils.ContractTest, contractId string) uint32 {
	t.Helper()
	h, err := strconv.ParseUint(ct.StateGet(contractId, constants.LastHeightKey), 10, 32)
	require.NoError(t, err)
	return uint32(h)
}

// stateSnapshot is every key the fail-closed tests require to be byte-identical.
func stateSnapshot(ct *test_utils.ContractTest, contractId string) [4]string {
	return [4]string{
		ct.StateGet(contractId, constants.VaultRegistryKey),
		ct.StateGet(contractId, constants.UtxoRegistryKey),
		ct.StateGet(contractId, constants.SupplyKey),
		ct.StateGet(contractId, constants.VaultActiveGenKey),
	}
}

// Control: with gen-0 PURGED the same state sweeps gen-1 (unchanged by the fix).
func TestSHADOWFIX_Control_Gen1SweepsWithoutGen0(t *testing.T) {
	ct, cid, owner := newShadowCT(t)
	setGenStatus(t, ct, cid, 0, mapping.VaultStatusPurged)
	r := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	require.NotEmpty(t, ct.StateGet(cid, constants.TxSpendsPrefix+r.Ret))
	vaults, _, _ := loadVaults(t, ct, cid)
	require.Equal(t, mapping.VaultStatusDraining, vaultByGen(t, vaults, 1).Status)
}

// RETIRING variant, end to end: gen-1 drains past the empty RETIRING gen-0 (canary, then
// bulk), both sweeps settle, retireVault moves both emptied gens to INACTIVE, and at the
// grace boundary to PURGED. Conservation holds throughout.
func TestSHADOWFIX_RetiringVariant_DrainsAndFinalizes(t *testing.T) {
	ct, cid, owner := newShadowCT(t)

	canary := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
	require.Empty(t, canary.Err, canary.ErrMsg)
	require.NotEqual(t, shadowNothingGen0, canary.Ret, "gen-1 is the first FUNDED retiring gen")
	require.Len(t, readSweepRecord(t, ct, cid, canary.Ret).InputIds, 1, "the 1M canary takes one 900k input")
	vaults, _, _ := loadVaults(t, ct, cid)
	require.Equal(t, mapping.VaultStatusRetiring, vaultByGen(t, vaults, 0).Status, "the empty gen-0 is skipped, not touched")
	require.Equal(t, mapping.VaultStatusDraining, vaultByGen(t, vaults, 1).Status)

	bulk := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
	require.Empty(t, bulk.Err, bulk.ErrMsg)
	require.NotEqual(t, shadowNothingGen0, bulk.Ret, "the bulk tranche builds past the empty gen-0")
	require.NotEqual(t, canary.Ret, bulk.Ret)

	require.True(t, confirmMigrationSweep(t, ct, cid, owner, canary.Ret, 200).Success)
	require.True(t, confirmMigrationSweep(t, ct, cid, owner, bulk.Ret, 210).Success)
	require.Empty(t, gen1Ids(t, ct, cid), "gen-1 fully drained")
	i1Holds(t, ct, cid)

	r := callKeyAction(t, ct, cid, owner, "retireVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	h := lastHeight(t, ct, cid)
	vaults, _, _ = loadVaults(t, ct, cid)
	require.Equal(t, mapping.VaultStatusInactive, vaultByGen(t, vaults, 0).Status, "R1: the empty RETIRING gen-0 now leaves RETIRING")
	require.Equal(t, h, vaultByGen(t, vaults, 0).InactiveHeight)
	require.Equal(t, mapping.VaultStatusInactive, vaultByGen(t, vaults, 1).Status)

	setHeight(ct, cid, h+constants.VaultPurgeGraceBlocks)
	r = callKeyAction(t, ct, cid, owner, "retireVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	vaults, _, _ = loadVaults(t, ct, cid)
	require.Equal(t, mapping.VaultStatusPurged, vaultByGen(t, vaults, 0).Status, "purged at grace, so its committee's bonds release")
	require.Equal(t, mapping.VaultStatusPurged, vaultByGen(t, vaults, 1).Status)
	require.Equal(t, mapping.VaultStatusActive, vaultByGen(t, vaults, 2).Status)
	i1Holds(t, ct, cid)
}

// DRAINING variant (the KPX F3 devnet state): gen-0 drained but never retired. The second
// tranche, which the empty DRAINING gen-0 used to shadow, now builds gen-1's bulk.
func TestSHADOWFIX_DrainingVariant_BulkBuilds(t *testing.T) {
	ct, cid, owner := newShadowCT(t)
	setGenStatus(t, ct, cid, 0, mapping.VaultStatusDraining)

	canary := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
	require.Empty(t, canary.Err, canary.ErrMsg)
	require.NotEqual(t, shadowNothingGen0, canary.Ret)

	bulk := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
	require.Empty(t, bulk.Err, bulk.ErrMsg)
	require.NotEqual(t, shadowNothingGen0, bulk.Ret, "the empty DRAINING gen-0 no longer shadows gen-1")
	require.NotEqual(t, canary.Ret, bulk.Ret)
	require.NotEmpty(t, ct.StateGet(cid, constants.TxSpendsPrefix+bulk.Ret))
	vaults, _, _ := loadVaults(t, ct, cid)
	require.Equal(t, mapping.VaultStatusDraining, vaultByGen(t, vaults, 0).Status, "the empty gen-0 is skipped, not touched")
}

// R1 grace gate: a lone empty RETIRING gen goes to INACTIVE, stays INACTIVE one block short
// of the grace window, and purges exactly at it.
func TestSHADOWFIX_R1_EmptyRetiringGenPurgesOnGrace(t *testing.T) {
	ct, cid, owner := newOneRotationCT(t, nil)
	r := callKeyAction(t, ct, cid, owner, "retireVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	h := lastHeight(t, ct, cid)
	vaults, _, _ := loadVaults(t, ct, cid)
	require.Equal(t, mapping.VaultStatusInactive, vaultByGen(t, vaults, 0).Status)
	require.Equal(t, h, vaultByGen(t, vaults, 0).InactiveHeight)

	setHeight(ct, cid, h+constants.VaultPurgeGraceBlocks-1)
	require.Empty(t, callKeyAction(t, ct, cid, owner, "retireVault", []byte("")).Err)
	vaults, _, _ = loadVaults(t, ct, cid)
	require.Equal(t, mapping.VaultStatusInactive, vaultByGen(t, vaults, 0).Status, "one block short of grace: still matchable")

	setHeight(ct, cid, h+constants.VaultPurgeGraceBlocks)
	require.Empty(t, callKeyAction(t, ct, cid, owner, "retireVault", []byte("")).Err)
	vaults, _, _ = loadVaults(t, ct, cid)
	require.Equal(t, mapping.VaultStatusPurged, vaultByGen(t, vaults, 0).Status)
}

// R1 match-until-purged: a late deposit to the formerly-RETIRING, now INACTIVE gen-0 makes
// retireVault revert it to DRAINING, and migrateVault then sweeps it to the active gen.
func TestSHADOWFIX_R1_LateDepositRevertsAndSweeps(t *testing.T) {
	ct, cid, owner := newOneRotationCT(t, nil)
	require.Empty(t, callKeyAction(t, ct, cid, owner, "retireVault", []byte("")).Err)
	vaults, _, _ := loadVaults(t, ct, cid)
	require.Equal(t, mapping.VaultStatusInactive, vaultByGen(t, vaults, 0).Status)

	appendGenUtxo(t, ct, cid, 0, 1300, 500_000)
	require.Empty(t, callKeyAction(t, ct, cid, owner, "retireVault", []byte("")).Err)
	vaults, _, _ = loadVaults(t, ct, cid)
	require.Equal(t, mapping.VaultStatusDraining, vaultByGen(t, vaults, 0).Status, "re-funded INACTIVE reverts to DRAINING")
	require.Equal(t, uint32(0), vaultByGen(t, vaults, 0).InactiveHeight, "the grace anchor resets")

	r := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	require.NotEqual(t, shadowNothingGen0, r.Ret)
	require.Equal(t, []uint16{1300}, readSweepRecord(t, ct, cid, r.Ret).InputIds)
}

// R1 negative: retireVault never moves a FUNDED RETIRING gen (its first tranche does).
func TestSHADOWFIX_R1_FundedRetiringGenUntouched(t *testing.T) {
	ct, cid, owner := newOneRotationCT(t, []utxoSeed{{1100, 900_000}})
	r := callKeyAction(t, ct, cid, owner, "retireVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	vaults, _, _ := loadVaults(t, ct, cid)
	require.Equal(t, mapping.VaultStatusRetiring, vaultByGen(t, vaults, 0).Status)
	require.Equal(t, uint32(0), vaultByGen(t, vaults, 0).InactiveHeight)
}

// Named residual, out of scope: a RETIRING gen funded ONLY by an input reserved for an
// in-flight unmap counts as funded, so retireVault leaves it RETIRING and migrateVault
// selects it and finds nothing. After F1 a fresh deploy cannot reach this (activation is
// refused while the active gen has an in-flight unmap); it needs pre-F1 legacy state.
// Recorded so a change to it is seen.
func TestSHADOWFIX_Residual_ReservedOnlyRetiringGen(t *testing.T) {
	ct, cid, owner := newOneRotationCT(t, []utxoSeed{{1100, 900_000}})
	ct.StateSet(cid, constants.ReservedUtxoPrefix+strconv.FormatUint(1100, 10), "1")
	require.Empty(t, callKeyAction(t, ct, cid, owner, "retireVault", []byte("")).Err)
	vaults, _, _ := loadVaults(t, ct, cid)
	require.Equal(t, mapping.VaultStatusRetiring, vaultByGen(t, vaults, 0).Status)
	r := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	require.Equal(t, shadowNothingGen0, r.Ret)
}

// The bot reads both terminal answers (isNothingToMigrate): the hard error with no
// superseded gen at all, and the benign no-op when every superseded gen is empty.
func TestSHADOWFIX_TerminalStringsUnchanged(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	cid, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(cid, owner, ContractWasm)
	ct.StateSet(cid, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(cid, constants.LastHeightKey, "102")
	seedActiveGen0(t, &ct, cid, owner)
	r := callKeyAction(t, &ct, cid, owner, "migrateVault", []byte(""))
	require.NotEmpty(t, r.Err)
	require.Contains(t, r.ErrMsg, "no retiring or draining vault to migrate")

	// One superseded gen, empty: the registry scan is skipped and the gen is selected as before.
	ct2, cid2, owner2 := newOneRotationCT(t, nil)
	r = callKeyAction(t, ct2, cid2, owner2, "migrateVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	require.Equal(t, shadowNothingGen0, r.Ret)

	// Two superseded gens, both empty: the scan finds no funded target and falls back.
	ct3, cid3, owner3 := newShadowCTWith(t, nil)
	r = callKeyAction(t, ct3, cid3, owner3, "migrateVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	require.Equal(t, shadowNothingGen0, r.Ret)
}

// Fail-closed: a registry entry whose blob is missing aborts migrateVault and retireVault
// with an error and changes nothing.
func TestSHADOWFIX_FailClosed_MissingUtxoBlob(t *testing.T) {
	ct, cid, owner := newShadowCT(t)
	ct.StateSet(cid, constants.UtxoPrefix+strconv.FormatUint(1101, 16), "")
	before := stateSnapshot(ct, cid)

	r := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
	require.NotEmpty(t, r.Err, "a missing blob must abort, not skip")
	t.Logf("migrateVault abort: %s", r.ErrMsg)
	require.Equal(t, before, stateSnapshot(ct, cid))

	r = callKeyAction(t, ct, cid, owner, "retireVault", []byte(""))
	require.NotEmpty(t, r.Err)
	t.Logf("retireVault abort: %s", r.ErrMsg)
	require.Equal(t, before, stateSnapshot(ct, cid))
}

// R2: gas in the shadow state (two superseded gens, so the fix runs its registry scan), and
// of retireVault (the same full-registry scan), at N extra active-gen registry entries.
func TestSHADOWFIX_Gas(t *testing.T) {
	for _, n := range []int{0, 200, 1000} {
		ct, cid, owner := newShadowCT(t)
		for i := 0; i < n; i++ {
			appendGenUtxo(t, ct, cid, 2, uint16(3000+i), 10_000)
		}
		mv := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
		rv := callKeyAction(t, ct, cid, owner, "retireVault", []byte(""))
		t.Logf("N=%d migrateVault gas=%d rc=%d err=%q | retireVault gas=%d rc=%d err=%q",
			n, mv.GasUsed, mv.RcUsed, mv.ErrMsg, rv.GasUsed, rv.RcUsed, rv.ErrMsg)
	}
}

// R2, like for like: gen-0 PURGED leaves ONE superseded gen, the normal case, where the
// fix skips its registry scan. Canary and bulk cost must match the code before the fix. The
// bulk tranche is the worst case: its input gather scans the whole registry.
func TestSHADOWFIX_GasBulkLikeForLike(t *testing.T) {
	for _, n := range []int{0, 200, 1000} {
		ct, cid, owner := newShadowCT(t)
		setGenStatus(t, ct, cid, 0, mapping.VaultStatusPurged)
		for i := 0; i < n; i++ {
			appendGenUtxo(t, ct, cid, 2, uint16(3000+i), 10_000)
		}
		canary := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
		bulk := callKeyAction(t, ct, cid, owner, "migrateVault", []byte(""))
		require.Empty(t, bulk.Err, bulk.ErrMsg)
		require.NotEqual(t, canary.Ret, bulk.Ret)
		t.Logf("N=%d canary rc=%d | bulk rc=%d", n, canary.RcUsed, bulk.RcUsed)
	}
}
