package current_test

// REGISTRY-RC-GROWTH-1: a call pays 1 RC per byte it reads, and rewriting an
// existing key costs its old and its new bytes. The vault registry holds every
// generation ever made (91 bytes each), so an unmap paid it three times over:
// the contract state load, then SaveToState rewriting it unchanged.

import (
	"encoding/binary"
	"testing"

	"btc-mapping-contract/contract/constants"

	"vsc-node/lib/test_utils"

	"github.com/stretchr/testify/require"
)

// unmapRCWithGenerations is the RC of a plain unmap on the rotation fixture (gen
// 0 retiring, gen 1 active) with `extra` purged generations appended to the
// registry.
func unmapRCWithGenerations(t *testing.T, extra int) int64 {
	t.Helper()
	const u = "hive:regrc1"
	ct, contractId, _ := wqRotationCT(t, []utxoSeed{{1100, 900_000}}, 20_000, u)
	reg := []byte(ct.StateGet(contractId, constants.VaultRegistryKey))
	require.Len(t, reg, 2*91)
	for i := 1; i <= extra; i++ {
		e := append([]byte(nil), reg[:91]...)
		binary.BigEndian.PutUint32(e[0:], uint32(1000+i))
		e[70] = 5 // purged
		reg = append(reg, e...)
	}
	ct.StateSet(contractId, constants.VaultRegistryKey, string(reg))
	r := wqUnmap(t, ct, contractId, u, 50_000)
	require.True(t, r.Success, r.ErrMsg)
	return r.RcUsed
}

// Eight more generations in the registry cost an unmap one read of their bytes
// (8 x 91 = 728 RC), not one per re-read (2,184 RC at three reads).
func TestREGRC1_AnUnmapReadsTheRegistryOnce(t *testing.T) {
	two := unmapRCWithGenerations(t, 0)
	ten := unmapRCWithGenerations(t, 8)
	delta := ten - two
	t.Logf("unmap: %d RC with 2 generations, %d RC with 10 (+%d)", two, ten, delta)
	require.InDelta(t, 8*91, delta, 40, "8 more generations must cost one read of their 728 bytes, got +%d RC", delta)
}

// The legacy fold check now reads the registry through LoadVaultState: an
// undecodable registry is still never folded over, and is left as it was.
func TestREGRC1_FoldNeverOverwritesAnUndecodableRegistry(t *testing.T) {
	for _, version := range []string{"1", ""} {
		ct := test_utils.NewContractTest()
		t.Cleanup(func() { ct.DataLayer.Stop() })
		contractId, owner := "mapping_contract", "hive:milo-hpr"
		ct.RegisterContract(contractId, owner, ContractWasm)
		ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
		ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
		const bad = "\x01\x02\x03"
		ct.StateSet(contractId, constants.VaultRegistryKey, bad)
		if version != "" {
			ct.StateSet(contractId, constants.MigrateVersionKey, version)
		}
		callMigrate(t, &ct, contractId, owner)
		require.Equal(t, bad, ct.StateGet(contractId, constants.VaultRegistryKey),
			"migrate (version %q) folded over an undecodable vault registry", version)
	}
}
