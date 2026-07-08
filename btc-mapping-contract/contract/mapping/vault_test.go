package mapping

import (
	"testing"

	"btc-mapping-contract/contract/constants"
)

func TestVaultKeyId(t *testing.T) {
	if got := vaultKeyId(0); got != constants.TssKeyName {
		t.Fatalf("gen 0 keyId = %q, want %q", got, constants.TssKeyName)
	}
	if got := vaultKeyId(1); got != constants.TssKeyName+"-v1" {
		t.Fatalf("gen 1 keyId = %q", got)
	}
	if got := vaultKeyId(42); got != constants.TssKeyName+"-v42" {
		t.Fatalf("gen 42 keyId = %q", got)
	}
}

func TestVaultKeysForGenerationFoundBool(t *testing.T) {
	var a, b CompressedPubKey
	a[0], b[0] = 0x02, 0x03
	cs := &ContractState{Vaults: VaultRegistry{{Generation: 1, Primary: a, Backup: b}}}
	p, bk, found := cs.vaultKeysForGeneration(1)
	if !found || p != a || bk != b {
		t.Fatal("gen 1 must be found with its own keys")
	}
	if _, _, found2 := cs.vaultKeysForGeneration(99); found2 {
		t.Fatal("gen 99 (absent) must return found=false so the caller aborts")
	}
}
