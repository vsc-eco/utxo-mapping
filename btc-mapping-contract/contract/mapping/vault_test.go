package mapping

import (
	"bytes"
	"testing"

	"btc-mapping-contract/contract/constants"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const testTxId64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// pk builds a distinct valid-length compressed pubkey for tests (P2WSH is a hash,
// so the bytes need not be a real curve point).
func pk(b byte) CompressedPubKey {
	var k CompressedPubKey
	k[0], k[1] = 0x02, b
	return k
}

func TestVaultKeyId(t *testing.T) {
	if got := VaultKeyId(0); got != constants.TssKeyName {
		t.Fatalf("gen 0 keyId = %q, want %q", got, constants.TssKeyName)
	}
	if got := VaultKeyId(1); got != constants.TssKeyName+"v1" {
		t.Fatalf("gen 1 keyId = %q", got)
	}
	if got := VaultKeyId(42); got != constants.TssKeyName+"v42" {
		t.Fatalf("gen 42 keyId = %q", got)
	}
	// The keyId MUST be alphanumeric — the runtime create_key/renew_key bindings
	// reject anything else, which would brick rotation (a hyphen was the original bug).
	for _, gen := range []uint32{0, 1, 7, 42, 1000} {
		id := VaultKeyId(gen)
		for _, c := range id {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
				t.Fatalf("gen %d keyId %q is not alphanumeric (runtime would reject at keygen)", gen, id)
			}
		}
	}
}

func TestVaultKeysForGenerationFoundBool(t *testing.T) {
	a, b := pk(0x02), pk(0x03)
	cs := &ContractState{Vaults: VaultRegistry{{Generation: 1, Primary: a, Backup: b}}}
	p, bk, found := cs.vaultKeysForGeneration(1)
	if !found || p != a || bk != b {
		t.Fatal("gen 1 must be found with its own keys")
	}
	if _, _, found2 := cs.vaultKeysForGeneration(99); found2 {
		t.Fatal("gen 99 (absent) must return found=false so the caller aborts")
	}
}

// TestBuildSpendUsesInputGenerationKeys proves fix #3's per-INPUT wiring (council 1c
// + round-3 adequacy gap 1): in a MIXED-generation spend (the migration-sweep case),
// each input's witness is built from ITS OWN generation's keys. The RETIRING gen-0
// input (NOT the active gen) must use gen-0 keys, and the active gen-1 input gen-1
// keys. This locks per-INPUT resolution `vaultKeysForGeneration(utxo.Generation)` —
// reverting to `cs.PublicKeys` OR to `cs.ActiveGen` both fail the gen-0 assertion.
func TestBuildSpendUsesInputGenerationKeys(t *testing.T) {
	net := &chaincfg.RegressionNetParams
	g0p, g0b, g1p, g1b := pk(0xA0), pk(0xB0), pk(0xC0), pk(0xD0)
	cs := &ContractState{
		NetworkParams: net,
		Supply:        SystemSupply{BaseFeeRate: 1},
		Vaults: VaultRegistry{
			{Generation: 0, Primary: g0p, Backup: g0b, Status: VaultStatusRetiring},
			{Generation: 1, Primary: g1p, Backup: g1b, Status: VaultStatusActive},
		},
		ActiveGen: 1,
	}
	changeAddr, _, err := createP2WSHAddressWithBackup(g1p, g1b, nil, net)
	if err != nil {
		t.Fatal(err)
	}
	// Mixed-gen sweep: a RETIRING gen-0 input (Vout 0) + an ACTIVE gen-1 input (Vout 1).
	inG0 := &Utxo{TxId: testTxId64, Vout: 0, Amount: 100000, Generation: 0}
	inG1 := &Utxo{TxId: testTxId64, Vout: 1, Amount: 100000, Generation: 1}
	_, witnessScripts, _, err := cs.buildSpendTransaction([]*Utxo{inG0, inG1}, 200000, changeAddr, changeAddr, 50000)
	if err != nil {
		t.Fatalf("mixed-gen spend should build: %v", err)
	}
	_, wantG0, _ := createP2WSHAddressWithBackup(g0p, g0b, nil, net)
	_, wantG1, _ := createP2WSHAddressWithBackup(g1p, g1b, nil, net)
	// Input 0 (RETIRING gen-0, != active) → gen-0 keys, NOT the active gen-1 keys.
	if !bytes.Equal(witnessScripts[0], wantG0) {
		t.Fatal("retiring gen-0 input witness must use its OWN gen-0 keys, not the active gen")
	}
	if bytes.Equal(witnessScripts[0], wantG1) {
		t.Fatal("retiring gen-0 input witness must NOT use the active gen-1 keys")
	}
	// Input 1 (ACTIVE gen-1) → gen-1 keys.
	if !bytes.Equal(witnessScripts[1], wantG1) {
		t.Fatal("active gen-1 input witness must use gen-1 keys")
	}
	if bytes.Equal(witnessScripts[1], wantG0) {
		t.Fatal("gen-1 input witness must NOT use gen-0 keys")
	}
}

// TestBuildSpendAbortsOnMissingGeneration proves fix #3's abort (council 1b): a UTXO
// whose generation is absent from a POPULATED vault list must abort (never build a
// witness the signature can't satisfy). Reverting the abort makes this build silently.
// It also confirms the pre-fold empty-list case still falls back (no over-eager abort).
func TestBuildSpendAbortsOnMissingGeneration(t *testing.T) {
	net := &chaincfg.RegressionNetParams
	g0p, g0b := pk(0x11), pk(0x22)
	cs := &ContractState{
		NetworkParams: net,
		Supply:        SystemSupply{BaseFeeRate: 1},
		Vaults:        VaultRegistry{{Generation: 0, Primary: g0p, Backup: g0b, Status: VaultStatusActive}},
		PublicKeys:    PublicKeys{Primary: g0p, Backup: g0b},
	}
	changeAddr, _, _ := createP2WSHAddressWithBackup(g0p, g0b, nil, net)
	in := &Utxo{TxId: testTxId64, Vout: 0, Amount: 100000, Generation: 99} // absent from a populated list
	if _, _, _, err := cs.buildSpendTransaction([]*Utxo{in}, 100000, changeAddr, changeAddr, 50000); err == nil {
		t.Fatal("spend of a UTXO whose generation is absent from a populated vault list must ABORT")
	}
	// Pre-fold empty list: the same gen falls back to legacy keys → NO abort.
	csEmpty := &ContractState{NetworkParams: net, Supply: SystemSupply{BaseFeeRate: 1}, PublicKeys: PublicKeys{Primary: g0p, Backup: g0b}}
	if _, _, _, err := csEmpty.buildSpendTransaction([]*Utxo{in}, 100000, changeAddr, changeAddr, 50000); err != nil {
		t.Fatalf("pre-fold empty-list spend must NOT abort (legacy fallback): %v", err)
	}
}

// TestDepositTaggedWithGeneration proves fix C-1: indexOutputs tags a DEPOSIT UTXO
// with the generation of the address it hit (AddressMetadata.Generation), so after a
// rotation a gen-1 deposit is recorded gen-1, not the zero value. Without the tag the
// spend path would resolve gen-0 keys for a gen-1-locked UTXO -> an unspendable
// witness while the balance is deducted (a fund-loss the council proved live).
func TestDepositTaggedWithGeneration(t *testing.T) {
	net := &chaincfg.RegressionNetParams
	addrStr, _, err := createP2WSHAddressWithBackup(pk(0x51), pk(0x52), nil, net)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := btcutil.DecodeAddress(addrStr, net)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}
	// The registry says this deposit address belongs to generation 3.
	ms := &MappingState{
		ContractState: ContractState{NetworkParams: net, ActiveGen: 3},
		AddressRegistry: map[string]*AddressMetadata{
			addrStr: {Instruction: "x", Recipient: "r", Tag: []byte{1, 2}, Type: MapDeposit, Generation: 3},
		},
	}
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxOut(wire.NewTxOut(50000, pkScript))

	utxos, err := ms.indexOutputs(tx)
	if err != nil {
		t.Fatal(err)
	}
	if len(utxos) != 1 {
		t.Fatalf("expected 1 indexed deposit, got %d", len(utxos))
	}
	if utxos[0].Generation != 3 {
		t.Fatalf("deposit UTXO Generation = %d, want 3 (the address's generation)", utxos[0].Generation)
	}
}

// TestChangeOutputTaggedWithActiveGen proves fix #2 (council 1a): a change output is
// tagged with the active generation, not the default 0. Reverting the tag fails this.
func TestChangeOutputTaggedWithActiveGen(t *testing.T) {
	net := &chaincfg.RegressionNetParams
	changeAddr, _, err := createP2WSHAddressWithBackup(pk(0x31), pk(0x32), nil, net)
	if err != nil {
		t.Fatal(err)
	}
	cAddr, err := btcutil.DecodeAddress(changeAddr, net)
	if err != nil {
		t.Fatal(err)
	}
	changePkScript, err := txscript.PayToAddrScript(cAddr)
	if err != nil {
		t.Fatal(err)
	}
	destAddrStr, _, _ := createP2WSHAddressWithBackup(pk(0x41), pk(0x42), nil, net)
	dAddr, _ := btcutil.DecodeAddress(destAddrStr, net)
	destPkScript, _ := txscript.PayToAddrScript(dAddr)

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxOut(wire.NewTxOut(50000, destPkScript))   // destination (not change)
	tx.AddTxOut(wire.NewTxOut(40000, changePkScript)) // change → changeAddr

	utxos, err := indexUnconfimedOutputs(tx, changeAddr, net, 7) // ActiveGen = 7
	if err != nil {
		t.Fatal(err)
	}
	tagged := false
	for _, u := range utxos {
		if u == nil {
			continue
		}
		if u.Generation != 7 {
			t.Fatalf("change UTXO Generation = %d, want 7 (the active generation)", u.Generation)
		}
		tagged = true
	}
	if !tagged {
		t.Fatal("expected a change UTXO to be indexed and tagged with the active generation")
	}
}
