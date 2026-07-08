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

// TestIsFundHoldingStatusSet pins the deposit-matchable ≡ renewable set to exactly
// {active, retiring, draining}. Both S1.4 deposit matching and RenewableVaultKeyIds
// route through isFundHoldingStatus, so widening/narrowing either side (which would
// break the "credited ⇒ renewable ⇒ signable" coupling) fails here.
func TestIsFundHoldingStatusSet(t *testing.T) {
	want := map[VaultStatus]bool{
		VaultStatusPending:  false,
		VaultStatusActive:   true,
		VaultStatusRetiring: true,
		VaultStatusDraining: true,
		VaultStatusInactive: false,
		VaultStatusPurged:   false,
	}
	for s, exp := range want {
		if got := isFundHoldingStatus(s); got != exp {
			t.Fatalf("isFundHoldingStatus(%d) = %v, want %v", s, got, exp)
		}
	}
}

// TestDepositAddressGenerationsMultiGen proves S1.4's core: deposit-address matching
// spans EVERY fund-holding generation (active + retiring + draining), ACTIVE first
// (collision precedence), each carrying its own generation — so a late deposit to a
// superseded generation's address still credits and is tagged with THAT generation
// (NR-4 / C-2). Reverting to active-gen-only drops the retiring/draining entries,
// re-opening the fund-loss S1.4 closes.
func TestDepositAddressGenerationsMultiGen(t *testing.T) {
	g0p, g0b, g1p, g1b := pk(0xA0), pk(0xB0), pk(0xC0), pk(0xD0)
	cs := &ContractState{
		Vaults: VaultRegistry{
			{Generation: 0, Primary: g0p, Backup: g0b, Status: VaultStatusRetiring},
			{Generation: 1, Primary: g1p, Backup: g1b, Status: VaultStatusActive},
		},
		ActiveGen: 1,
	}
	got := cs.depositAddressGenerations()
	if len(got) != 2 {
		t.Fatalf("want 2 matchable generations (active+retiring), got %d", len(got))
	}
	if got[0].generation != 1 || got[0].primary != g1p || got[0].backup != g1b {
		t.Fatalf("candidate[0] must be the ACTIVE gen 1 with its own keys, got gen %d", got[0].generation)
	}
	if got[1].generation != 0 || got[1].primary != g0p || got[1].backup != g0b {
		t.Fatalf("candidate[1] must be the RETIRING gen 0 with its own keys, got gen %d", got[1].generation)
	}
	// Distinct generations derive DISTINCT deposit addresses for the same instruction,
	// so a tx output matches exactly one generation → unambiguous tagging.
	net := &chaincfg.RegressionNetParams
	tag := []byte{1, 2, 3}
	a0, _, _ := createP2WSHAddressWithBackup(g0p, g0b, tag, net)
	a1, _, _ := createP2WSHAddressWithBackup(g1p, g1b, tag, net)
	if a0 == a1 {
		t.Fatal("distinct generations must derive distinct deposit addresses")
	}
}

// TestDepositAddressGenerationsExcludesAndFallsBack proves the matchable set is
// exactly the fund-holding, keyed generations (draining INCLUDED; pending / inactive
// / purged EXCLUDED) and the pre-fold / fresh-deploy fail-safe fallback.
func TestDepositAddressGenerationsExcludesAndFallsBack(t *testing.T) {
	act, actb := pk(0x51), pk(0x52)
	cs := &ContractState{
		Vaults: VaultRegistry{
			{Generation: 5, Primary: act, Backup: actb, Status: VaultStatusActive},
			{Generation: 2, Primary: pk(0x91), Backup: pk(0x92), Status: VaultStatusDraining}, // fund-holding → included
			{Generation: 4, Primary: pk(0x61), Backup: pk(0x62), Status: VaultStatusInactive}, // excluded
			{Generation: 3, Primary: pk(0x71), Backup: pk(0x72), Status: VaultStatusPurged},   // excluded
			{Generation: 6, Primary: pk(0x81), Backup: pk(0x82), Status: VaultStatusPending},  // excluded
		},
		ActiveGen: 5,
	}
	got := cs.depositAddressGenerations()
	if len(got) != 2 {
		t.Fatalf("want active gen 5 + draining gen 2 only, got %d entries", len(got))
	}
	if got[0].generation != 5 {
		t.Fatalf("active gen 5 must be first, got gen %d", got[0].generation)
	}
	if got[1].generation != 2 {
		t.Fatalf("draining gen 2 must be matched (fund-holding), got gen %d", got[1].generation)
	}

	// A PENDING active-gen with ZERO keys (fresh-deploy genesis pre-activation) must
	// NOT match from the list — fall back to the resolved legacy/active key pair.
	fb := &ContractState{
		Vaults:     VaultRegistry{{Generation: 0, Status: VaultStatusPending}}, // zero keys
		ActiveGen:  0,
		PublicKeys: PublicKeys{Primary: act, Backup: actb},
	}
	if g := fb.depositAddressGenerations(); len(g) != 1 || g[0].generation != 0 || g[0].primary != act {
		t.Fatal("fresh-deploy pre-activation must fall back to the resolved key pair tagged the active gen")
	}

	// Empty vault list (pre-fold) → fallback to cs.PublicKeys tagged cs.ActiveGen
	// (byte-identical to pre-S1.4 single-address behaviour).
	empty := &ContractState{ActiveGen: 0, PublicKeys: PublicKeys{Primary: act, Backup: actb}}
	if e := empty.depositAddressGenerations(); len(e) != 1 || e[0].primary != act || e[0].generation != 0 {
		t.Fatal("empty vault list must fall back to the single legacy key pair")
	}
}

// TestDepositAddressGenerationsTwoSupersededGens proves matching spans MULTIPLE
// superseded generations at once (a double rotation: gen-0 draining + gen-1 retiring
// while gen-2 is active) — active first, then every fund-holding predecessor in
// vault-list order. Covers the S1.4-council F3 gap (no multi-retiring-gen coverage).
func TestDepositAddressGenerationsTwoSupersededGens(t *testing.T) {
	cs := &ContractState{
		Vaults: VaultRegistry{
			{Generation: 0, Primary: pk(0x10), Backup: pk(0x11), Status: VaultStatusDraining},
			{Generation: 1, Primary: pk(0x20), Backup: pk(0x21), Status: VaultStatusRetiring},
			{Generation: 2, Primary: pk(0x30), Backup: pk(0x31), Status: VaultStatusActive},
		},
		ActiveGen: 2,
	}
	got := cs.depositAddressGenerations()
	if len(got) != 3 {
		t.Fatalf("want all 3 fund-holding gens matched, got %d", len(got))
	}
	if got[0].generation != 2 {
		t.Fatalf("active gen 2 must be first, got %d", got[0].generation)
	}
	// Both superseded gens follow, in vault-list order (0 draining, then 1 retiring).
	if got[1].generation != 0 || got[2].generation != 1 {
		t.Fatalf("both superseded gens must be matched in list order, got [%d,%d]", got[1].generation, got[2].generation)
	}
}

// TestDepositAddressGenerationsSkipsZeroBackup proves the S1.4 council D-2 defensive
// guard: a (would-be fund-holding) generation with a real primary but a ZERO backup
// key is NOT matched — deriving an address with a zero backup leaves its CSV recovery
// path unspendable. Unreachable in normal flow (activation requires both keys) but
// defense-in-depth; reverting the backup zero-check matches it into the registry.
func TestDepositAddressGenerationsSkipsZeroBackup(t *testing.T) {
	act, actb := pk(0x51), pk(0x52)
	cs := &ContractState{
		Vaults: VaultRegistry{
			{Generation: 0, Primary: act, Backup: actb, Status: VaultStatusActive},
			{Generation: 1, Primary: pk(0x61), Status: VaultStatusRetiring}, // zero Backup
		},
		ActiveGen: 0,
	}
	got := cs.depositAddressGenerations()
	if len(got) != 1 || got[0].generation != 0 {
		t.Fatalf("gen 1 with a zero backup key must be skipped; got %d entries", len(got))
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
