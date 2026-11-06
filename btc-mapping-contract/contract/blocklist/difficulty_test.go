package blocklist

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

// BTC-HDR-1 regression.
//
// blockchain.CheckProofOfWork, the only difficulty check HandleAddBlocks used
// to make, answers "does this hash meet the target this header DECLARES, and is
// that target no easier than PowLimit?". A header mined at minimum difficulty
// satisfies both. Nothing asked whether the declared target is the one the
// retarget schedule requires, so the only thing between the contract and a
// fabricated header chain was the 2/3 oracle quorum — and the header chain is
// what every SPV deposit proof is verified against.
//
// These tests are built on REAL mainnet headers, fetched from the live chain
// and verified here to hash to their real block hashes. That matters for two
// reasons: a fabricated fixture could not be mined at mainnet difficulty, so
// the hash check is what makes the fixture trustworthy; and the notes required
// "a replay of real mainnet header history first", because a retarget formula
// that is subtly wrong would reject the real chain and halt the bridge.

// Real mainnet headers (80 bytes each, as stored by the contract).
//
//	971712 — first block of the retarget period
//	973727 — last block of that period (the parent of the boundary block)
//	973728 — the retarget boundary itself (= 483 * 2016)
//	974000, 974001 — an ordinary consecutive pair, mid-period
const (
	hdr971712Hex = "006005202e5ea9d74cd63c1fb65514e47c38f2a4767ad8d6ae51000000000000000000003d63f20e90eb3b43e72ea91858f41d1d92103442acfa6106400e04e08f4d94df8b1ad26a930002176d7224e8"
	hdr973727Hex = "00a04b20f3f9aa1aaa2bb91f5d8acd5112a3c428814c3e4087ff0100000000000000000042ab8f9c176bd1993227e826305521f4c23f96b9dfb66354b08bab9f8a004d309297e36a9300021765ed2b3c"
	hdr973728Hex = "00e06620044f3b4ed568ef68218ced65c5f370ee81736922b732010000000000000000005c99018695acc6a1822dd070138fe75e77d0b3e17f0e3d3d5e595faeeb5ed791329be36aace501170839ffa9"
	hdr974000Hex = "00c008208042e76820f82d605498e609240e207b0d1559982ce800000000000000000000c1541910c988f1a6421f0a04ae5a053ac3e1f126f0f4c6738ff7c98a96513e0a8721e66aace501176f002e09"
	hdr974001Hex = "0000002a65e8741d08df768f60a6d91396ad2c0524c05a3fd1d700000000000000000000ef5b32ca9df9bca2312800317f407f4dc49ea8e07f77d20215ea981bef53fe6f9922e66aace501175fe6b447"

	hash971712 = "00000000000000000000c185f0906690a08d62d6fe842682a888d5560217e467"
	hash973727 = "0000000000000000000132b722697381ee70f3c565ed8c2168ef68d54e3b4f04"
	hash973728 = "0000000000000000000104150b08ff89bbb2d11bab42c245c82b8165ab2e2c11"
	hash974000 = "00000000000000000000d7d13f5ac024052cad9613d9a6608f76df081d74e865"
	hash974001 = "00000000000000000000ad021486a7888ab593e06b9b17e7658ae442237722d3"

	// MINED FORGERIES. Not synthetic: each was actually mined at minimum
	// difficulty (0x1d00ffff) against the real mainnet parent, ~3.9 billion
	// hashes and about four minutes on eight cores. That cost IS the finding —
	// forging a header the old code accepts is trivially affordable, which is
	// why the 2/3 oracle quorum was the only thing standing in the way.
	//
	// They are needed because simply rewriting a real header's nBits does not
	// produce a usable forgery: changing the field changes the hash, so
	// CheckProofOfWork rejects it and a test built that way passes without
	// exercising the difficulty check at all (it did, at first).
	//
	//	minedMidPeriodHex — height 974001, parent = real 974000 (not a boundary)
	//	minedBoundaryHex  — height 973728, parent = real 973727 (a boundary)
	minedMidPeriodHex = "0000002a65e8741d08df768f60a6d91396ad2c0524c05a3fd1d700000000000000000000ef5b32ca9df9bca2312800317f407f4dc49ea8e07f77d20215ea981bef53fe6f9922e66affff001d3527596b"
	minedBoundaryHex  = "00e06620044f3b4ed568ef68218ced65c5f370ee81736922b732010000000000000000005c99018695acc6a1822dd070138fe75e77d0b3e17f0e3d3d5e595faeeb5ed791329be36affff001dbedf49d2"
)

func mustHeader(t *testing.T, hexStr string) *wire.BlockHeader {
	t.Helper()
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("bad fixture hex: %v", err)
	}
	if len(raw) != 80 {
		t.Fatalf("header must be 80 bytes, got %d", len(raw))
	}
	var h wire.BlockHeader
	if err := h.BtcDecode(bytes.NewReader(raw), wire.ProtocolVersion, wire.LatestEncoding); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return &h
}

// TestHDR1_FixturesAreRealMainnetHeaders authenticates the fixture before any
// other test leans on it. A header that hashes to a real mainnet block hash,
// with leading zeros at mainnet difficulty, cannot have been fabricated — so
// this is what makes it legitimate to treat downloaded bytes as ground truth.
func TestHDR1_FixturesAreRealMainnetHeaders(t *testing.T) {
	cases := []struct {
		name, hdr, hash string
	}{
		{"971712", hdr971712Hex, hash971712},
		{"973727", hdr973727Hex, hash973727},
		{"973728", hdr973728Hex, hash973728},
		{"974000", hdr974000Hex, hash974000},
		{"974001", hdr974001Hex, hash974001},
	}
	params := &chaincfg.MainNetParams
	for _, c := range cases {
		h := mustHeader(t, c.hdr)
		if got := h.BlockHash().String(); got != c.hash {
			t.Fatalf("%s: header does not hash to the real block hash\n got %s\nwant %s", c.name, got, c.hash)
		}
		// And it really is at mainnet difficulty, not the PowLimit floor.
		target := blockchain.CompactToBig(h.Bits)
		if target.Cmp(params.PowLimit) >= 0 {
			t.Fatalf("%s: fixture is at or below minimum difficulty (bits %08x) — not representative of mainnet", c.name, h.Bits)
		}
	}

	// The chain links the tests depend on.
	p, c := mustHeader(t, hdr973727Hex), mustHeader(t, hdr973728Hex)
	ph := p.BlockHash()
	if !c.PrevBlock.IsEqual(&ph) {
		t.Fatal("973727 -> 973728 does not link")
	}
	p2, c2 := mustHeader(t, hdr974000Hex), mustHeader(t, hdr974001Hex)
	p2h := p2.BlockHash()
	if !c2.PrevBlock.IsEqual(&p2h) {
		t.Fatal("974000 -> 974001 does not link")
	}
}

// THE REAL-HISTORY REPLAY. The retarget formula must reproduce the value the
// live chain actually used. If this drifts, mainnet's own headers get rejected
// and the bridge stops — which is the failure mode that makes a difficulty
// check dangerous to add carelessly.
func TestHDR1_RetargetFormulaReproducesRealMainnetBits(t *testing.T) {
	params := &chaincfg.MainNetParams
	first := mustHeader(t, hdr971712Hex)
	last := mustHeader(t, hdr973727Hex)
	boundary := mustHeader(t, hdr973728Hex)

	if got := retargetInterval(params); got != 2016 {
		t.Fatalf("mainnet retarget interval should be 2016, got %d", got)
	}
	if 973728%2016 != 0 {
		t.Fatal("973728 must be a retarget boundary for this test to mean anything")
	}

	expected := calcNextRequiredBits(params, last, first)
	if expected != boundary.Bits {
		t.Fatalf("retarget formula does not match the real chain:\n"+
			"  period %d..%d, actual timespan %ds (target %ds)\n"+
			"  parent bits %08x, computed %08x, REAL %08x",
			971712, 973727,
			last.Timestamp.Unix()-first.Timestamp.Unix(),
			int64(params.TargetTimespan.Seconds()),
			last.Bits, expected, boundary.Bits)
	}
	t.Logf("real mainnet retarget at 973728 reproduced exactly: %08x -> %08x", last.Bits, expected)
}

// Real consecutive mid-period headers must pass. A false rejection here would
// halt the bridge on honest data.
func TestHDR1_RealConsecutiveHeadersAccepted(t *testing.T) {
	params := &chaincfg.MainNetParams
	parent := mustHeader(t, hdr974000Hex)
	child := mustHeader(t, hdr974001Hex)
	if err := validateDifficulty(params, 974001, child, parent); err != nil {
		t.Fatalf("real mainnet header rejected: %v", err)
	}
}

// THE ATTACK, with a real forgery.
//
// This first establishes the premise: the mined header has GENUINELY VALID
// proof of work for the minimum-difficulty target it declares, so
// CheckProofOfWork — the only difficulty check the contract used to make —
// accepts it. Then it asserts the new check refuses it.
//
// Both halves matter. Without the first, the test could be passing because the
// forgery is malformed rather than because the fix works, which is exactly what
// happened when the forgery was produced by rewriting nBits instead of mining.
func TestHDR1_MinedMinDifficultyForgeryRejected(t *testing.T) {
	params := &chaincfg.MainNetParams
	parent := mustHeader(t, hdr974000Hex)
	forged := mustHeader(t, minedMidPeriodHex)

	// Premise 1: it chains to the real mainnet parent.
	ph := parent.BlockHash()
	if !forged.PrevBlock.IsEqual(&ph) {
		t.Fatal("the forgery does not chain to real mainnet block 974000")
	}
	// Premise 2: it declares minimum difficulty.
	if forged.Bits != blockchain.BigToCompact(params.PowLimit) {
		t.Fatalf("the forgery should declare minimum difficulty, got %08x", forged.Bits)
	}
	// Premise 3 — THE VULNERABILITY: the old check accepts it.
	msg := wire.MsgBlock{Header: *forged}
	if err := blockchain.CheckProofOfWork(btcutil.NewBlock(&msg), params.PowLimit); err != nil {
		t.Fatalf("the forgery must pass CheckProofOfWork or it proves nothing about the fix: %v", err)
	}
	t.Logf("CheckProofOfWork ACCEPTS this forgery (hash %s) — that is BTC-HDR-1", forged.BlockHash())

	// THE FIX.
	err := validateDifficulty(params, 974001, forged, parent)
	if err == nil {
		t.Fatal("a mined minimum-difficulty header was accepted mid-period — BTC-HDR-1 is not fixed")
	}
	t.Logf("refused: %v", err)
}

// The same forgery at a retarget boundary, where the exact required value is
// known from the period's first header. Under the host stub state reads return
// nil, so this lands on the fallback clamp; the WASM test covers the exact path.
func TestHDR1_MinedBoundaryForgeryRejected(t *testing.T) {
	params := &chaincfg.MainNetParams
	parent := mustHeader(t, hdr973727Hex)
	forged := mustHeader(t, minedBoundaryHex)

	ph := parent.BlockHash()
	if !forged.PrevBlock.IsEqual(&ph) {
		t.Fatal("the forgery does not chain to real mainnet block 973727")
	}
	msg := wire.MsgBlock{Header: *forged}
	if err := blockchain.CheckProofOfWork(btcutil.NewBlock(&msg), params.PowLimit); err != nil {
		t.Fatalf("the boundary forgery must pass CheckProofOfWork: %v", err)
	}

	if err := validateDifficulty(params, 973728, forged, parent); err == nil {
		t.Fatal("a mined minimum-difficulty header was accepted at a retarget boundary")
	} else {
		t.Logf("refused: %v", err)
	}
}

// Any off-schedule change mid-period is refused, not just an easier one: a
// HARDER target is equally a sign of a fabricated chain. (nBits rewriting is
// fine here — the point is the schedule check, and a harder target would fail
// PoW anyway, so there is nothing to mine.)
func TestHDR1_HarderOffScheduleTargetRejectedMidPeriod(t *testing.T) {
	params := &chaincfg.MainNetParams
	parent := mustHeader(t, hdr974000Hex)
	harder := *mustHeader(t, hdr974001Hex)
	harder.Bits = parent.Bits - 1
	if err := validateDifficulty(params, 974001, &harder, parent); err == nil {
		t.Fatal("an off-schedule harder target was accepted mid-period")
	}
}

// At a boundary with the period's first header unavailable (pruned, or the
// contract was seeded inside the period) the exact value cannot be recomputed,
// so the fallback bounds the adjustment instead. Under the host test stub
// StateGetObject always returns nil, so this is the branch exercised here.
func TestHDR1_BoundaryFallbackBoundsTheAdjustment(t *testing.T) {
	params := &chaincfg.MainNetParams
	parent := mustHeader(t, hdr973727Hex)

	t.Run("a 4x ease is allowed", func(t *testing.T) {
		h := *mustHeader(t, hdr973728Hex)
		oldTarget := blockchain.CompactToBig(parent.Bits)
		h.Bits = blockchain.BigToCompact(oldTarget.Mul(oldTarget, big.NewInt(params.RetargetAdjustmentFactor)))
		if err := validateDifficulty(params, 973728, &h, parent); err != nil {
			t.Fatalf("the protocol's own maximum adjustment was rejected: %v", err)
		}
	})

	t.Run("minimum difficulty is refused even at a boundary", func(t *testing.T) {
		h := *mustHeader(t, hdr973728Hex)
		h.Bits = blockchain.BigToCompact(params.PowLimit)
		if err := validateDifficulty(params, 973728, &h, parent); err == nil {
			t.Fatal("a minimum-difficulty header was accepted at a retarget boundary")
		}
	})

	t.Run("the real boundary header is still accepted", func(t *testing.T) {
		h := mustHeader(t, hdr973728Hex)
		if err := validateDifficulty(params, 973728, h, parent); err != nil {
			t.Fatalf("the real mainnet boundary header was rejected by the fallback: %v", err)
		}
	})
}

// Test networks must stay exempt: ReduceMinDifficulty is true for them, so the
// 20-minute rule lets a block legitimately carry minimum difficulty and
// "nBits unchanged" is not a rule at all. The repo's own testnet3 fixtures are
// mined at 0x1d00ffff, so enforcing there would break them.
func TestHDR1_TestNetworksExempt(t *testing.T) {
	for _, params := range []*chaincfg.Params{
		&chaincfg.TestNet3Params, &chaincfg.TestNet4Params, &chaincfg.RegressionNetParams,
	} {
		if !params.ReduceMinDifficulty {
			t.Fatalf("%s unexpectedly has ReduceMinDifficulty false; the exemption reasoning needs revisiting", params.Name)
		}
		parent := mustHeader(t, hdr974000Hex)
		forged := *mustHeader(t, hdr974001Hex)
		forged.Bits = blockchain.BigToCompact(params.PowLimit)
		if err := validateDifficulty(params, 974001, &forged, parent); err != nil {
			t.Fatalf("%s must be exempt, got: %v", params.Name, err)
		}
	}
	// And mainnet, the one network that holds funds, must NOT be exempt.
	if chaincfg.MainNetParams.ReduceMinDifficulty {
		t.Fatal("mainnet must have ReduceMinDifficulty false or none of this is enforced")
	}
}
