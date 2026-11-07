package current_test

import (
	"testing"

	btcMapping "btc-mapping-contract"
	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BTC-HDR-1, through the real mainnet WASM.
//
// The unit tests in contract/blocklist cover the formula and the non-boundary
// rule, but under the host SDK stub StateGetObject always returns nil, so they
// can only ever reach the boundary FALLBACK. This exercises the branch that
// matters most — the exact retarget check, which needs the period's first
// header to actually be readable from contract state.
//
// Mainnet mode is required: it is the only network the contract builds for with
// ReduceMinDifficulty false, so it is the only one where any of this is
// enforced. (The repo's testnet3 header fixtures are mined at 0x1d00ffff, which
// is exactly why the test networks are exempt.)

// Real mainnet headers; authenticated against their block hashes by
// TestHDR1_FixturesAreRealMainnetHeaders in contract/blocklist.
const (
	mainnetHdr971712 = "006005202e5ea9d74cd63c1fb65514e47c38f2a4767ad8d6ae51000000000000000000003d63f20e90eb3b43e72ea91858f41d1d92103442acfa6106400e04e08f4d94df8b1ad26a930002176d7224e8"
	mainnetHdr973727 = "00a04b20f3f9aa1aaa2bb91f5d8acd5112a3c428814c3e4087ff0100000000000000000042ab8f9c176bd1993227e826305521f4c23f96b9dfb66354b08bab9f8a004d309297e36a9300021765ed2b3c"
	mainnetHdr973728 = "00e06620044f3b4ed568ef68218ced65c5f370ee81736922b732010000000000000000005c99018695acc6a1822dd070138fe75e77d0b3e17f0e3d3d5e595faeeb5ed791329be36aace501170839ffa9"
	mainnetHdr974000 = "00c008208042e76820f82d605498e609240e207b0d1559982ce800000000000000000000c1541910c988f1a6421f0a04ae5a053ac3e1f126f0f4c6738ff7c98a96513e0a8721e66aace501176f002e09"
	mainnetHdr974001 = "0000002a65e8741d08df768f60a6d91396ad2c0524c05a3fd1d700000000000000000000ef5b32ca9df9bca2312800317f407f4dc49ea8e07f77d20215ea981bef53fe6f9922e66aace501175fe6b447"
)

// Mined at minimum difficulty against the real mainnet parents — see the
// comment on minedMidPeriodHex in contract/blocklist/difficulty_test.go for why
// a forgery has to be MINED rather than produced by rewriting nBits.
const (
	minedForgery974001 = "0000002a65e8741d08df768f60a6d91396ad2c0524c05a3fd1d700000000000000000000ef5b32ca9df9bca2312800317f407f4dc49ea8e07f77d20215ea981bef53fe6f9922e66affff001d3527596b"
	minedForgery973728 = "00e06620044f3b4ed568ef68218ced65c5f370ee81736922b732010000000000000000005c99018695acc6a1822dd070138fe75e77d0b3e17f0e3d3d5e595faeeb5ed791329be36affff001dbedf49d2"
)

const btcOracleCaller = "did:vsc:oracle:btc"

// newMainnetBlocklistCT registers a mainnet-mode contract with `atHeight` as the
// tip and the given headers seeded.
func newMainnetBlocklistCT(t *testing.T, contractId string, atHeight string, headers map[string]string) *test_utils.ContractTest {
	t.Helper()
	if len(btcMapping.MainnetWasm) == 0 {
		t.Fatal("bin/mainnet.wasm is missing, so the contract would run with NO code and " +
			"every call would fail with \"EOF\" — a missing build artifact, not a contract " +
			"failure. Run `make mainnet` (GOTOOLCHAIN=go1.25.10).")
	}
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	ct.RegisterContract(contractId, "hive:milo-hpr", btcMapping.MainnetWasm)
	ct.StateSet(contractId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, atHeight)
	for h, hdrHex := range headers {
		ct.StateSet(contractId, constants.BlockPrefix+h, decodeHex(t, hdrHex))
	}
	return &ct
}

func addBlocks(t *testing.T, ct *test_utils.ContractTest, contractId, headerHex, txId string) test_utils.ContractTestCallResult {
	t.Helper()
	return ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: txId, BlockId: "block:hdr1", Index: 0, OpIndex: 0,
			Timestamp: "2026-11-05T00:00:00", RequiredAuths: []string{btcOracleCaller},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId, Action: "addBlocks",
		Payload: []byte(`{"blocks":"` + headerHex + `","latest_fee":0}`),
		RcLimit: 10000, Intents: []contracts.Intent{}, Caller: btcOracleCaller,
	})
}

// The exact-retarget branch, with the period's first header present in state.
// This is the real mainnet retarget at height 973,728 (= 483 * 2016).
func TestHDR1_Wasm_RealRetargetAcceptedWithFirstHeaderPresent(t *testing.T) {
	const id = "hdr1_retarget_ok"
	ct := newMainnetBlocklistCT(t, id, "973727", map[string]string{
		"971712": mainnetHdr971712, // period's first block -> enables the exact check
		"973727": mainnetHdr973727, // parent
	})

	r := addBlocks(t, ct, id, mainnetHdr973728, "hdr1-retarget-ok")
	require.True(t, r.Success,
		"the real mainnet retarget header must be accepted; err=%q msg=%q", r.Err, r.ErrMsg)
	assert.Contains(t, r.Ret, "973728")
}

// Same setup, but the boundary header claims minimum difficulty. With the first
// header present the contract knows the exact required value, so this is
// refused on the precise comparison rather than the fallback bound.
func TestHDR1_Wasm_ForgedMinDifficultyRetargetRejected(t *testing.T) {
	const id = "hdr1_retarget_forged"
	ct := newMainnetBlocklistCT(t, id, "973727", map[string]string{
		"971712": mainnetHdr971712,
		"973727": mainnetHdr973727,
	})

	r := addBlocks(t, ct, id, minedForgery973728, "hdr1-retarget-forged")
	require.False(t, r.Success, "a minimum-difficulty retarget header must be refused")
	t.Logf("refused: err=%q msg=%q", r.Err, r.ErrMsg)

	// And the tip must not have moved.
	assert.Equal(t, "973727", ct.StateGet(id, constants.LastHeightKey),
		"a refused header must not advance the tip")
}

// The non-boundary rule through the WASM: mid-period, nBits must be identical
// to the parent's. This is the check that makes the walk-down attack
// infeasible, so it is worth proving end to end and not only as a unit test.
func TestHDR1_Wasm_MidPeriodDifficultyChangeRejected(t *testing.T) {
	const id = "hdr1_midperiod"

	t.Run("the real header is accepted", func(t *testing.T) {
		ct := newMainnetBlocklistCT(t, id+"_ok", "974000", map[string]string{
			"974000": mainnetHdr974000,
		})
		r := addBlocks(t, ct, id+"_ok", mainnetHdr974001, "hdr1-mid-ok")
		require.True(t, r.Success, "real consecutive mainnet headers must be accepted; err=%q msg=%q", r.Err, r.ErrMsg)
	})

	t.Run("a minimum-difficulty header is refused", func(t *testing.T) {
		ct := newMainnetBlocklistCT(t, id+"_bad", "974000", map[string]string{
			"974000": mainnetHdr974000,
		})
		r := addBlocks(t, ct, id+"_bad", minedForgery974001, "hdr1-mid-bad")
		require.False(t, r.Success,
			"a minimum-difficulty header mid-period must be refused — this is BTC-HDR-1")
		t.Logf("refused: err=%q msg=%q", r.Err, r.ErrMsg)
		assert.Equal(t, "974000", ct.StateGet(id+"_bad", constants.LastHeightKey),
			"a refused header must not advance the tip")
	})
}

// replaceBlock drives the replaceBlock export. Its payload is a bare 80-byte
// header in hex, not JSON, and checkAdmin admits constants.OracleAddress — the
// same role that relays through addBlocks.
func replaceBlock(t *testing.T, ct *test_utils.ContractTest, contractId, headerHex, txId string) test_utils.ContractTestCallResult {
	t.Helper()
	return ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: txId, BlockId: "block:hdr1-replace", Index: 0, OpIndex: 0,
			Timestamp: "2026-11-07T00:00:00", RequiredAuths: []string{btcOracleCaller},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId, Action: "replaceBlock",
		Payload: []byte(headerHex),
		RcLimit: 10000, Intents: []contracts.Intent{}, Caller: btcOracleCaller,
	})
}

// BTC-HDR-1 on the REPLACE path.
//
// validateDifficulty was originally called from HandleAddBlocks and nowhere
// else, so the guard had one entry point and the store had two. replaceBlock
// checks CheckProofOfWork against networkParams.PowLimit — the network MINIMUM —
// plus chain linkage, and nothing about the retarget schedule, so a
// minimum-difficulty header that addBlocks refuses was accepted as the tip; a
// mid-period addBlocks afterwards only compares bits against that poisoned
// parent, so the forgery sticks. Reported by lordbutterfly reviewing #39.
//
// Severity, stated honestly: replaceBlock is checkAdmin-gated, so this is not a
// permissionless forgery. checkAdmin admits constants.OracleAddress, which is
// the same role that relays headers through addBlocks — i.e. exactly the actor
// the add-path check exists to constrain — so the guard belongs on both paths,
// but a reader should not read this as open to anyone.
//
// The forgeries are the ones already committed for the add-path tests: MINED at
// minimum difficulty against real mainnet parents, because rewriting nBits
// changes the hash and the header then dies on PoW without ever reaching the
// difficulty branch.
func TestHDR1_Wasm_ReplacePathAlsoChecksDifficulty(t *testing.T) {
	// CONTROL. Replacing with the REAL header must still succeed, or a refusal
	// below would prove only that replaceBlock is broken.
	t.Run("the real header is accepted", func(t *testing.T) {
		const id = "hdr1_replace_ok"
		ct := newMainnetBlocklistCT(t, id, "974001", map[string]string{
			"974000": mainnetHdr974000, // parent
			"974001": mainnetHdr974001, // the block being replaced
		})
		r := replaceBlock(t, ct, id, mainnetHdr974001, "hdr1-replace-ok")
		require.True(t, r.Success,
			"replacing with the real mainnet header must be accepted; err=%q msg=%q", r.Err, r.ErrMsg)
	})

	t.Run("a minimum-difficulty replacement is refused mid-period", func(t *testing.T) {
		const id = "hdr1_replace_forged_mid"
		ct := newMainnetBlocklistCT(t, id, "974001", map[string]string{
			"974000": mainnetHdr974000,
			"974001": mainnetHdr974001,
		})
		r := replaceBlock(t, ct, id, minedForgery974001, "hdr1-replace-forged-mid")
		require.False(t, r.Success,
			"a mined minimum-difficulty replacement must be refused — this is BTC-HDR-1 on the replace path")
		t.Logf("refused: err=%q msg=%q", r.Err, r.ErrMsg)

		// The stored tip header must be untouched: a refused replacement that
		// still overwrote state would be the same bug wearing an error message.
		assert.Equal(t, decodeHex(t, mainnetHdr974001),
			ct.StateGet(id, constants.BlockPrefix+"974001"),
			"a refused replacement must leave the stored header as it was")
	})

	t.Run("a minimum-difficulty replacement is refused at a retarget boundary", func(t *testing.T) {
		const id = "hdr1_replace_forged_boundary"
		ct := newMainnetBlocklistCT(t, id, "973728", map[string]string{
			"971712": mainnetHdr971712, // period's first block -> the exact check
			"973727": mainnetHdr973727, // parent
			"973728": mainnetHdr973728, // the block being replaced
		})
		r := replaceBlock(t, ct, id, minedForgery973728, "hdr1-replace-forged-boundary")
		require.False(t, r.Success, "a minimum-difficulty retarget replacement must be refused")
		t.Logf("refused: err=%q msg=%q", r.Err, r.ErrMsg)
		assert.Equal(t, decodeHex(t, mainnetHdr973728),
			ct.StateGet(id, constants.BlockPrefix+"973728"),
			"a refused replacement must leave the stored header as it was")
	})

	// NOT PROVEN BY RUNNING: the multi-header replaceBlocks loop. The same
	// validateDifficulty call is in it, carrying the parent header forward
	// (anchor for the first, the previously validated header after that), but
	// driving the loop needs TWO headers that chain to each other AND are both
	// mined at minimum difficulty against real mainnet parents. The repo has two
	// mined forgeries and neither chains to the other, and mining a chaining
	// pair is ~4 minutes of CPU each. A one-header replaceBlocks call delegates
	// to HandleReplaceBlock, so it would exercise the single path again and
	// prove nothing about the loop. Code-read only; flagged rather than faked.
}
