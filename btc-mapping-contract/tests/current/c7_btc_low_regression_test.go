package current_test

// C7 — btc-mapping-contract LOW-fix regression tests.
//
// These tests are the inverted WASM-RT proofs from the audit
// (LOW-btc-hivego-deploy.md). Each one FAILS against the unfixed contract and
// PASSES once the fix is built into bin/dev.wasm:
//
//   BTC-L-CONFIRMSPEND (contract/mapping/handlers.go HandleConfirmSpend):
//     A permissionless confirmSpend with empty or non-matching indices used to
//     promote zero UTXOs yet still run the unconditional signing-data cleanup,
//     wiping a pending withdrawal's signing context (griefing an in-flight spend).
//     Fixed by (a) rejecting empty indices up front and (b) only cleaning up when
//     at least one UTXO was actually promoted.
//
//   BTC-L-NEGFEE (contract/main.go AddBlocks):
//     The oracle-supplied LatestFee (int64) was only guarded with `== 0`, so a
//     negative value was written verbatim into BaseFeeRate (corrupt state).
//     Fixed by clamping any non-positive value (`<= 0`) to 1.

import (
	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"
	"testing"

	"vsc-node/lib/test_utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// BTC-L-CONFIRMSPEND
// ---------------------------------------------------------------------------

// TestC7_ConfirmSpendEmptyIndicesGriefReverts is the inverted griefing proof.
// A valid SPV proof for a pending spend's txId combined with an EMPTY indices
// slice must revert WITHOUT deleting the pending spend's signing data.
//
// Pre-fix behaviour (the bug): r.Success == true, signing data DELETED.
// Post-fix behaviour: r.Success == false, signing data PRESERVED.
func TestC7_ConfirmSpendEmptyIndicesGriefReverts(t *testing.T) {
	ct, contractId, fixture := setupConfirmSpendContract(t)

	// Sanity: signing data is present before the call.
	require.NotEmpty(t, ct.StateGet(contractId, constants.TxSpendsPrefix+fixture.TxId),
		"setup must leave signing data present for the pending spend")

	params := mapping.ConfirmSpendParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    fixture.BlockHeight,
			RawTxHex:       fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex,
			TxIndex:        fixture.TxIndex,
		},
		Indices: []uint32{}, // empty — the griefing input
	}

	// A random non-owner attacker, to prove the permissionless path is closed.
	r := callConfirmSpend(t, ct, contractId, "hive:random-attacker", params)

	assert.False(t, r.Success,
		"confirmSpend with empty indices must revert (cannot promote any UTXO)")
	assert.NotEmpty(t, r.Err, "revert must carry an error")

	// The pending withdrawal's signing context must still be intact.
	assert.NotEmpty(t, ct.StateGet(contractId, constants.TxSpendsPrefix+fixture.TxId),
		"signing data for the pending spend MUST NOT be deleted by an empty-indices confirmSpend")
}

// TestC7_ConfirmSpendNonMatchingIndicesReverts covers the second variant: the
// indices are non-empty but match no unconfirmed output of this tx (vout 0 is
// the only change output; we pass vout 99). Nothing is promoted, so the call
// must revert and leave the signing data intact.
func TestC7_ConfirmSpendNonMatchingIndicesReverts(t *testing.T) {
	ct, contractId, fixture := setupConfirmSpendContract(t)

	require.NotEmpty(t, ct.StateGet(contractId, constants.TxSpendsPrefix+fixture.TxId),
		"setup must leave signing data present for the pending spend")

	params := mapping.ConfirmSpendParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    fixture.BlockHeight,
			RawTxHex:       fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex,
			TxIndex:        fixture.TxIndex,
		},
		Indices: []uint32{99}, // valid proof, but no output at vout 99
	}

	r := callConfirmSpend(t, ct, contractId, "hive:random-attacker", params)

	assert.False(t, r.Success,
		"confirmSpend with non-matching indices must revert (cannot promote any UTXO)")
	assert.NotEmpty(t, r.Err, "revert must carry an error")
	assert.NotEmpty(t, ct.StateGet(contractId, constants.TxSpendsPrefix+fixture.TxId),
		"signing data MUST NOT be deleted when no output matched the indices")
}

// TestC7_ConfirmSpendLegitimateStillSucceeds is the don't-break-anything guard:
// the legitimate bot path (matching, non-empty indices) must still promote the
// UTXO and clean up the signing data. This mirrors the production mapping-bot,
// which always supplies non-empty indices derived from dbTx.Signatures.
func TestC7_ConfirmSpendLegitimateStillSucceeds(t *testing.T) {
	ct, contractId, fixture := setupConfirmSpendContract(t)

	require.NotEmpty(t, ct.StateGet(contractId, constants.TxSpendsPrefix+fixture.TxId),
		"setup must leave signing data present for the pending spend")

	params := mapping.ConfirmSpendParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    fixture.BlockHeight,
			RawTxHex:       fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex,
			TxIndex:        fixture.TxIndex,
		},
		Indices: []uint32{0}, // matches the unconfirmed change output at vout 0
	}

	r := callConfirmSpend(t, ct, contractId, "hive:milo-hpr", params)

	require.True(t, r.Success, "legitimate confirmSpend must still succeed: %s %s", r.Err, r.ErrMsg)
	assert.Empty(t, ct.StateGet(contractId, constants.TxSpendsPrefix+fixture.TxId),
		"signing data should be cleaned up after a successful promotion")
}

// ---------------------------------------------------------------------------
// BTC-L-NEGFEE
// ---------------------------------------------------------------------------

// readBaseFeeRate reads the persisted BaseFeeRate back out of contract state
// using the contract's own binary supply encoding (32-byte, four int64 BE).
func readBaseFeeRate(t *testing.T, ct *test_utils.ContractTest, contractId string) int64 {
	t.Helper()
	raw := ct.StateGet(contractId, constants.SupplyKey)
	require.NotEmpty(t, raw, "supply state must be present after addBlocks")
	supply, err := mapping.UnmarshalSupply([]byte(raw))
	require.NoError(t, err, "supply state must decode")
	return supply.BaseFeeRate
}

// seedForAddBlocks seeds the minimal state addBlocks needs: a last height, the
// matching seed header (stored as RAW 80 bytes, as HandleAddBlocks reads it back
// via BtcDecode), and a binary supply blob at SupplyKey (the key SupplyFromState
// actually reads). The two headers in addBlocksWithFee chain onto lastBlockHeader.
func seedForAddBlocks(t *testing.T, ct *test_utils.ContractTest, contractId string) {
	t.Helper()
	ct.StateSet(contractId, constants.LastHeightKey, lastBlockHeight)
	ct.StateSet(contractId, constants.BlockPrefix+lastBlockHeight, decodeHex(t, lastBlockHeader))
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
}

// addBlocksWithFee runs addBlocks as the owner with the given latest_fee and
// returns the call result. Uses the shared twoBlocksPayload's headers but with
// a custom fee value.
func addBlocksWithFee(t *testing.T, ct *test_utils.ContractTest, contractId, latestFee string) test_utils.ContractTestCallResult {
	t.Helper()
	w := &ctWrapper{ct: ct}
	payload := `{"blocks":"00c0fa213b04801d1b66efcf8f41290a675777893f5c6ac158a585654263ba0900000000fdf6162d92eee3af012f1ddab30a401bb371a0da32371d185fc25eb3655fd6d013575469ffff001db80220f80000002002883f9d7847a35a0d371cd11bf95c0f9d252ed41f46dde04172bf0c000000003d2af3ae86b3638665e6214df4dc12712fd7486348c3c319cedb3c69bc8a4ddac45b5469ffff001d1adfdc74","latest_fee":` + latestFee + `}`
	return callActionOnContract(t, w, contractId, "addBlocks", payload, "")
}

// TestC7_AddBlocksNegativeFeeClampedToOne is the inverted NEGFEE proof: an
// oracle addBlocks with latest_fee:-5 must store BaseFeeRate == 1, not -5.
//
// Pre-fix behaviour (the bug): BaseFeeRate == -5 in state.
// Post-fix behaviour: BaseFeeRate == 1.
func TestC7_AddBlocksNegativeFeeClampedToOne(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "negfee_contract"
	ct.RegisterContract(contractId, testOwner, ContractWasm)
	seedForAddBlocks(t, &ct, contractId)

	r := addBlocksWithFee(t, &ct, contractId, "-5")
	require.True(t, r.Success, "addBlocks must still succeed (fee clamped, not rejected): %s %s", r.Err, r.ErrMsg)

	assert.Equal(t, int64(1), readBaseFeeRate(t, &ct, contractId),
		"a negative latest_fee must be clamped to 1, never stored as a negative BaseFeeRate")
}

// TestC7_AddBlocksZeroFeeClampedToOne confirms the pre-existing zero clamp is
// preserved by the `<= 0` change (no regression of the original guard).
func TestC7_AddBlocksZeroFeeClampedToOne(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "zerofee_contract"
	ct.RegisterContract(contractId, testOwner, ContractWasm)
	seedForAddBlocks(t, &ct, contractId)

	r := addBlocksWithFee(t, &ct, contractId, "0")
	require.True(t, r.Success, "addBlocks must succeed with zero fee: %s %s", r.Err, r.ErrMsg)

	assert.Equal(t, int64(1), readBaseFeeRate(t, &ct, contractId),
		"a zero latest_fee must remain clamped to 1 (original guard preserved)")
}

// TestC7_AddBlocksPositiveFeePassesThrough is the don't-break-anything guard:
// a normal positive fee must be stored verbatim, unaffected by the clamp.
func TestC7_AddBlocksPositiveFeePassesThrough(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "posfee_contract"
	ct.RegisterContract(contractId, testOwner, ContractWasm)
	seedForAddBlocks(t, &ct, contractId)

	r := addBlocksWithFee(t, &ct, contractId, "6")
	require.True(t, r.Success, "addBlocks must succeed with positive fee: %s %s", r.Err, r.ErrMsg)

	assert.Equal(t, int64(6), readBaseFeeRate(t, &ct, contractId),
		"a positive latest_fee must pass through unchanged")
}
