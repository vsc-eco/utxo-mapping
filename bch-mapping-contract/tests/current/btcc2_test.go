package current_test

import (
	"bch-mapping-contract/contract/constants"
	"bch-mapping-contract/contract/mapping"
	"fmt"
	"testing"
	"time"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Pentest finding BTC-C2 (resolved by keeping, not clearing, the observed-tx
// list on block replacement).
//
// replaceBlock / replaceBlocks overwrite the canonical header at a height but
// deliberately leave the per-height observed-tx list (ObservedBlockPrefix+H)
// in place. The observed list is the *only* double-mint guard — UTXOs are
// keyed by sequential internal id, not by (txid,vout) — so if a reorg re-mines
// the same deposit tx into the replacement block at the same height, clearing
// the list would let a permissionless second `map` credit the deposit twice.
//
// This test pins that protection. It performs a real deposit against block B1
// at the tip, then replaces B1 with a *different* block B2 (different hash,
// same height) that still commits to the same tx (single-tx block →
// MerkleRoot == TxHash, so the same empty Merkle proof validates against both).
// A second `map` of the same tx against the replacement must be a no-op: the
// surviving observed entry blocks it and the depositor's balance is unchanged.
//
// It replaces the two former BTCC2_*_ClearsObservedTxList tests, which asserted
// the now-removed (and unsafe) "delete the observed list on replace" behaviour.
func TestBTCC2_RepeatedTxInReplacedBlockNoDoubleMint(t *testing.T) {
	const instruction = "deposit_to=hive:milo-depositor"
	const recipient = "hive:milo-depositor"
	const amount int64 = 10_000
	const anchorHeight = "100" // H-1: the block the replacement must chain to
	const tipHeight = "101"    // H: the deposit's containing block (the tip)
	const tipHeightNum = uint32(101)

	// Deposit tx paying `amount` to the contract's deposit address for the
	// instruction. The contract derives the same address from Instructions,
	// so the output is recognised as a relevant deposit.
	depositAddr, _, err := mapping.DepositAddress(
		TestPrimaryPubKeyHex, TestBackupPubKeyHex, instruction, regtestParams(),
	)
	require.NoError(t, err, "derive deposit address")
	tx := buildTestTx(t, depositAddr, amount)
	txHash := tx.TxHash()
	rawTxHex := serializeTx(t, tx)

	// Anchor header at H-1 (regtest PoW; merkle root irrelevant, never mapped).
	seedTs := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	seed := buildRegtestHeader(chainhash.Hash{}, chainhash.Hash{}, seedTs)
	seedHash := seed.BlockHash()

	// Two distinct blocks at the tip height H, both chaining to the anchor and
	// both committing to the same deposit tx (MerkleRoot == txHash). Different
	// timestamps → different block hashes → a genuine reorg replacement.
	blockOrig := buildRegtestHeader(seedHash, txHash, seedTs.Add(10*time.Minute))
	blockReplace := buildRegtestHeader(seedHash, txHash, seedTs.Add(20*time.Minute))
	require.NotEqual(t, blockOrig.BlockHash(), blockReplace.BlockHash(),
		"original and replacement blocks must be distinct to simulate a reorg")

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })

	const contractId = "btc_mapping_for_btcc2"
	// testOwner is the contract owner, which is also the admin on regtest and
	// therefore the authorised caller for replaceBlocks.
	ct.RegisterContract(contractId, testOwner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, tipHeight)
	ct.StateSet(contractId, constants.BlockPrefix+anchorHeight, serializeHeaderRaw(t, seed))
	ct.StateSet(contractId, constants.BlockPrefix+tipHeight, serializeHeaderRaw(t, blockOrig))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	require.Empty(t, ct.StateGet(contractId, constants.BalancePrefix+recipient),
		"precondition: depositor starts with zero balance")

	mapPayload, err := tinyjson.Marshal(mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    tipHeightNum,
			RawTxHex:       rawTxHex,
			MerkleProofHex: "",
			TxIndex:        0,
		},
		Instructions: []string{instruction},
	})
	require.NoError(t, err, "marshal map params")

	doMap := func(txId, blockId string) test_utils.ContractTestCallResult {
		return ct.Call(stateEngine.TxVscCallContract{
			Self: stateEngine.TxSelf{
				TxId:                 txId,
				BlockId:              blockId,
				Index:                0,
				OpIndex:              0,
				Timestamp:            "2026-05-07T00:00:00",
				RequiredAuths:        []string{recipient},
				RequiredPostingAuths: []string{},
			},
			ContractId: contractId,
			Action:     "map",
			Payload:    mapPayload,
			RcLimit:    10000,
			Intents:    []contracts.Intent{},
			Caller:     recipient,
		})
	}

	// --- 1. First deposit against the original block credits the depositor once.
	r1 := doMap("btcc2-map-1", "block:btcc2-1")
	require.True(t, r1.Success, "first map should succeed: %s %s", r1.Err, r1.ErrMsg)
	require.Equal(t, amount, decodeBalance(t, ct.StateGet(contractId, constants.BalancePrefix+recipient)),
		"first map must credit the deposit exactly once")

	// Sanity: the deposit registered an observed entry at the tip height.
	require.NotEmpty(t, ct.StateGet(contractId, constants.ObservedBlockPrefix+tipHeight),
		"first map must record an observed-tx entry at the tip height")

	// --- 2. Reorg: replace the tip block with a different block that still
	//        contains the same tx.
	rr := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "btcc2-replace",
			BlockId:              "block:btcc2-replace",
			Index:                0,
			OpIndex:              0,
			Timestamp:            "2026-05-07T00:01:00",
			RequiredAuths:        []string{testOwner},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "replaceBlocks",
		Payload:    []byte(serializeHeader(t, blockReplace)),
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
		Caller:     testOwner,
	})
	require.True(t, rr.Success, "replaceBlocks should succeed: %s %s", rr.Err, rr.ErrMsg)
	require.Equal(t, serializeHeaderRaw(t, blockReplace), ct.StateGet(contractId, constants.BlockPrefix+tipHeight),
		"tip header must be overwritten by the replacement block")
	// The observed-tx list MUST survive the replacement — that is the guard.
	require.NotEmpty(t, ct.StateGet(contractId, constants.ObservedBlockPrefix+tipHeight),
		"observed-tx list must persist across replaceBlocks (it is the double-mint guard)")

	// --- 3. Re-mapping the same tx against the replacement block is a no-op.
	//        The Merkle proof still validates (same MerkleRoot), but the
	//        surviving observed entry blocks a second credit.
	r2 := doMap("btcc2-map-2", "block:btcc2-2")
	require.True(t, r2.Success, "second map should succeed as a no-op: %s %s", r2.Err, r2.ErrMsg)

	postBal := decodeBalance(t, ct.StateGet(contractId, constants.BalancePrefix+recipient))
	assert.Equal(t, amount, postBal,
		"BTC-C2: re-mapping a tx re-included in a replaced block must NOT double-mint; "+
			"balance is %d, want %d (single credit)", postBal, amount)

	fmt.Printf("btc-c2 verified: tx re-included after replaceBlocks credited once (balance=%d)\n", postBal)
}
