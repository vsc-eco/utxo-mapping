package current_test

import (
	dashMapping "dash-mapping-contract"
	"dash-mapping-contract/contract/blocklist"
	"dash-mapping-contract/contract/constants"
	"dash-mapping-contract/contract/mapping"
	"encoding/binary"
	"encoding/json"
	"math/bits"
	"strings"
	"testing"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func encodeBalance(t *testing.T, amount int64) string {
	t.Helper()
	if amount == 0 {
		return ""
	}
	v := uint64(amount)
	n := (bits.Len64(v) + 7) / 8
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return string(buf[8-n:])
}

var ContractWasm = dashMapping.DevWasm

const testContractId = "mapping_contract"
const testOwner = "hive:milo-hpr"

// Block headers use the same 80-byte wire format as Bitcoin.
// DASH skips PoW validation (X11 not in btcsuite), so any valid-format headers
// with correct prev-block linkage will work.
const lastBlockHeight = "116087"
const lastBlockHeader = "00c0a520165303733ee5b0561d46da9dcce685fd12a807d64472931c46d5920c00000000c96f929654fc44fb69783b6cc4f2340ad85de5b10c5047836561901299ed23d162525469ffff001dda00dd53"
const twoBlocksPayload = `{"blocks":"00c0fa213b04801d1b66efcf8f41290a675777893f5c6ac158a585654263ba0900000000fdf6162d92eee3af012f1ddab30a401bb371a0da32371d185fc25eb3655fd6d013575469ffff001db80220f80000002002883f9d7847a35a0d371cd11bf95c0f9d252ed41f46dde04172bf0c000000003d2af3ae86b3638665e6214df4dc12712fd7486348c3c319cedb3c69bc8a4ddac45b5469ffff001d1adfdc74","latest_fee":1}`

type ctWrapper struct {
	ct *test_utils.ContractTest
}

func callAction(t *testing.T, w *ctWrapper, action string, payload string, caller string) test_utils.ContractTestCallResult {
	return callActionOnContract(t, w, testContractId, action, payload, caller)
}

func callActionOnContract(t *testing.T, w *ctWrapper, contractId string, action string, payload string, caller string) test_utils.ContractTestCallResult {
	t.Helper()
	if caller == "" {
		caller = testOwner
	}
	return w.ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, caller),
		ContractId: contractId,
		Action:     action,
		Payload:    json.RawMessage([]byte(payload)),
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
		Caller:     caller,
	})
}

func seedBlocksViaState(w *ctWrapper) {
	seedBlocksViaStateForContract(w, testContractId)
}

func seedBlocksViaStateForContract(w *ctWrapper, contractId string) {
	w.ct.StateSet(contractId, blocklist.LastHeightKey, lastBlockHeight)
	w.ct.StateSet(contractId, constants.BlockPrefix+lastBlockHeight, lastBlockHeader)
	w.ct.StateSet(contractId, "sply", `{"active_supply":0,"user_supply":0,"fee_supply":0,"base_fee_rate":1}`)
}

// TestAllOperations runs all contract tests within a single ContractTest
// to avoid Badger DB lock conflicts.
func TestAllOperations(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	ct.RegisterContract(testContractId, testOwner, ContractWasm)
	w := &ctWrapper{ct: &ct}

	// ========== SeedBlocks ==========

	t.Run("SeedBlocks_NonOwnerFails", func(t *testing.T) {
		r := callAction(t, w, "seedBlocks", `{"block_header":"aa","block_height":100}`, "hive:attacker")
		assert.False(t, r.Success, "seedBlocks by non-owner should fail")
	})

	t.Run("SeedBlocks_OwnerSucceeds", func(t *testing.T) {
		payload := `{"block_header":"` + lastBlockHeader + `","block_height":` + lastBlockHeight + `}`
		r := callAction(t, w, "seedBlocks", payload, "")
		require.True(t, r.Success, "seedBlocks by owner should succeed: %s %s", r.Err, r.ErrMsg)
		assert.Contains(t, r.Ret, "last height:")
	})

	// ========== AddBlocks ==========

	seedBlocksViaState(w)

	t.Run("AddBlocks_NonOwnerFails", func(t *testing.T) {
		r := callAction(t, w, "addBlocks", twoBlocksPayload, "hive:attacker")
		assert.False(t, r.Success, "addBlocks by non-owner should fail")
	})

	t.Run("AddBlocks_InvalidHexFails", func(t *testing.T) {
		r := callAction(t, w, "addBlocks", `{"blocks":"ZZZZ","latest_fee":1}`, "")
		assert.False(t, r.Success, "addBlocks with invalid hex should fail")
	})

	t.Run("AddBlocks_WrongLengthFails", func(t *testing.T) {
		shortBlock := strings.Repeat("00", 79)
		r := callAction(t, w, "addBlocks", `{"blocks":"`+shortBlock+`","latest_fee":1}`, "")
		assert.False(t, r.Success, "addBlocks with wrong length (79 bytes) should fail")
	})

	t.Run("AddBlocks_81BytesFails", func(t *testing.T) {
		longBlock := strings.Repeat("00", 81)
		r := callAction(t, w, "addBlocks", `{"blocks":"`+longBlock+`","latest_fee":1}`, "")
		assert.False(t, r.Success, "addBlocks with 81-byte block should fail")
	})

	t.Run("AddBlocks_WrongSequenceReportsError", func(t *testing.T) {
		seedBlocksViaState(w)
		fakeBlock := strings.Repeat("00", 80)
		r := callAction(t, w, "addBlocks", `{"blocks":"`+fakeBlock+`","latest_fee":1}`, "")
		// Contract treats sequence errors as soft errors (returns success with error in message)
		if r.Success {
			assert.Contains(t, r.Ret, "error adding blocks")
		}
	})

	t.Run("AddBlocks_EmptyBlocksNoOp", func(t *testing.T) {
		seedBlocksViaState(w)
		r := callAction(t, w, "addBlocks", `{"blocks":"","latest_fee":1}`, "")
		if r.Success {
			assert.Contains(t, r.Ret, "last height:")
		}
	})

	t.Run("AddBlocks_NoSeedFails", func(t *testing.T) {
		freshId := "fresh_blocklist"
		w.ct.RegisterContract(freshId, testOwner, ContractWasm)
		w.ct.StateSet(freshId, "sply", `{"active_supply":0,"user_supply":0,"fee_supply":0,"base_fee_rate":1}`)
		r := callActionOnContract(t, w, freshId, "addBlocks", twoBlocksPayload, "")
		assert.False(t, r.Success, "addBlocks without seed should fail")
	})

	t.Run("AddBlocks_ValidChainSucceeds", func(t *testing.T) {
		// DASH skips PoW validation, so valid-format headers with correct
		// prev-block linkage should succeed.
		seedBlocksViaState(w)
		r := callAction(t, w, "addBlocks", twoBlocksPayload, "")
		require.True(t, r.Success, "addBlocks with valid chain should succeed: %s %s", r.Err, r.ErrMsg)
		assert.Contains(t, r.Ret, "last height:")
	})

	// ========== RegisterPublicKey ==========

	t.Run("RegisterPublicKey_Success", func(t *testing.T) {
		payload := `{"primary_public_key":"0242f9da15eae56fe6aca65136738905c0afdb2c4edf379e107b3b00b98c7fc9f0","backup_public_key":"0332e9f22cfa2f6233c059c4d54700e3d00df3d7f55e3ea16207b860360446634f"}`
		r := callAction(t, w, "registerPublicKey", payload, "")
		require.True(t, r.Success, "registerPublicKey should succeed: %s %s", r.Err, r.ErrMsg)
		assert.Contains(t, r.Ret, "set primary key")
		assert.Contains(t, r.Ret, "set backup key")
	})

	t.Run("RegisterPublicKey_NonOwnerFails", func(t *testing.T) {
		payload := `{"primary_public_key":"0242f9da15eae56fe6aca65136738905c0afdb2c4edf379e107b3b00b98c7fc9f0"}`
		r := callAction(t, w, "registerPublicKey", payload, "hive:attacker")
		assert.False(t, r.Success, "registerPublicKey by non-owner should fail")
	})

	t.Run("RegisterPublicKey_InvalidHexFails", func(t *testing.T) {
		payload := `{"primary_public_key":"ZZZZZZ"}`
		r := callAction(t, w, "registerPublicKey", payload, "")
		assert.False(t, r.Success, "registerPublicKey with invalid hex should fail")
	})

	t.Run("RegisterPublicKey_WrongLengthFails", func(t *testing.T) {
		payload := `{"primary_public_key":"02` + strings.Repeat("aa", 31) + `"}`
		r := callAction(t, w, "registerPublicKey", payload, "")
		assert.False(t, r.Success, "registerPublicKey with 32-byte key should fail")
	})

	t.Run("RegisterPublicKey_BadPrefixFails", func(t *testing.T) {
		// 33 bytes with 0x04 prefix (should be 0x02 or 0x03 for compressed)
		payload := `{"primary_public_key":"04` + strings.Repeat("aa", 32) + `"}`
		r := callAction(t, w, "registerPublicKey", payload, "")
		assert.False(t, r.Success, "registerPublicKey with bad compressed prefix should fail")
	})

	t.Run("RegisterPublicKey_EmptyIsNoOp", func(t *testing.T) {
		r := callAction(t, w, "registerPublicKey", `{}`, "")
		require.True(t, r.Success, "empty registerPublicKey should succeed")
	})

	// ========== CreateKeyPair ==========

	t.Run("CreateKeyPair_OwnerCanCall", func(t *testing.T) {
		r := callAction(t, w, "createKeyPair", `""`, "")
		t.Logf("createKeyPair result: success=%v err=%s", r.Success, r.Err)
	})

	t.Run("CreateKeyPair_NonOwnerFails", func(t *testing.T) {
		r := callAction(t, w, "createKeyPair", `""`, "hive:attacker")
		assert.False(t, r.Success, "createKeyPair by non-owner should fail")
	})

	// ========== RegisterRouter ==========

	t.Run("RegisterRouter_Success", func(t *testing.T) {
		payload := `{"router_contract":"vsc1abc123"}`
		r := callAction(t, w, "registerRouter", payload, "")
		require.True(t, r.Success, "registerRouter should succeed: %s %s", r.Err, r.ErrMsg)
		assert.Contains(t, r.Ret, "set router contract ID")
	})

	t.Run("RegisterRouter_NonOwnerFails", func(t *testing.T) {
		payload := `{"router_contract":"vsc1abc123"}`
		r := callAction(t, w, "registerRouter", payload, "hive:attacker")
		assert.False(t, r.Success, "registerRouter by non-owner should fail")
	})

	t.Run("RegisterRouter_EmptyIdIsNoOp", func(t *testing.T) {
		r := callAction(t, w, "registerRouter", `{}`, "")
		require.True(t, r.Success, "registerRouter with empty id should succeed")
	})

	// ========== Transfer ==========

	t.Run("Transfer_InsufficientBalanceFails", func(t *testing.T) {
		w.ct.StateSet(testContractId, mapping.BalancePrefix+"hive:milo-hpr", encodeBalance(t, 100))
		payload := `{"amount":5000,"to":"hive:recipient"}`
		r := callAction(t, w, "transfer", payload, "")
		assert.False(t, r.Success, "transfer with insufficient balance should fail")
	})

	t.Run("Transfer_InvalidPayloadFails", func(t *testing.T) {
		r := callAction(t, w, "transfer", `not json`, "")
		assert.False(t, r.Success, "transfer with invalid JSON should fail")
	})

	t.Run("Transfer_ZeroAmountFails", func(t *testing.T) {
		w.ct.StateSet(testContractId, mapping.BalancePrefix+"hive:milo-hpr", encodeBalance(t, 1000))
		payload := `{"amount":0,"to":"hive:recipient"}`
		r := callAction(t, w, "transfer", payload, "")
		assert.False(t, r.Success, "transfer with zero amount should fail")
	})

	t.Run("Transfer_NegativeAmountFails", func(t *testing.T) {
		w.ct.StateSet(testContractId, mapping.BalancePrefix+"hive:milo-hpr", encodeBalance(t, 1000))
		payload := `{"amount":-100,"to":"hive:recipient"}`
		r := callAction(t, w, "transfer", payload, "")
		assert.False(t, r.Success, "transfer with negative amount should fail")
	})

	t.Run("Transfer_EmptyRecipientFails", func(t *testing.T) {
		w.ct.StateSet(testContractId, mapping.BalancePrefix+"hive:milo-hpr", encodeBalance(t, 1000))
		payload := `{"amount":100,"to":""}`
		r := callAction(t, w, "transfer", payload, "")
		assert.False(t, r.Success, "transfer with empty recipient should fail")
	})

	// ========== Unmap ==========

	t.Run("Unmap_InvalidPayloadFails", func(t *testing.T) {
		r := callAction(t, w, "unmap", `not json`, "")
		assert.False(t, r.Success, "unmap with invalid JSON should fail")
	})

	t.Run("Unmap_ZeroAmountFails", func(t *testing.T) {
		payload := `{"amount":0,"to":"XqMkVUZnqe3w4xvgdZRtZoe7gMitDudGs4"}`
		r := callAction(t, w, "unmap", payload, "")
		assert.False(t, r.Success, "unmap with zero amount should fail")
	})

	t.Run("Unmap_InsufficientBalanceFails", func(t *testing.T) {
		w.ct.StateSet(testContractId, mapping.BalancePrefix+"hive:milo-hpr", encodeBalance(t, 100))
		payload := `{"amount":99999,"to":"XqMkVUZnqe3w4xvgdZRtZoe7gMitDudGs4"}`
		r := callAction(t, w, "unmap", payload, "")
		assert.False(t, r.Success, "unmap with insufficient balance should fail")
	})

	// ========== Map ==========

	t.Run("Map_InvalidPayloadFails", func(t *testing.T) {
		r := callAction(t, w, "map", `not json`, "")
		assert.False(t, r.Success, "map with invalid JSON should fail")
	})

	// ========== TransferFrom ==========

	t.Run("TransferFrom_InvalidPayloadFails", func(t *testing.T) {
		r := callAction(t, w, "transferFrom", `not json`, "")
		assert.False(t, r.Success, "transferFrom with invalid JSON should fail")
	})

	t.Run("TransferFrom_InsufficientBalanceFails", func(t *testing.T) {
		w.ct.StateSet(testContractId, mapping.BalancePrefix+"hive:milo-hpr", encodeBalance(t, 100))
		payload := `{"amount":5000,"to":"hive:recipient"}`
		r := callAction(t, w, "transferFrom", payload, "")
		assert.False(t, r.Success, "transferFrom with insufficient balance should fail")
	})
}
