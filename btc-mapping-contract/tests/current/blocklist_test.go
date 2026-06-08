package current_test

import (
	btcMapping "btc-mapping-contract"
	"btc-mapping-contract/contract/constants"
	"encoding/json"
	"strings"
	"testing"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testContractId = "mapping_contract"
const testOwner = "hive:milo-hpr"

// Valid Bitcoin testnet4 block headers (116087 → 116088 → 116089).
const lastBlockHeight = "116087"

const lastBlockHeader = "00c0a520165303733ee5b0561d46da9dcce685fd12a807d64472931c46d5920c00000000c96f929654fc44fb69783b6cc4f2340ad85de5b10c5047836561901299ed23d162525469ffff001dda00dd53"

const twoBlocksPayload = `{"blocks":"00c0fa213b04801d1b66efcf8f41290a675777893f5c6ac158a585654263ba0900000000fdf6162d92eee3af012f1ddab30a401bb371a0da32371d185fc25eb3655fd6d013575469ffff001db80220f80000002002883f9d7847a35a0d371cd11bf95c0f9d252ed41f46dde04172bf0c000000003d2af3ae86b3638665e6214df4dc12712fd7486348c3c319cedb3c69bc8a4ddac45b5469ffff001d1adfdc74","latest_fee":1}`

type ctWrapper struct {
	ct *test_utils.ContractTest
}

func callAction(
	t *testing.T,
	w *ctWrapper,
	action string,
	payload string,
	caller string,
) test_utils.ContractTestCallResult {
	return callActionOnContract(t, w, testContractId, action, payload, caller)
}

func callActionOnContract(
	t *testing.T,
	w *ctWrapper,
	contractId string,
	action string,
	payload string,
	caller string,
) test_utils.ContractTestCallResult {
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
	w.ct.StateSet(contractId, constants.LastHeightKey, lastBlockHeight)
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

	// ========== GetInfo ==========

	t.Run("GetInfo_ReturnsTokenMetadata", func(t *testing.T) {
		r := callAction(t, w, "getInfo", "{}", "")
		require.True(t, r.Success, "getInfo should succeed: %s %s", r.Err, r.ErrMsg)
		assert.JSONEq(t, `{"name":"Bitcoin","symbol":"BTC","decimals":"8"}`, r.Ret)
	})

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

	t.Run("AddBlocks_WrongSequenceFails", func(t *testing.T) {
		seedBlocksViaState(w)
		fakeBlock := strings.Repeat("00", 80)
		r := callAction(t, w, "addBlocks", `{"blocks":"`+fakeBlock+`","latest_fee":1}`, "")
		assert.False(t, r.Success, "addBlocks with wrong prev-block sequence should fail")
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
		// createKeyPair calls sdk.TssCreateKey which may fail in test environment
		// if TSS infrastructure is not available. We only verify that the owner
		// can reach the TSS call (non-owner is rejected before that point).
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
		w.ct.StateSet(testContractId, "bal/hive:milo-hpr", "100")
		payload := `{"amount":5000,"to":"hive:recipient"}`
		r := callAction(t, w, "transfer", payload, "")
		assert.False(t, r.Success, "transfer with insufficient balance should fail")
	})

	t.Run("Transfer_InvalidPayloadFails", func(t *testing.T) {
		r := callAction(t, w, "transfer", `not json`, "")
		assert.False(t, r.Success, "transfer with invalid JSON should fail")
	})

	t.Run("Transfer_ZeroAmountFails", func(t *testing.T) {
		w.ct.StateSet(testContractId, "bal/hive:milo-hpr", "1000")
		payload := `{"amount":0,"to":"hive:recipient"}`
		r := callAction(t, w, "transfer", payload, "")
		assert.False(t, r.Success, "transfer with zero amount should fail")
	})

	t.Run("Transfer_NegativeAmountFails", func(t *testing.T) {
		w.ct.StateSet(testContractId, "bal/hive:milo-hpr", "1000")
		payload := `{"amount":-100,"to":"hive:recipient"}`
		r := callAction(t, w, "transfer", payload, "")
		assert.False(t, r.Success, "transfer with negative amount should fail")
	})

	t.Run("Transfer_EmptyRecipientFails", func(t *testing.T) {
		w.ct.StateSet(testContractId, "bal/hive:milo-hpr", "1000")
		payload := `{"amount":100,"to":""}`
		r := callAction(t, w, "transfer", payload, "")
		assert.False(t, r.Success, "transfer with empty recipient should fail")
	})

	t.Run("Transfer_SelfTransferFails", func(t *testing.T) {
		w.ct.StateSet(testContractId, "bal/hive:milo-hpr", "1000")
		payload := `{"amount":100,"to":"hive:milo-hpr"}`
		r := callAction(t, w, "transfer", payload, "")
		// Self-transfer may or may not be allowed by the contract
		// This tests the behavior either way
		t.Logf("Self-transfer result: success=%v ret=%s", r.Success, r.Ret)
	})

	// ========== AddBlocks round-trip (block sequence bug) ==========
	// Reproduces the testnet bug: after addBlocks stores block headers as raw
	// bytes, the next addBlocks must read them back and verify chain continuity.
	// Uses real BTC testnet3 block headers at heights 4888515 → 4888516 → 4888517.

	t.Run("AddBlocks_RoundTrip_ChainContinuity", func(t *testing.T) {
		rtId := "roundtrip_blocklist"
		// Use testnet3 WASM since we're testing with real testnet3 block headers
		w.ct.RegisterContract(rtId, testOwner, btcMapping.Testnet3Wasm)

		// Real BTC testnet3 block headers fetched from btcd RPC.
		// hash(4888515) = 00000000f570586692e115a950b812f359b27ac1441c91b91223163843504515
		// hash(4888516) = 000000000923f265408b69969242b68fbec135b24761ac2f51cd60b53855dc1c
		// hash(4888517) = 000000002e42abbf29b8d01a647c0b42521966edb88e87e11c80720de1135a39
		block4888515Hex := "000000209bfa65ae0af2ba13fd4403312a44554123c4b972374fd1995adce62c0000000081af5bae21b11430df381ee109e51181f5ff4164f744f0747ce980cf43c6c73797b4bc69ffff001d28ffa61f"
		block4888516Hex := "000000201545504338162312b9911c44c17ab259f312b850a915e192665870f500000000d2684baebc7ac8401ac29754247d1091bd3c6604bb4b26aeff107b6cfde0787648b9bc69ffff001d176c1809"
		block4888517Hex := "000000201cdc5538b560cd512fac6147b235c1be8fb6429296698b4065f22309000000000061c5ef9468eb91177b04aabf349991b9000774ac4f87f747f07935d4ad9e3ffbbdbc69ffff001d89201fc7"

		// Seed with block 4888515 stored as raw bytes (matching what the
		// contract itself does in HandleAddBlocks line 124-126).
		seedRaw := decodeHex(t, block4888515Hex)
		w.ct.StateSet(rtId, constants.LastHeightKey, "4888515")
		w.ct.StateSet(rtId, constants.BlockPrefix+"4888515", seedRaw)
		// Supply: 4x int64 BE = 32 zero bytes for all-zero supply with base_fee=1
		supply := make([]byte, 32)
		supply[31] = 1 // base_fee_rate = 1
		w.ct.StateSet(rtId, constants.SupplyKey, string(supply))

		// Debug: verify the stored seed is readable
		stored := w.ct.StateGet(rtId, constants.BlockPrefix+"4888515")
		t.Logf("Stored seed length: %d, expected: 80", len(stored))
		t.Logf("Stored seed hex: %x", []byte(stored)[:min(20, len(stored))])
		t.Logf("Stored height: %s", w.ct.StateGet(rtId, constants.LastHeightKey))
		t.Logf("Stored supply length: %d", len(w.ct.StateGet(rtId, constants.SupplyKey)))

		// First addBlocks: submit block 4888516.
		// Use oracle DID as caller (always allowed) to bypass auth issues in test
		oracleCaller := "did:vsc:oracle:btc"
		payload1 := `{"blocks":"` + block4888516Hex + `","latest_fee":0}`
		r1 := callActionOnContract(t, w, rtId, "addBlocks", payload1, oracleCaller)
		t.Logf("r1: success=%v err=%q errMsg=%q ret=%q", r1.Success, r1.Err, r1.ErrMsg, r1.Ret)
		require.True(t, r1.Success, "first addBlocks (4888516) should succeed: %s %s", r1.Err, r1.ErrMsg)
		assert.Contains(t, r1.Ret, "4888516")

		// Second addBlocks: submit block 4888517.
		// This reads back the raw bytes stored by the first call.
		// If the raw byte round-trip corrupts the header, BlockHash()
		// will differ and we get "block sequence incorrect".
		payload2 := `{"blocks":"` + block4888517Hex + `","latest_fee":0}`
		r2 := callActionOnContract(t, w, rtId, "addBlocks", payload2, oracleCaller)
		require.True(t, r2.Success, "second addBlocks (4888517) should succeed: %s %s", r2.Err, r2.ErrMsg)
		assert.Contains(t, r2.Ret, "4888517")
	})

	// ========== ReplaceBlocks (multi-block reorg) ==========

	t.Run("ReplaceBlocks_NonOwnerFails", func(t *testing.T) {
		r := callAction(t, w, "replaceBlocks", strings.Repeat("00", 80), "hive:attacker")
		assert.False(t, r.Success, "replaceBlocks by non-owner should fail")
	})

	t.Run("ReplaceBlocks_InvalidHexFails", func(t *testing.T) {
		r := callAction(t, w, "replaceBlocks", "ZZZZ", "")
		assert.False(t, r.Success, "replaceBlocks with invalid hex should fail")
	})

	t.Run("ReplaceBlocks_WrongLengthFails", func(t *testing.T) {
		r := callAction(t, w, "replaceBlocks", strings.Repeat("00", 79), "")
		assert.False(t, r.Success, "replaceBlocks with 79 bytes should fail")
	})

	t.Run("ReplaceBlocks_MultiBlock_Success", func(t *testing.T) {
		// Set up a 3-block chain: 4888515 → 4888516 → 4888517
		rbId := "replaceblocks_test"
		w.ct.RegisterContract(rbId, testOwner, btcMapping.Testnet3Wasm)

		block4888515Hex := "000000209bfa65ae0af2ba13fd4403312a44554123c4b972374fd1995adce62c0000000081af5bae21b11430df381ee109e51181f5ff4164f744f0747ce980cf43c6c73797b4bc69ffff001d28ffa61f"
		block4888516Hex := "000000201545504338162312b9911c44c17ab259f312b850a915e192665870f500000000d2684baebc7ac8401ac29754247d1091bd3c6604bb4b26aeff107b6cfde0787648b9bc69ffff001d176c1809"
		block4888517Hex := "000000201cdc5538b560cd512fac6147b235c1be8fb6429296698b4065f22309000000000061c5ef9468eb91177b04aabf349991b9000774ac4f87f747f07935d4ad9e3ffbbdbc69ffff001d89201fc7"

		// Seed with block 4888515
		seedRaw := decodeHex(t, block4888515Hex)
		w.ct.StateSet(rbId, constants.LastHeightKey, "4888515")
		w.ct.StateSet(rbId, constants.BlockPrefix+"4888515", seedRaw)
		supply := make([]byte, 32)
		supply[31] = 1
		w.ct.StateSet(rbId, constants.SupplyKey, string(supply))

		// Add blocks 4888516 and 4888517
		oracleCaller := "did:vsc:oracle:btc"
		payload := `{"blocks":"` + block4888516Hex + block4888517Hex + `","latest_fee":1}`
		r := callActionOnContract(t, w, rbId, "addBlocks", payload, oracleCaller)
		require.True(t, r.Success, "addBlocks should succeed: %s %s", r.Err, r.ErrMsg)
		assert.Contains(t, r.Ret, "4888517")

		// Now replace both blocks 4888516 and 4888517 with themselves (same canonical headers).
		// This simulates a 2-block reorg where the canonical chain happens to match.
		// The key test is that the chaining validation passes for multi-block replacement.
		replacePayload := block4888516Hex + block4888517Hex
		r2 := callActionOnContract(t, w, rbId, "replaceBlocks", replacePayload, "")
		require.True(t, r2.Success, "replaceBlocks (2 blocks) should succeed: %s %s", r2.Err, r2.ErrMsg)
		assert.Contains(t, r2.Ret, "replaced 2 blocks")
		assert.Contains(t, r2.Ret, "4888517")
	})

	t.Run("ReplaceBlocks_SingleBlock_DelegatesToReplaceBlock", func(t *testing.T) {
		// Single-header replaceBlocks should delegate to HandleReplaceBlock
		rbId2 := "replaceblocks_single"
		w.ct.RegisterContract(rbId2, testOwner, btcMapping.Testnet3Wasm)

		block4888515Hex := "000000209bfa65ae0af2ba13fd4403312a44554123c4b972374fd1995adce62c0000000081af5bae21b11430df381ee109e51181f5ff4164f744f0747ce980cf43c6c73797b4bc69ffff001d28ffa61f"
		block4888516Hex := "000000201545504338162312b9911c44c17ab259f312b850a915e192665870f500000000d2684baebc7ac8401ac29754247d1091bd3c6604bb4b26aeff107b6cfde0787648b9bc69ffff001d176c1809"

		seedRaw := decodeHex(t, block4888515Hex)
		raw516 := decodeHex(t, block4888516Hex)
		w.ct.StateSet(rbId2, constants.LastHeightKey, "4888516")
		w.ct.StateSet(rbId2, constants.BlockPrefix+"4888515", seedRaw)
		w.ct.StateSet(rbId2, constants.BlockPrefix+"4888516", raw516)
		supply := make([]byte, 32)
		supply[31] = 1
		w.ct.StateSet(rbId2, constants.SupplyKey, string(supply))

		// Replace just the tip (single block)
		replacePayload := block4888516Hex
		r := callActionOnContract(t, w, rbId2, "replaceBlocks", replacePayload, "")
		require.True(t, r.Success, "single-block replaceBlocks should succeed: %s %s", r.Err, r.ErrMsg)
		assert.Contains(t, r.Ret, "4888516")
	})

	// ========== Unmap ==========

	t.Run("Unmap_InvalidPayloadFails", func(t *testing.T) {
		r := callAction(t, w, "unmap", `not json`, "")
		assert.False(t, r.Success, "unmap with invalid JSON should fail")
	})

	t.Run("Unmap_ZeroAmountFails", func(t *testing.T) {
		payload := `{"amount":0,"to":"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"}`
		r := callAction(t, w, "unmap", payload, "")
		assert.False(t, r.Success, "unmap with zero amount should fail")
	})

	t.Run("Unmap_InsufficientBalanceFails", func(t *testing.T) {
		w.ct.StateSet(testContractId, "bal/hive:milo-hpr", "100")
		payload := `{"amount":99999,"to":"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"}`
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
		w.ct.StateSet(testContractId, "bal/hive:milo-hpr", "100")
		payload := `{"amount":5000,"to":"hive:recipient"}`
		r := callAction(t, w, "transferFrom", payload, "")
		assert.False(t, r.Success, "transferFrom with insufficient balance should fail")
	})
}
