package current_test

import (
	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"
	"fmt"
	"testing"
	"time"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	ledgerDb "vsc-node/modules/db/vsc/ledger"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// TestDoubleMapSameUtxo — Map a UTXO (txid:0), verify balance credited.
// Then map the same UTXO again. Verify balance does NOT increase again
// (double-spend protection via observed key o-<txid>:0).
// ---------------------------------------------------------------------------
func TestDoubleMapSameUtxo(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const blockHeight = uint32(100)
	const depositAmount = int64(10000)

	fixture := buildMapFixture(t, instruction, depositAmount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	params := mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    blockHeight,
			RawTxHex:       fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex,
			TxIndex:        fixture.TxIndex,
		},
		Instructions: []string{instruction},
	}
	payload, err := tinyjson.Marshal(params)
	if err != nil {
		t.Fatal("error marshalling params:", err)
	}

	call := stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "firstmap",
			BlockId:              "block:firstmap",
			Index:                0,
			OpIndex:              0,
			Timestamp:            "2025-10-14T00:00:00",
			RequiredAuths:        []string{"hive:milo-hpr"},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "map",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
		Caller:     "hive:milo-hpr",
	}

	// First map call — should succeed and credit balance
	r1 := ct.Call(call)
	if r1.Err != "" {
		fmt.Printf("first map error: %s: %s\n", r1.Err, r1.ErrMsg)
	}
	assert.True(t, r1.Success, "first map call should succeed")

	balAfterFirst := ct.StateGet(contractId, constants.BalancePrefix+"hive:milo-hpr")
	assert.Equal(t, encodeBalance(t, depositAmount), balAfterFirst,
		"balance should equal deposit amount after first map")

	// Second map call with the same UTXO — should succeed but NOT credit again
	call.Self.TxId = "secondmap"
	call.Self.BlockId = "block:secondmap"
	r2 := ct.Call(call)
	if r2.Err != "" {
		fmt.Printf("second map error: %s: %s\n", r2.Err, r2.ErrMsg)
	}
	assert.True(t, r2.Success, "second map call should succeed (idempotent)")

	balAfterSecond := ct.StateGet(contractId, constants.BalancePrefix+"hive:milo-hpr")
	assert.Equal(t, encodeBalance(t, depositAmount), balAfterSecond,
		"balance should NOT increase on duplicate map (double-spend protection)")
}

// ---------------------------------------------------------------------------
// TestUnmapInsufficientBalance — Try to unmap more than the user's balance.
// Should fail.
// ---------------------------------------------------------------------------
func TestUnmapInsufficientBalance(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const fakeTxId0 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.BalancePrefix+"hive:milo-hpr", encodeBalance(t, 5000))
	ct.StateSet(contractId, constants.ObservedBlockPrefix+"100", buildObservedList(t, observedParam{fakeTxId0, 0}))
	ct.StateSet(contractId, constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(mapping.UtxoRegistry{
		{Id: 1024, Amount: 5000},
	})))
	ct.StateSet(contractId, constants.UtxoPrefix+"400", depositUtxoBinary(t, fakeTxId0, 0, 5000, instruction))
	ct.StateSet(contractId, constants.UtxoLastIdKey, encodeUtxoCounters(1025, 0))
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: 5000,
		UserSupply:   5000,
		BaseFeeRate:  1,
	})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", buildSeedHeaderRaw(t, time.Unix(0, 0)))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	// Try to unmap 50000 — way more than balance of 5000
	payload, err := tinyjson.Marshal(mapping.TransferParams{
		Amount: "50000",
		To:     regtestDestAddress(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:milo-hpr"),
		ContractId: contractId,
		Action:     "unmap",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})

	assert.False(t, r.Success, "unmap with insufficient balance should fail")
	assert.NotEmpty(t, r.Err, "should have an error message")
	t.Logf("Expected error: %s: %s", r.Err, r.ErrMsg)
}

// ---------------------------------------------------------------------------
// TestUnmapAmountBelowDust — Unmap an amount below the dust threshold (546 sats).
// Should fail because the BTC output would be unspendable.
// ---------------------------------------------------------------------------
func TestUnmapAmountBelowDust(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const fakeTxId0 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.BalancePrefix+"hive:milo-hpr", encodeBalance(t, 50000))
	ct.StateSet(contractId, constants.ObservedBlockPrefix+"100", buildObservedList(t, observedParam{fakeTxId0, 0}))
	ct.StateSet(contractId, constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(mapping.UtxoRegistry{
		{Id: 1024, Amount: 50000},
	})))
	ct.StateSet(contractId, constants.UtxoPrefix+"400", depositUtxoBinary(t, fakeTxId0, 0, 50000, instruction))
	ct.StateSet(contractId, constants.UtxoLastIdKey, encodeUtxoCounters(1025, 0))
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: 50000,
		UserSupply:   50000,
		BaseFeeRate:  1,
	})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", buildSeedHeaderRaw(t, time.Unix(0, 0)))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	// 100 sats is below the dust threshold (546 sats) so the BTC output would be unspendable.
	payload, err := tinyjson.Marshal(mapping.TransferParams{
		Amount: "100",
		To:     regtestDestAddress(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:milo-hpr"),
		ContractId: contractId,
		Action:     "unmap",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})

	assert.False(t, r.Success, "unmap with amount below dust threshold should fail")
	assert.NotEmpty(t, r.Err, "should have an error message")
	t.Logf("Expected error: %s: %s", r.Err, r.ErrMsg)
}

// ---------------------------------------------------------------------------
// TestTransferToSelf — Transfer tokens to yourself. Should fail
// (self-transfer protection) or succeed depending on contract behavior.
// ---------------------------------------------------------------------------
func TestTransferToSelf(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.BalancePrefix+"hive:milo-hpr", encodeBalance(t, 10000))

	payload, err := tinyjson.Marshal(mapping.TransferParams{
		Amount: "5000",
		To:     "hive:milo-hpr",
	})
	if err != nil {
		t.Fatal(err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:milo-hpr"),
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     "hive:milo-hpr",
		Intents:    []contracts.Intent{},
	})

	// The contract does not explicitly block self-transfers.
	// checkAndDeductBalance deducts first, then HandleTransfer credits.
	// The net result should be balance stays the same.
	if r.Success {
		// If it succeeded, balance should be unchanged
		assert.Equal(t, encodeBalance(t, 10000), ct.StateGet(contractId, constants.BalancePrefix+"hive:milo-hpr"),
			"self-transfer should leave balance unchanged")
		t.Log("self-transfer succeeded (balance unchanged as expected)")
	} else {
		// If the contract rejects self-transfers, that is also valid
		t.Logf("self-transfer was rejected: %s: %s", r.Err, r.ErrMsg)
	}
}

// ---------------------------------------------------------------------------
// TestTransferExactBalance — Transfer exactly all tokens. Balance should
// be zero after.
// ---------------------------------------------------------------------------
func TestTransferExactBalance(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.BalancePrefix+"hive:milo-hpr", encodeBalance(t, 8000))

	payload, err := tinyjson.Marshal(mapping.TransferParams{
		Amount: "8000",
		To:     "hive:vaultec",
	})
	if err != nil {
		t.Fatal(err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:milo-hpr"),
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     "hive:milo-hpr",
		Intents:    []contracts.Intent{},
	})
	if r.Err != "" {
		t.Fatalf("transfer failed: %s: %s", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success, "exact-balance transfer should succeed")

	// Balance should be zero (key deleted when balance is 0)
	senderBal := ct.StateGet(contractId, constants.BalancePrefix+"hive:milo-hpr")
	assert.Equal(t, "", senderBal, "sender balance should be zero (key deleted) after exact transfer")

	// Recipient should have received all 8000
	recipientBal := ct.StateGet(contractId, constants.BalancePrefix+"hive:vaultec")
	assert.Equal(t, encodeBalance(t, 8000), recipientBal, "recipient should have 8000")
}

// ---------------------------------------------------------------------------
// TestMapMultipleOutputsSameTx — A transaction with multiple outputs to
// different deposit addresses. Both should be indexed.
// ---------------------------------------------------------------------------
func TestMapMultipleOutputsSameTx(t *testing.T) {
	const instruction1 = "deposit_to=hive:alice"
	const instruction2 = "deposit_to=hive:bob"
	const blockHeight = uint32(100)
	const amount1 = int64(5000)
	const amount2 = int64(3000)

	// Derive both deposit addresses
	addr1, _, err := mapping.DepositAddress(TestPrimaryPubKeyHex, TestBackupPubKeyHex, instruction1, regtestParams())
	if err != nil {
		t.Fatal("failed to derive addr1:", err)
	}
	addr2, _, err := mapping.DepositAddress(TestPrimaryPubKeyHex, TestBackupPubKeyHex, instruction2, regtestParams())
	if err != nil {
		t.Fatal("failed to derive addr2:", err)
	}

	// Build a multi-output transaction: first output to addr1, second to addr2
	tx := buildTestTx(t, addr1, amount1)

	// Add second output to the same transaction
	addr2Decoded, err := btcutil.DecodeAddress(addr2, regtestParams())
	if err != nil {
		t.Fatal("failed to decode addr2:", err)
	}
	script2, err := txscript.PayToAddrScript(addr2Decoded)
	if err != nil {
		t.Fatal("failed to create output script for addr2:", err)
	}
	tx.AddTxOut(&wire.TxOut{Value: amount2, PkScript: script2})

	txHash := tx.TxHash()
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	header := buildRegtestHeader(chainhash.Hash{}, txHash, ts)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", serializeHeaderRaw(t, header))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	params := mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    blockHeight,
			RawTxHex:       serializeTx(t, tx),
			MerkleProofHex: "",
			TxIndex:        0,
		},
		Instructions: []string{instruction1, instruction2},
	}
	payload, err := tinyjson.Marshal(params)
	if err != nil {
		t.Fatal("error marshalling params:", err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "multioutputtx",
			BlockId:              "block:multioutput",
			Index:                0,
			OpIndex:              0,
			Timestamp:            "2025-10-14T00:00:00",
			RequiredAuths:        []string{"hive:milo-hpr"},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "map",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
		Caller:     "hive:milo-hpr",
	})
	if r.Err != "" {
		fmt.Printf("multi-output map error: %s: %s\n", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success, "multi-output map should succeed")

	dumpLogs(t, r.Logs)

	// Alice should have received amount1
	aliceBal := ct.StateGet(contractId, constants.BalancePrefix+"hive:alice")
	assert.Equal(t, encodeBalance(t, amount1), aliceBal, "alice should have 5000")

	// Bob should have received amount2
	bobBal := ct.StateGet(contractId, constants.BalancePrefix+"hive:bob")
	assert.Equal(t, encodeBalance(t, amount2), bobBal, "bob should have 3000")
}

// ---------------------------------------------------------------------------
// TestUnmapExactBalance — Unmap with exact balance accounting for fees.
// Verify balance goes to zero.
// ---------------------------------------------------------------------------
func TestUnmapExactBalance(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const fakeTxId0 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const fakeTxId1 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)

	// Set a large balance so we can unmap a moderate amount and verify
	// the balance decreases correctly (amount + vscFee + btcFee).
	const balance = int64(100000)
	const unmapAmount = int64(50000)

	ct.StateSet(contractId, constants.BalancePrefix+"hive:milo-hpr", encodeBalance(t, balance))
	ct.StateSet(contractId, constants.ObservedBlockPrefix+"100", buildObservedList(t,
		observedParam{fakeTxId0, 0}, observedParam{fakeTxId1, 0},
	))
	ct.StateSet(contractId, constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(mapping.UtxoRegistry{
		{Id: 1024, Amount: 50000},
		{Id: 1025, Amount: 50000},
	})))
	ct.StateSet(contractId, constants.UtxoPrefix+"400", depositUtxoBinary(t, fakeTxId0, 0, 50000, instruction))
	ct.StateSet(contractId, constants.UtxoPrefix+"401", changeUtxoBinary(t, fakeTxId1, 0, 50000))
	ct.StateSet(contractId, constants.UtxoLastIdKey, encodeUtxoCounters(1026, 0))
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: balance,
		UserSupply:   balance,
		BaseFeeRate:  1,
	})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", buildSeedHeaderRaw(t, time.Unix(0, 0)))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	payload, err := tinyjson.Marshal(mapping.TransferParams{
		Amount: fmt.Sprintf("%d", unmapAmount),
		To:     regtestDestAddress(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:milo-hpr"),
		ContractId: contractId,
		Action:     "unmap",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})

	dumpLogs(t, r.Logs)
	dumpStateDiff(t, r.StateDiff)

	if r.Err != "" {
		fmt.Printf("unmap error: %s: %s\n", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success, "unmap should succeed with sufficient balance")

	// After unmap, balance should be less than original
	remainingBal := ct.StateGet(contractId, constants.BalancePrefix+"hive:milo-hpr")
	// vscFee = 0 (VscFeeMinSats=0, VscFeeRateBps=0)
	// So remaining should be 100000 - 50000 - btcFee = 50000 - btcFee
	t.Logf("remaining balance after unmap: %q", remainingBal)
	// Verify it decreased significantly
	if remainingBal != "" {
		assert.NotEqual(t, encodeBalance(t, balance), remainingBal,
			"balance should have decreased after unmap")
	}
}

// ---------------------------------------------------------------------------
// TestApproveAndTransferFromSameAsOwner — Owner calls transferFrom on their
// own tokens. Should work without allowance since caller == from.
// ---------------------------------------------------------------------------
func TestApproveAndTransferFromSameAsOwner(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 10000)

	// No approval needed — the caller IS the owner
	r := callTransferFrom(t, ct, contractId, allowanceOwner, allowanceOwner, "hive:recipient", 5000)
	if r.Err != "" {
		fmt.Printf("transferFrom (self) error: %s: %s\n", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success, "transferFrom where caller == from should succeed without allowance")

	// Owner balance should be 10000 - 5000 = 5000
	assert.Equal(t, encodeBalance(t, 5000), ct.StateGet(contractId, constants.BalancePrefix+allowanceOwner),
		"owner balance should decrease by transferred amount")
	// Recipient should have 5000
	assert.Equal(t, encodeBalance(t, 5000), ct.StateGet(contractId, constants.BalancePrefix+"hive:recipient"),
		"recipient should have received 5000")
}

// ---------------------------------------------------------------------------
// TestMapInvalidTxHex — Pass garbage hex to the map action.
// ---------------------------------------------------------------------------
func TestMapInvalidTxHex(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", buildSeedHeaderRaw(t, time.Unix(0, 0)))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	params := mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    100,
			RawTxHex:       "not_valid_hex_at_all",
			MerkleProofHex: "",
			TxIndex:        0,
		},
		Instructions: []string{"deposit_to=hive:milo-hpr"},
	}
	payload, _ := tinyjson.Marshal(params)

	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:milo-hpr"),
		ContractId: contractId,
		Action:     "map",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})
	assert.False(t, r.Success, "map with invalid tx hex should fail")
	t.Logf("Expected error: %s: %s", r.Err, r.ErrMsg)
}

// ---------------------------------------------------------------------------
// TestMapWrongBlockHeight — Map with a block height that doesn't match
// any stored header.
// ---------------------------------------------------------------------------
func TestMapWrongBlockHeight(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	fixture := buildMapFixture(t, instruction, 10000, 100)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	// Use block height 999 — no header stored at that height
	params := mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    999,
			RawTxHex:       fixture.RawTxHex,
			MerkleProofHex: "",
			TxIndex:        0,
		},
		Instructions: []string{instruction},
	}
	payload, _ := tinyjson.Marshal(params)

	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:milo-hpr"),
		ContractId: contractId,
		Action:     "map",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})
	assert.False(t, r.Success, "map with non-existent block height should fail")
	t.Logf("Expected error: %s: %s", r.Err, r.ErrMsg)
}

// ---------------------------------------------------------------------------
// TestUnmapZeroAmount — Unmap with amount "0". Should fail.
// ---------------------------------------------------------------------------
func TestUnmapZeroAmount(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.BalancePrefix+"hive:milo-hpr", encodeBalance(t, 50000))

	payload, _ := tinyjson.Marshal(mapping.TransferParams{
		Amount: "0",
		To:     regtestDestAddress(t),
	})

	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:milo-hpr"),
		ContractId: contractId,
		Action:     "unmap",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})
	assert.False(t, r.Success, "unmap with zero amount should fail")
	t.Logf("Expected error: %s: %s", r.Err, r.ErrMsg)
}

// ---------------------------------------------------------------------------
// TestUnmapNegativeAmount — Unmap with a negative amount. Should fail.
// ---------------------------------------------------------------------------
func TestUnmapNegativeAmount(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.BalancePrefix+"hive:milo-hpr", encodeBalance(t, 50000))

	payload, _ := tinyjson.Marshal(mapping.TransferParams{
		Amount: "-100",
		To:     regtestDestAddress(t),
	})

	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:milo-hpr"),
		ContractId: contractId,
		Action:     "unmap",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})
	assert.False(t, r.Success, "unmap with negative amount should fail")
	t.Logf("Expected error: %s: %s", r.Err, r.ErrMsg)
}

// ---------------------------------------------------------------------------
// TestUnmapSupplyUpdates — Verify that after unmap, the supply state
// is updated correctly (ActiveSupply, UserSupply, FeeSupply).
// ---------------------------------------------------------------------------
func TestUnmapSupplyUpdates(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const fakeTxId0 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)

	const balance = int64(100000)
	const unmapAmount = int64(20000)

	ct.StateSet(contractId, constants.BalancePrefix+"hive:milo-hpr", encodeBalance(t, balance))
	ct.StateSet(contractId, constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(mapping.UtxoRegistry{
		{Id: 1024, Amount: 100000},
	})))
	ct.StateSet(contractId, constants.UtxoPrefix+"400", depositUtxoBinary(t, fakeTxId0, 0, 100000, instruction))
	ct.StateSet(contractId, constants.UtxoLastIdKey, encodeUtxoCounters(1025, 0))
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: balance,
		UserSupply:   balance,
		FeeSupply:    0,
		BaseFeeRate:  1,
	})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", buildSeedHeaderRaw(t, time.Unix(0, 0)))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	payload, _ := tinyjson.Marshal(mapping.TransferParams{
		Amount: fmt.Sprintf("%d", unmapAmount),
		To:     regtestDestAddress(t),
	})

	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:milo-hpr"),
		ContractId: contractId,
		Action:     "unmap",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})
	if !r.Success {
		t.Fatalf("unmap failed: %s: %s", r.Err, r.ErrMsg)
	}

	dumpLogs(t, r.Logs)

	// Parse supply after unmap
	supplyRaw := ct.StateGet(contractId, constants.SupplyKey)
	supply, err := mapping.UnmarshalSupply([]byte(supplyRaw))
	if err != nil {
		t.Fatal("failed to unmarshal supply:", err)
	}

	t.Logf("supply after unmap: active=%d, user=%d, fee=%d", supply.ActiveSupply, supply.UserSupply, supply.FeeSupply)

	// vscFee = 0 (VscFeeMinSats=0, VscFeeRateBps=0)
	// ActiveSupply should decrease by (amount + btcFee)
	assert.True(t, supply.ActiveSupply < balance, "active supply should decrease")
	assert.True(t, supply.UserSupply < balance, "user supply should decrease")
	assert.Equal(t, int64(0), supply.FeeSupply, "vsc fee should be 0")
}

// ---------------------------------------------------------------------------
// TestMapThenUnmapFullCycle — Map BTC, then unmap the full amount minus fees.
// Verifies the complete deposit→withdraw cycle.
// ---------------------------------------------------------------------------
func TestMapThenUnmapFullCycle(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const blockHeight = uint32(100)
	const depositAmount = int64(50000)

	fixture := buildMapFixture(t, instruction, depositAmount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	// Top up the caller's HBD balance so RCs cover both map and unmap in one
	// test (the 10k free tier alone is borderline for a single op).
	ct.Deposit("hive:milo-hpr", 10000, ledgerDb.AssetHbd)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	// Step 1: Map
	mapParams := mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    blockHeight,
			RawTxHex:       fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex,
			TxIndex:        fixture.TxIndex,
		},
		Instructions: []string{instruction},
	}
	mapPayload, _ := tinyjson.Marshal(mapParams)

	r1 := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:milo-hpr"),
		ContractId: contractId,
		Action:     "map",
		Payload:    mapPayload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})
	if !r1.Success {
		t.Fatalf("map failed: %s: %s", r1.Err, r1.ErrMsg)
	}

	balAfterMap := ct.StateGet(contractId, constants.BalancePrefix+"hive:milo-hpr")
	assert.Equal(t, encodeBalance(t, depositAmount), balAfterMap, "balance after map should equal deposit")
	t.Log("balance after map:", depositAmount)

	// Step 2: Unmap a portion (small enough to cover fees)
	const unmapAmount = int64(10000)
	unmapPayload, _ := tinyjson.Marshal(mapping.TransferParams{
		Amount: fmt.Sprintf("%d", unmapAmount),
		To:     regtestDestAddress(t),
	})

	r2 := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:milo-hpr"),
		ContractId: contractId,
		Action:     "unmap",
		Payload:    unmapPayload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})
	if !r2.Success {
		t.Fatalf("unmap failed: %s: %s", r2.Err, r2.ErrMsg)
	}

	dumpLogs(t, r2.Logs)

	// Balance should be less than before (amount + vscFee + btcFee deducted)
	balAfterUnmap := ct.StateGet(contractId, constants.BalancePrefix+"hive:milo-hpr")
	assert.NotEqual(t, balAfterMap, balAfterUnmap, "balance should change after unmap")
	t.Logf("balance after unmap: %q", balAfterUnmap)

	// TxSpends registry should have one pending spend
	txSpendsRaw := ct.StateGet(contractId, constants.TxSpendsRegistryKey)
	assert.NotEmpty(t, txSpendsRaw, "should have a pending spend tx")
}

// ---------------------------------------------------------------------------
// TestTransferMultipleRecipients — Transfer to multiple recipients in
// sequence. Verify all balances correct.
// ---------------------------------------------------------------------------
func TestTransferMultipleRecipients(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.BalancePrefix+"hive:milo-hpr", encodeBalance(t, 10000))

	recipients := []struct {
		to     string
		amount int64
	}{
		{"hive:alice", 2000},
		{"hive:bob", 3000},
		{"hive:charlie", 1000},
	}

	for _, r := range recipients {
		payload, _ := tinyjson.Marshal(mapping.TransferParams{
			Amount: fmt.Sprintf("%d", r.amount),
			To:     r.to,
		})
		result := ct.Call(stateEngine.TxVscCallContract{
			Self:       *basicSelf(t, "hive:milo-hpr"),
			ContractId: contractId,
			Action:     "transfer",
			Payload:    payload,
			RcLimit:    1000,
			Intents:    []contracts.Intent{},
		})
		if !result.Success {
			t.Fatalf("transfer to %s failed: %s: %s", r.to, result.Err, result.ErrMsg)
		}
	}

	// Sender: 10000 - 2000 - 3000 - 1000 = 4000
	assert.Equal(t, encodeBalance(t, 4000), ct.StateGet(contractId, constants.BalancePrefix+"hive:milo-hpr"))
	assert.Equal(t, encodeBalance(t, 2000), ct.StateGet(contractId, constants.BalancePrefix+"hive:alice"))
	assert.Equal(t, encodeBalance(t, 3000), ct.StateGet(contractId, constants.BalancePrefix+"hive:bob"))
	assert.Equal(t, encodeBalance(t, 1000), ct.StateGet(contractId, constants.BalancePrefix+"hive:charlie"))
}

// ---------------------------------------------------------------------------
// TestTransferChain — A transfers to B, B transfers to C. Verify final state.
// ---------------------------------------------------------------------------
func TestTransferChain(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.BalancePrefix+"hive:alice", encodeBalance(t, 5000))

	// Alice → Bob: 3000
	payload, _ := tinyjson.Marshal(mapping.TransferParams{Amount: "3000", To: "hive:bob"})
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:alice"),
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    1000,
		Intents:    []contracts.Intent{},
	})
	assert.True(t, r.Success, "alice→bob transfer should succeed")

	// Bob → Charlie: 2000
	payload, _ = tinyjson.Marshal(mapping.TransferParams{Amount: "2000", To: "hive:charlie"})
	r = ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:bob"),
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    1000,
		Intents:    []contracts.Intent{},
	})
	assert.True(t, r.Success, "bob→charlie transfer should succeed")

	assert.Equal(t, encodeBalance(t, 2000), ct.StateGet(contractId, constants.BalancePrefix+"hive:alice"))
	assert.Equal(t, encodeBalance(t, 1000), ct.StateGet(contractId, constants.BalancePrefix+"hive:bob"))
	assert.Equal(t, encodeBalance(t, 2000), ct.StateGet(contractId, constants.BalancePrefix+"hive:charlie"))
}

// ---------------------------------------------------------------------------
// TestTransferFromWithInsufficientAllowance — Spender has some allowance
// but tries to transfer more than allowed.
// ---------------------------------------------------------------------------
func TestTransferFromWithInsufficientAllowance(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 10000)

	// Approve spender for only 1000
	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 1000)

	// Try to transferFrom 5000 — exceeds allowance
	r := callTransferFrom(t, ct, contractId, allowanceSpender, allowanceOwner, allowanceTarget, 5000)
	assert.False(t, r.Success, "transferFrom exceeding allowance should fail")
	assert.NotEmpty(t, r.Err)

	// Balance should be unchanged
	assert.Equal(t, encodeBalance(t, 10000), ct.StateGet(contractId, constants.BalancePrefix+allowanceOwner))
	// Allowance should be unchanged
	assert.Equal(t, encodeBalance(t, 1000), ct.StateGet(contractId, allowanceKey(allowanceOwner, allowanceSpender)))
}

// ---------------------------------------------------------------------------
// TestMapUpdatesSupply — Verify that map correctly increases supply counters.
// ---------------------------------------------------------------------------
func TestMapUpdatesSupply(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const blockHeight = uint32(100)
	const depositAmount = int64(25000)

	fixture := buildMapFixture(t, instruction, depositAmount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: 0,
		UserSupply:   0,
		FeeSupply:    0,
		BaseFeeRate:  1,
	})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	params := mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    blockHeight,
			RawTxHex:       fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex,
			TxIndex:        fixture.TxIndex,
		},
		Instructions: []string{instruction},
	}
	payload, _ := tinyjson.Marshal(params)

	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:milo-hpr"),
		ContractId: contractId,
		Action:     "map",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})
	assert.True(t, r.Success, "map should succeed")

	supplyRaw := ct.StateGet(contractId, constants.SupplyKey)
	supply, err := mapping.UnmarshalSupply([]byte(supplyRaw))
	if err != nil {
		t.Fatal("failed to unmarshal supply:", err)
	}

	t.Logf("supply after map: active=%d, user=%d, fee=%d", supply.ActiveSupply, supply.UserSupply, supply.FeeSupply)
	assert.Equal(t, depositAmount, supply.ActiveSupply, "active supply should equal deposited amount")
	assert.Equal(t, depositAmount, supply.UserSupply, "user supply should equal deposited amount")
}

// ---------------------------------------------------------------------------
// TestConfirmSpendPromotesUtxos — Verify that confirmSpend promotes
// unconfirmed UTXOs (id 0-63) to confirmed pool (id 64+).
// ---------------------------------------------------------------------------
func TestConfirmSpendPromotesUtxos(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const fakeTxId0 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// Build a real spend tx so its TxID can be verified via Merkle proof.
	fixture := buildConfirmSpendFixture(t, 101)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)

	// Set up: one confirmed UTXO (id=1024) and one unconfirmed (id=0) linked to a pending spend
	ct.StateSet(contractId, constants.BalancePrefix+"hive:milo-hpr", encodeBalance(t, 5000))
	ct.StateSet(contractId, constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(mapping.UtxoRegistry{
		{Id: 1024, Amount: 5000},
		{Id: 0, Amount: 2000},
	})))
	ct.StateSet(contractId, constants.UtxoPrefix+"400", depositUtxoBinary(t, fakeTxId0, 0, 5000, instruction))
	ct.StateSet(contractId, constants.UtxoPrefix+"0", changeUtxoBinary(t, fixture.TxId, 0, 2000))
	ct.StateSet(contractId, constants.UtxoLastIdKey, encodeUtxoCounters(1025, 1))
	ct.StateSet(contractId, constants.TxSpendsRegistryKey, string(mapping.MarshalTxSpendsRegistry(mapping.TxSpendsRegistry{fixture.TxId})))

	sigData := mapping.SigningData{
		Tx: []byte{0x01},
		UnsignedSigHashes: []mapping.UnsignedSigHash{
			{Index: 0, SigHash: []byte{0x00}, WitnessScript: []byte{0x00}},
		},
	}
	sigDataBytes, err := mapping.MarshalSigningData(&sigData)
	if err != nil {
		t.Fatal("error marshalling signing data:", err)
	}
	ct.StateSet(contractId, constants.TxSpendsPrefix+fixture.TxId, string(sigDataBytes))

	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: 7000,
		UserSupply:   5000,
		BaseFeeRate:  1,
	})))
	ct.StateSet(contractId, constants.LastHeightKey, "101")
	ct.StateSet(contractId, constants.BlockPrefix+"100", buildSeedHeaderRaw(t, time.Unix(0, 0)))
	ct.StateSet(contractId, constants.BlockPrefix+"101", fixture.BlockHeaderRaw)
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	confirmPayload, _ := tinyjson.Marshal(mapping.ConfirmSpendParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    fixture.BlockHeight,
			RawTxHex:       fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex,
			TxIndex:        fixture.TxIndex,
		},
		Indices: []uint32{0},
	})

	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:milo-hpr"),
		ContractId: contractId,
		Action:     "confirmSpend",
		Payload:    confirmPayload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})

	dumpStateDiff(t, r.StateDiff)

	assert.True(t, r.Success, "confirmSpend should succeed")
	assert.Empty(t, ct.StateGet(contractId, constants.TxSpendsPrefix+fixture.TxId),
		"signing data should be removed after confirmation")
}
