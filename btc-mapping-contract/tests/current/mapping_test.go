package current_test

import (
	"btc-mapping-contract/contract/blocklist"
	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"
	"fmt"
	"testing"
	"time"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"

	btcMapping "btc-mapping-contract"
)

var ContractWasm = btcMapping.DevWasm

func TestMap(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const blockHeight = uint32(100)

	fixture := buildMapFixture(t, instruction, 10000, blockHeight)

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

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "sometxid",
			BlockId:              "block:map",
			Index:                69,
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
		fmt.Printf("%s: %s", r.Err, r.ErrMsg)
	}

	dumpLogs(t, r.Logs)

	assert.True(t, r.Success)
	if assert.LessOrEqual(t, r.GasUsed, uint(1000000000)) {
		fmt.Println("gas used:", r.GasUsed)
	}

	dumpStateDiff(t, r.StateDiff)
	fmt.Println("Return value:", r.Ret)
}

func TestUnmap(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const fakeTxId0 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const fakeTxId1 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.BalancePrefix+"hive:milo-hpr", encodeBalance(t, 10000))
	ct.StateSet(contractId, constants.ObservedPrefix+fakeTxId0+":0", "1")
	ct.StateSet(contractId, constants.ObservedPrefix+fakeTxId1+":0", "1")
	// UTXOs in confirmed pool: IDs 64 (0x40) and 65 (0x41)
	ct.StateSet(contractId, constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(mapping.UtxoRegistry{
		{Id: 64, Amount: 5000},
		{Id: 65, Amount: 5000},
	})))
	ct.StateSet(contractId, constants.UtxoPrefix+"40", depositUtxoBinary(t, fakeTxId0, 0, 5000, instruction))
	ct.StateSet(contractId, constants.UtxoPrefix+"41", changeUtxoBinary(t, fakeTxId1, 0, 5000))
	// 2-byte counter: [confirmedNextId=66, unconfirmedNextId=0]
	ct.StateSet(contractId, constants.UtxoLastIdKey, string([]byte{66, 0}))
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: 10000,
		UserSupply:   10000,
		FeeSupply:    0,
		BaseFeeRate:  1,
	})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", buildSeedHeaderRaw(t, time.Unix(0, 0)))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	payload, err := tinyjson.Marshal(mapping.TransferParams{
		Amount: "7500",
		To:     regtestDestAddress(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "sometxid",
			BlockId:              "block:unmap",
			Index:                69,
			OpIndex:              0,
			Timestamp:            "2025-10-14T00:00:00",
			RequiredAuths:        []string{"hive:milo-hpr"},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "unmap",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})

	dumpLogs(t, r.Logs)

	if r.Err != "" {
		fmt.Printf("%s: %s", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success)
	if assert.LessOrEqual(t, r.GasUsed, uint(10000000000)) {
		fmt.Println("gas used:", r.GasUsed)
	}

	dumpStateDiff(t, r.StateDiff)
	fmt.Println("Return value:", r.Ret)
}

func TestTransfer(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.BalancePrefix+"hive:milo-hpr", encodeBalance(t, 10000))

	transferDetails := mapping.TransferParams{
		Amount: "8000",
		To:     "hive:vaultec",
	}
	payload, err := tinyjson.Marshal(transferDetails)
	if err != nil {
		t.Fatal("err marshaling payload:", err.Error())
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "sometxid",
			BlockId:              "block:transfer",
			Index:                69,
			OpIndex:              0,
			Timestamp:            "2025-10-14T00:00:00",
			RequiredAuths:        []string{"hive:milo-hpr"},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    10000,
		Caller:     "hive:milo-hpr",
		Intents:    []contracts.Intent{},
	})
	if r.Err != "" {
		fmt.Println("error:", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success)
	if assert.LessOrEqual(t, r.GasUsed, uint(1000000000)) {
		fmt.Println("gas used:", r.GasUsed)
	}

	dumpStateDiff(t, r.StateDiff)
	fmt.Println("Return value:", r.Ret)
}

func TestRegisterKey(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)

	input, err := tinyjson.Marshal(mapping.RegisterKeyParams{
		PrimaryPubKey: TestPrimaryPubKeyHex,
		BackupPubKey:  TestBackupPubKeyHex,
	})
	if err != nil {
		t.Fatal("error marshalling input:", err.Error())
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "sometxid",
			BlockId:              "block:register_pubkey",
			Index:                69,
			OpIndex:              0,
			Timestamp:            "2025-10-14T00:00:00",
			RequiredAuths:        []string{"hive:milo-hpr"},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "registerPublicKey",
		Payload:    input,
		RcLimit:    5000,
		Intents:    []contracts.Intent{},
	})
	if r.Err != "" {
		fmt.Println("error:", r.Err)
	}
	assert.True(t, r.Success)
	assert.LessOrEqual(t, r.GasUsed, uint(1000000000))

	dumpStateDiff(t, r.StateDiff)
	fmt.Println("Return value:", r.Ret)
}

func TestAddBlocks(t *testing.T) {
	seedTime := time.Unix(0, 0) // epoch: WASM time.Now() returns epoch
	seedHex, chainHex := buildHeaderChain(t, seedTime, 2)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, seedHex))
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))

	payload, err := tinyjson.Marshal(blocklist.AddBlocksParams{
		Blocks:    chainHex,
		LatestFee: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "sometxid",
			BlockId:              "block:add_blocks",
			Index:                69,
			OpIndex:              0,
			Timestamp:            "2025-10-14T00:00:00",
			RequiredAuths:        []string{"hive:milo-hpr"},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "addBlocks",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})
	if r.Err != "" {
		fmt.Println("error:", r.Err, r.ErrMsg)
	}

	assert.True(t, r.Success)
	assert.LessOrEqual(t, r.GasUsed, uint(1000000000))

	dumpStateDiff(t, r.StateDiff)
	fmt.Println("Return value:", r.Ret)
}

func TestSeedBlocks(t *testing.T) {
	seedTime := time.Unix(0, 0) // epoch: WASM time.Now() returns epoch

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	// no LastHeightKey set — seeding from scratch

	payload, err := tinyjson.Marshal(blocklist.SeedBlocksParams{
		BlockHeader: buildSeedHeader(t, seedTime), // hex string, decoded by HandleSeedBlocks
		BlockHeight: 100,
	})
	t.Log(string(payload))
	if err != nil {
		t.Fatal(err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "sometxid",
			BlockId:              "block:seed_blocks",
			Index:                69,
			OpIndex:              0,
			Timestamp:            "2025-10-14T00:00:00",
			RequiredAuths:        []string{"hive:milo-hpr"},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "seedBlocks",
		Payload:    payload,
		RcLimit:    5000,
		Intents:    []contracts.Intent{},
	})
	if r.Err != "" {
		fmt.Println("error:", r.Err, r.ErrMsg)
	}

	dumpLogs(t, r.Logs)

	assert.True(t, r.Success)
	assert.LessOrEqual(t, r.GasUsed, uint(1000000000))

	dumpStateDiff(t, r.StateDiff)
	fmt.Println("Return value:", r.Ret)
}
