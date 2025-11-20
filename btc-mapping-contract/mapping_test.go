package mapping_test

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"testing"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/stretchr/testify/assert"
)

//go:embed artifacts/main.wasm
var ContractWasm []byte

const rawInstruction = `{"tx_data":{"block_height":4782849,"raw_tx_hex":"02000000019321ce0e5c5d9b815baf0670f742475436b83fc90b6f63f75268fec240ac4290010000006a473044022049ab9d2eae4f142a2e32b2a05b131013c74c4bb1f63ee54f3cd49829c667239e02203bd5b57353d28156957c30f272077f733c9bfcf1eb9659834f705751a324c435012103520e3be1d9d9a7356ec59aa433358435035f90e8cc0219baf4c44f8be4a379edfdffffff02b5855c34000000002251203ee8d7e436d62558c6eb1a5b2ab814741d8965058909772b015a57208e950ac832ba010000000000220020609c6ef5a960078ace8f2776ac7dd1bb5925434f51d89da5eb8f954249e07a5700fb4800","merkle_proof_hex":"31930b35c33e9fe68f1f28df5b49879383f6d3b70e53cbe8dd1c8d118ee0cb0d66f8a782a28e99e228f132fa95b6054d10bba61df91101f46ca587bd620bccb9a43e7ea1ae600a434685390889ace263568d829101a48f17a17346b6c968676bc926d17d9533a236e94fb188ea2c7ffe76423945a32190403edda285013868eeac4c752b93787141b37021cd39d5db1e7c0d4a5d7d12086a83f26d26cf9d2a74","tx_index":13},"instructions":["deposit_to=hive:milo-hpr"]}`

func printKeys(ct *test_utils.ContractTest, contractId string, keys []string) {
	for _, key := range keys {
		fmt.Printf("%s: %s\n", key, ct.StateGet(contractId, key))
	}
}

func TestMapping(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, "observed_txs", `{}`)
	ct.StateSet(contractId, "utxo_registry", `[]`)
	ct.StateSet(
		contractId,
		"supply",
		`{"active_supply":0,"user_supply":0,"fee_supply":0,"base_fee_rate":1}`,
	)
	ct.StateSet(contractId, "last_block_height", "4782849")
	ct.StateSet(
		contractId,
		"block4782849",
		"00000020c85f72486dce7bbe73e806f095494d37553995ffc9a6995ab860a34700000000e37446d7b9f3f5498d2b07a25ca3e76144a4754dd49794f8f8b91e7161cff7eee7321e69ffff001dc44cdfad",
	)
	ct.StateSet(contractId, "pubkey", `0332e9f22cfa2f6233c059c4d54700e3d00df3d7f55e3ea16207b860360446634f`)

	result, gasUsed, logs := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "sometxid",
			BlockId:              "block:map",
			Index:                69,
			OpIndex:              0,
			Timestamp:            "2025-10-14T00:00:00",
			RequiredAuths:        []string{"hive:someone"},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "map",
		Payload:    json.RawMessage([]byte(rawInstruction)),
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
		Caller:     "hive:milo-hpr",
	})
	if result.Err != nil {
		fmt.Println("error:", *result.Err)
	}

	if len(logs) > 0 {
		fmt.Println("console logs: ==================================================")
		for _, logArray := range logs {
			for _, log := range logArray {
				fmt.Println(log)
			}
		}
		fmt.Printf("================================================================\n")
	}

	assert.True(t, result.Success)                        // assert contract execution success
	if assert.LessOrEqual(t, gasUsed, uint(1000000000)) { // assert this call uses no more than 10M WASM gas
		fmt.Println("gas used:", gasUsed)
	}
	assert.GreaterOrEqual(t, len(logs), 0) // assert at least 1 log emitted

	printKeys(
		&ct,
		contractId,
		[]string{
			"balhive:milo-hpr",
			"observed_txs70392917bb417a68fabd51e8d97a48b5d9594538b76cd47317b4c5c7755b3229:1",
			"utxo_registry",
			"utxos0",
			"utxo_last_id",
			"supply",
			"last_block_height",
		},
	)

	fmt.Println("Return value:", result.Ret)
}

func TestUnmapping(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, "balhive:milo-hpr", "113202")
	ct.StateSet(
		contractId,
		"observed_txs70392917bb417a68fabd51e8d97a48b5d9594538b76cd47317b4c5c7755b3229:1",
		"1",
	)
	ct.StateSet(
		contractId,
		"utxo_registry",
		`[["AA==","Aboy","AQ=="]]`,
	)
	ct.StateSet(
		contractId,
		"utxos0",
		`{"tx_id":"70392917bb417a68fabd51e8d97a48b5d9594538b76cd47317b4c5c7755b3229","vout":1,"amount":113202,"pk_script":"ACBgnG71qWAHis6PJ3asfdG7WSVDT1HYnaXrj5VCSeB6Vw==","tag":"6ad59da3ece6b8fcfd0cd8c615ed5ec82504fbd81808b2aea5fb750adb01f20c"}`,
	)
	ct.StateSet(contractId, "utxo_last_id", "1")
	ct.StateSet(contractId, "tx_spends", "null")
	ct.StateSet(
		contractId,
		"supply",
		`{"active_supply":113202,"user_supply":113202,"fee_supply":0,"base_fee_rate":1}`,
	)
	ct.StateSet(contractId, "last_block_height", "4782849")
	ct.StateSet(
		contractId,
		"block4782849",
		"00000020c85f72486dce7bbe73e806f095494d37553995ffc9a6995ab860a34700000000e37446d7b9f3f5498d2b07a25ca3e76144a4754dd49794f8f8b91e7161cff7eee7321e69ffff001dc44cdfad",
	)
	ct.StateSet(contractId, "pubkey", `0332e9f22cfa2f6233c059c4d54700e3d00df3d7f55e3ea16207b860360446634f`)

	result, gasUsed, logs := ct.Call(stateEngine.TxVscCallContract{
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
		Payload: json.RawMessage(
			[]byte(`{"amount":10000,"recipient_btc_address":"tb1q5dgehs94wf5mgfasnfjsh4dqv6hz8e35w4w7tk"}`),
		),
		RcLimit: 10000,
		Intents: []contracts.Intent{},
	})

	if len(logs) > 0 {
		fmt.Println("console logs: ==================================================")
		for _, logArray := range logs {
			for _, log := range logArray {
				fmt.Println(log)
			}
		}
		fmt.Printf("================================================================\n")
	}

	if result.Err != nil {
		fmt.Println("error:", *result.Err)
	}
	assert.True(t, result.Success)                         // assert contract execution success
	if assert.LessOrEqual(t, gasUsed, uint(10000000000)) { // assert this call uses no more than 10M WASM gas
		fmt.Println("gas used:", gasUsed)
	}
	assert.GreaterOrEqual(t, len(logs), 1) // assert at least 1 log emitted

	printKeys(
		&ct,
		contractId,
		[]string{
			"balhive:milo-hpr",
			"observed_txs64240d2b706020087463530cd13304907033dd50b7938817e1016416376876bf:0",
			"utxo_registry",
			"utxo_last_id",
			"utxos0",
			"tx_spend_registry",
			"tx_spendc5827857f860f4e5c1071e9da4b75fb87c9d256c00dee1663034e74dc06fe82f",
			"supply",
			"last_block_height",
		},
	)

	fmt.Println("Return value:", result.Ret)
}

func TestTransfer(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, "balhive:milo-hpr", "113202")
	ct.StateSet(
		contractId,
		"observed_txs70392917bb417a68fabd51e8d97a48b5d9594538b76cd47317b4c5c7755b3229:1",
		"1",
	)
	ct.StateSet(
		contractId,
		"utxo_registry",
		`[["AA==","Aboy","AQ=="]]`,
	)
	ct.StateSet(
		contractId,
		"utxos0",
		`{"tx_id":"70392917bb417a68fabd51e8d97a48b5d9594538b76cd47317b4c5c7755b3229","vout":1,"amount":113202,"pk_script":"ACBgnG71qWAHis6PJ3asfdG7WSVDT1HYnaXrj5VCSeB6Vw==","tag":"6ad59da3ece6b8fcfd0cd8c615ed5ec82504fbd81808b2aea5fb750adb01f20c"}`,
	)
	ct.StateSet(contractId, "utxo_last_id", "1")
	ct.StateSet(contractId, "tx_spends", "null")
	ct.StateSet(
		contractId,
		"supply",
		`{"active_supply":113202,"user_supply":113202,"fee_supply":0,"base_fee_rate":1}`,
	)
	ct.StateSet(contractId, "last_block_height", "4782849")
	ct.StateSet(
		contractId,
		"block4782849",
		"00000020c85f72486dce7bbe73e806f095494d37553995ffc9a6995ab860a34700000000e37446d7b9f3f5498d2b07a25ca3e76144a4754dd49794f8f8b91e7161cff7eee7321e69ffff001dc44cdfad",
	)
	ct.StateSet(contractId, "pubkey", `0332e9f22cfa2f6233c059c4d54700e3d00df3d7f55e3ea16207b860360446634f`)

	result, gasUsed, _ := ct.Call(stateEngine.TxVscCallContract{
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
		Payload: json.RawMessage(
			[]byte(`{"amount":8000,"recipient_vsc_address":"hive:vaultec"}`),
		),
		RcLimit: 10000,
		Intents: []contracts.Intent{},
	})
	if result.Err != nil {
		fmt.Println("error:", *result.Err)
	}
	assert.True(t, result.Success)                        // assert contract execution success
	if assert.LessOrEqual(t, gasUsed, uint(1000000000)) { // assert this call uses no more than 10M WASM gas
		fmt.Println("gas used:", gasUsed)
	}

	fmt.Printf("%s: %s\n\n", "account_balance", ct.StateGet("mapping_contract", "account_balances"))
	fmt.Printf("%s: %s\n\n", "observed_txs", ct.StateGet("mapping_contract", "observed_txs"))
	fmt.Printf("%s: %s\n\n", "utxos", ct.StateGet("mapping_contract", "utxos"))
	fmt.Printf("%s: %s\n\n", "tx_spends", ct.StateGet("mapping_contract", "tx_spends"))
	fmt.Printf("%s: %s\n\n", "supply", ct.StateGet("mapping_contract", "supply"))
	fmt.Printf("%s: %s\n\n", "blocklist", ct.StateGet("mapping_contract", "blocklist"))

	fmt.Println("Return value:", result.Ret)
}

func TestCreateKey(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)

	result, gasUsed, _ := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "sometxid",
			BlockId:              "block:create_key_pair",
			Index:                0,
			OpIndex:              0,
			Timestamp:            "2025-10-14T00:00:00",
			RequiredAuths:        []string{"hive:milo-hpr"},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "create_key_pair",
		Payload:    json.RawMessage([]byte("")),
		RcLimit:    1000,
		Intents:    []contracts.Intent{},
	})
	if result.Err != nil {
		fmt.Println("error:", *result.Err)
	}
	assert.True(t, result.Success)                 // assert contract execution success
	assert.LessOrEqual(t, gasUsed, uint(10000000)) // assert this call uses no more than 10M WASM gas

	printKeys(
		&ct,
		contractId,
		[]string{
			"tx_spends",
		},
	)

	fmt.Println("Return value:", result.Ret)
}

func TestRegisterKey(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)

	result, gasUsed, _ := ct.Call(stateEngine.TxVscCallContract{
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
		Action:     "register_public_key",
		Payload:    json.RawMessage([]byte("1000")),
		RcLimit:    1000,
		Intents:    []contracts.Intent{},
	})
	if result.Err != nil {
		fmt.Println("error:", *result.Err)
	}
	assert.True(t, result.Success)                 // assert contract execution success
	assert.LessOrEqual(t, gasUsed, uint(10000000)) // assert this call uses no more than 10M WASM gas

	printKeys(
		&ct,
		contractId,
		[]string{
			"tx_spends",
		},
	)

	fmt.Println("Return value:", result.Ret)
}

const rawBlocks = `{"blocks":"04000020e25bdb1dac9e52ab73217048889ca6aabb013c8c75cf20a8cdbba1eb00000000593f41d586ab3ca38b2fef4247e4c1e67a25cbc057284f34f113b9d0318cd7705af21c69ffff001d1adeb3890000002056f01934cb217451b4cfc0de2659cb21d05574f9b498e2e50f7cb9220000000007c163714629200295224756e7738ee85ed86fa5a89a2a1bfd48a5b65107596e3cf71c69ffff001dc4463eff","latest_fee":1}`

func TestAddBlocks(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, "last_block_height", "4782781")
	ct.StateSet(
		contractId,
		"block4782781",
		"0000002076bd5abaaf4f9b70901c84c29ce5211e85d0f5e2dc6be53619193b50000000007acadb1928b7931a92288bfd3ab925391b4913d7ebad46f92067399a5541d57aa6ed1c69ffff001df352048d",
	)
	// ct.StateSet("mapping_contract", "supply", `{}`)

	result, gasUsed, _ := ct.Call(stateEngine.TxVscCallContract{
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
		Action:     "add_blocks",
		Payload:    json.RawMessage([]byte(rawBlocks)),
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})
	if result.Err != nil {
		fmt.Println("error:", *result.Err)
	}

	assert.True(t, result.Success)                   // assert contract execution success
	assert.LessOrEqual(t, gasUsed, uint(1000000000)) // assert this call uses no more than 10M WASM gas

	printKeys(
		&ct,
		contractId,
		[]string{
			"tx_spends",
			"supply",
			"last_block_height",
			"block4782782",
			"block4782783",
		},
	)

	fmt.Println("Return value:", result.Ret)
}

const seedBlockInput = `{"block_header":"0000002081e2ced515b739090e16bd5d6b7cd7d5450ebe1deb24e4ff2c00000000000000ddba270323b3ae839a4ac7bc31ab10f35c00204833bdcf5d88cf2bd9247bc030c40dee68ffff001d4ee60d63","block_height":4736940}`

func TestSeedBlocks(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)

	result, gasUsed, logs := ct.Call(stateEngine.TxVscCallContract{
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
		Action:     "seed_blocks",
		Payload:    json.RawMessage([]byte(seedBlockInput)),
		RcLimit:    1000,
		Intents:    []contracts.Intent{},
	})
	if result.Err != nil {
		fmt.Println("error:", *result.Err)
	}

	if len(logs) > 0 {
		fmt.Println("console logs:")
		for _, logArray := range logs {
			for _, log := range logArray {
				fmt.Println(log)
			}
		}
		fmt.Println()
	}

	assert.True(t, result.Success)                   // assert contract execution success
	assert.LessOrEqual(t, gasUsed, uint(1000000000)) // assert this call uses no more than 10M WASM gas

	printKeys(
		&ct,
		contractId,
		[]string{
			"tx_spends",
			"last_block_height",
			"block4736940",
		},
	)

	fmt.Println("Return value:", result.Ret)
}

func TestLogging(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, "tx_spends", "null")

	result, gasUsed, logs := ct.Call(stateEngine.TxVscCallContract{
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
		Action:     "test_log",
		Payload: json.RawMessage(
			[]byte(`{"amount":10000,"recipient_btc_address":"tb1q5dgehs94wf5mgfasnfjsh4dqv6hz8e35w4w7tk"}`),
		),
		RcLimit: 10000,
		Intents: []contracts.Intent{},
	})

	fmt.Println("logs:", logs)

	if len(logs) > 0 {
		fmt.Println("console logs: ==================================================")
		for _, logArray := range logs {
			for _, log := range logArray {
				fmt.Println(log)
			}
		}
		fmt.Printf("================================================================\n")
	}

	if result.Err != nil {
		fmt.Println("error:", *result.Err)
	}
	assert.True(t, result.Success)                        // assert contract execution success
	if assert.LessOrEqual(t, gasUsed, uint(1000000000)) { // assert this call uses no more than 10M WASM gas
		fmt.Println("gas used:", gasUsed)
	}
	assert.GreaterOrEqual(t, len(logs), 1) // assert at least 1 log emitted

	fmt.Println("Return value:", result.Ret)
}
