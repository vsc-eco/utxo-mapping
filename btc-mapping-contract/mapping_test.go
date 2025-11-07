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

const rawInstruction = `{"tx_data":{"block_height":4736609,"raw_tx_hex":"020000000001018f4c96ff8a3fa466e8005c0caa6b01d5e1529df0bedbd94a0529514db0ffe0370000000000fdffffff0196260000000000002200202a0ce40846879b42fa7739eb15cdab77ca01b7817a97879b1f58feb52e44478c02473044022076e5f199324d192079acacb0124fcaf5930342b7e80909fc4eee21f48cb23d2b02200e13ef79db59d506f26c6de2fab230fc672a9d00a84269297abb1fbf2b842fd20121022b219f50bb0f57f84ee598b3434904706ee64289c5ac4b1218c4a3a35e390c6d60464800","merkle_proof_hex":"cbb6ae1b0cbe4ef2c17c9e28e06661660b458c862a638930b098d0aec4f4dced63ec55694517b9e1216840b81ef27d9b6e91b3dc31acd34b3830f58293385627f31456aed14b0813e0a3b9c8bf65a20f4423d70b9976b37c31fbaad6f3eab3205efc6dade7738f9fdc844943921f12b60ea246164dc098c852f1fac2e6c398bde37e85c04e8bfac72ee345d6f31d7da36c02e41f3087bd7d2fe1fd541ac2e979d9e5dab1fd538abe721206222e95815b96904faa3f1468aae7553f4536d1c197","tx_index":61},"instructions":["deposit_to=hive:milo-hpr"]}`

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
	ct.StateSet(contractId, "tx_spends", `{}`)
	ct.StateSet(
		contractId,
		"supply",
		`{"active_supply":0,"user_supply":0,"fee_supply":0,"base_fee_rate":1}`,
	)
	ct.StateSet(contractId, "last_block_height", "4736609")
	ct.StateSet(
		contractId,
		"block4736609",
		"000000205fe55a9fc06c60fd340c84411363dfd8b574e8bfe6a44ec21f170f0d000000008c84bcca5e78351d0c8f671c7b9f83430e80ad462fa0b808a0be2c3b1c142df4e8b6e968ffff001db2174f36",
	)
	ct.StateSet(contractId, "pubkey", `0242f9da15eae56fe6aca65136738905c0afdb2c4edf379e107b3b00b98c7fc9f0`)

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
			"observed_txs64240d2b706020087463530cd13304907033dd50b7938817e1016416376876bf:0",
			"utxo_registry",
			"utxos0",
			"utxo_last_id",
			"tx_spends",
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
	ct.StateSet(contractId, "balhive:milo-hpr", "9878")
	ct.StateSet(
		contractId,
		"observed_txs64240d2b706020087463530cd13304907033dd50b7938817e1016416376876bf:0",
		"1",
	)
	ct.StateSet(
		contractId,
		"utxo_registry",
		`[["AA==","JpY=","AQ=="]]`,
	)
	ct.StateSet(
		contractId,
		"utxos0",
		`{"tx_id":"64240d2b706020087463530cd13304907033dd50b7938817e1016416376876bf","vout":0,"amount":9878,"pk_script":"ACAqDOQIRoebQvp3OesVzat3ygG3gXqXh5sfWP61LkRHjA==","tag":"6ad59da3ece6b8fcfd0cd8c615ed5ec82504fbd81808b2aea5fb750adb01f20c"}`,
	)
	ct.StateSet(contractId, "utxo_last_id", "1")
	ct.StateSet(contractId, "tx_spends", `{}`)
	ct.StateSet(
		contractId,
		"supply",
		`{"active_supply":9878,"user_supply":9878,"fee_supply":0,"base_fee_rate":1}`,
	)
	ct.StateSet(contractId, "last_block_height", "4736609")
	ct.StateSet(
		contractId,
		"block4736609",
		"000000205fe55a9fc06c60fd340c84411363dfd8b574e8bfe6a44ec21f170f0d000000008c84bcca5e78351d0c8f671c7b9f83430e80ad462fa0b808a0be2c3b1c142df4e8b6e968ffff001db2174f36",
	)
	ct.StateSet(contractId, "pubkey", `0242f9da15eae56fe6aca65136738905c0afdb2c4edf379e107b3b00b98c7fc9f0`)

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
			[]byte(`{"amount":8000,"recipient_btc_address":"tb1qd4erjn4tvt52c92yv66lwju9pzsd2ltph0xe5s"}`),
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
	assert.True(t, result.Success)                        // assert contract execution success
	if assert.LessOrEqual(t, gasUsed, uint(1000000000)) { // assert this call uses no more than 10M WASM gas
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
			"tx_spends",
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
	ct.StateSet("mapping_contract", "account_balances", `{"hive:milo-hpr":9878}`)
	ct.StateSet(
		"mapping_contract",
		"observed_txs",
		`{"64240d2b706020087463530cd13304907033dd50b7938817e1016416376876bf:0":true}`,
	)
	ct.StateSet(
		"mapping_contract",
		"utxos",
		`{"64240d2b706020087463530cd13304907033dd50b7938817e1016416376876bf:0":{"tx_id":"64240d2b706020087463530cd13304907033dd50b7938817e1016416376876bf","vout":0,"amount":9878,"pk_script":"ACAqDOQIRoebQvp3OesVzat3ygG3gXqXh5sfWP61LkRHjA==","tag":"6ad59da3ece6b8fcfd0cd8c615ed5ec82504fbd81808b2aea5fb750adb01f20c","confirmed":true}}`,
	)
	ct.StateSet("mapping_contract", "tx_spends", `{}`)
	ct.StateSet(
		"mapping_contract",
		"supply",
		`{"active_supply":9878,"user_supply":9878,"fee_supply":0,"base_fee_rate":1}`,
	)
	ct.StateSet(
		"mapping_contract",
		"blocklist",
		`{"block_map":{"4736609":"000000205fe55a9fc06c60fd340c84411363dfd8b574e8bfe6a44ec21f170f0d000000008c84bcca5e78351d0c8f671c7b9f83430e80ad462fa0b808a0be2c3b1c142df4e8b6e968ffff001db2174f36"},"last_height":4736609}`,
	)
	ct.StateSet("mapping_contract", "pubkey", `0242f9da15eae56fe6aca65136738905c0afdb2c4edf379e107b3b00b98c7fc9f0`)

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
		Action:     "register_pubkey",
		Payload:    json.RawMessage([]byte("1000")),
		RcLimit:    1000,
		Intents:    []contracts.Intent{},
	})
	if result.Err != nil {
		fmt.Println("error:", *result.Err)
	}
	assert.True(t, result.Success)                 // assert contract execution success
	assert.LessOrEqual(t, gasUsed, uint(10000000)) // assert this call uses no more than 10M WASM gas
	fmt.Println("Return value:", result.Ret)
}

const rawBlocks = `{"blocks":"000000204286711ef1b295f5393717779e97684f2df7db3637564376ed3a54010000000014833ac94c78dc6f17424a7e3620bcd5c1ea1c282196b2ba8cf4af5ac17c206a9dbbe968ffff001d936e4485000000203a3d51f10d78c09023158cac89d30c45270ce1031620294b457a4d0e00000000043fae4bb9f9729d603552558c0dc9dea27270feda93c014d76bee213f4c5b5752c0e968ffff001d1519a9c0","latest_fee":2}`

func TestAddBlocks(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, "last_block_height", "4736609")
	ct.StateSet(
		contractId,
		"block4736609",
		"000000205fe55a9fc06c60fd340c84411363dfd8b574e8bfe6a44ec21f170f0d000000008c84bcca5e78351d0c8f671c7b9f83430e80ad462fa0b808a0be2c3b1c142df4e8b6e968ffff001db2174f36",
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

	fmt.Printf("%s: %s\n\n", "last_block_height", ct.StateGet(contractId, "last_block_height"))
	fmt.Printf("added block 1: %s\n", ct.StateGet("mapping_contract", "block4736610"))
	fmt.Printf("added block 2: %s\n", ct.StateGet("mapping_contract", "block4736611"))
	fmt.Printf("%s: %s\n\n", "supply", ct.StateGet(contractId, "supply"))

	fmt.Println("Return value:", result.Ret)
}

const seedBlockInput = `{"block_header":"0000002081e2ced515b739090e16bd5d6b7cd7d5450ebe1deb24e4ff2c00000000000000ddba270323b3ae839a4ac7bc31ab10f35c00204833bdcf5d88cf2bd9247bc030c40dee68ffff001d4ee60d63","block_height":4736940}`

func TestSeedBlocks(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	// ct.StateSet(
	// 	"mapping_contract",
	// 	"blocklist",
	// 	`{"block_map":{"4736609":"000000205fe55a9fc06c60fd340c84411363dfd8b574e8bfe6a44ec21f170f0d000000008c84bcca5e78351d0c8f671c7b9f83430e80ad462fa0b808a0be2c3b1c142df4e8b6e968ffff001db2174f36"},"last_height":4736609}`,
	// )

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

	fmt.Printf("last height state: %s\n", ct.StateGet("mapping_contract", "last_block_height"))
	fmt.Printf("seeded block: %s\n", ct.StateGet("mapping_contract", "block4736940"))

	fmt.Println("Return value:", result.Ret)
}
