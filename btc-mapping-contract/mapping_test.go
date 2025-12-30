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

const rawInstruction = `{"tx_data":{"block_height":114810,"raw_tx_hex":"02000000000101ff34ce5f34ad7c5ff9eac34c24953f10c2c1bd2cd87fd20bfaf654e030dd5da10000000000fdffffff0288130000000000002200202a0ce40846879b42fa7739eb15cdab77ca01b7817a97879b1f58feb52e44478cf38c07000000000022512021fa9598255a3c65b217132475dfd5c979a874721ca45d728db8eeb13b80a66c0247304402204a1fd9f399bc46960e410ac4e55653c8ea9f64508779ec0bdb8e388afa2180db02202a9ac46b41e32cbf985a8b2742764596b027599a7e252358fa4a8da03aa887b70121035d96c7175fb6ca59eb5299a1cb83acf5e24a44e3ef811923a4ff408981929ba179c00100","merkle_proof_hex":"b699e12d1185403c486cff27b27623076f1f0813bef11d20b1d06a377b9aa1e0cca5dd25fadecb3b1f78cc782ff691e15d0d20cedff223cd69c53ceb0faa6b1c5d8d4647f5b9a7e4842d057f02dc8945aa7505a7d3d9150056b2fdc32f778c311e17834d3d8f0b8db75d21e734977dfd815024d63afcfe389f8d47f4f678f1ae73a2d4e3f73a3bc9f11a0f96843653f15e592645b99cf9c30ca5176951fbbbe1e7c842da4f7dfd4794108ac3b74b14670665be1e519a203f429dbea7086cf908082350445bf369d984f9cfb603c65cfda7c769e628d39558402e47de34db8c64","tx_index":118},"instructions":["deposit_to=hive:milo-hpr"]}`

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
	ct.StateSet(contractId, "last_block_height", "114810")
	ct.StateSet(
		contractId,
		"block114810",
		"00e0eb20634e08b3fea4fe1467451c13c1b9637765925fde62d8c396df218a0c00000000486e3aeb4090e44737ef71a71855dae60dbd8cf0b7a067c760e5ef4b8365519435104a699f1f0319d229d24b",
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
			"observed_txs95af4aafb228696204ed86003e9ac6b904d6493d4311eda90ac34875c4ebab9a:0",
			"utxo_registry",
			"utxos0",
			"utxo_id",
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
	ct.StateSet(contractId, "balhive:milo-hpr", "10000")
	ct.StateSet(
		contractId,
		"observed_txs95af4aafb228696204ed86003e9ac6b904d6493d4311eda90ac34875c4ebab9a:0",
		"1",
	)
	ct.StateSet(
		contractId,
		"observed_txs4cfede180e58a2326aabd41c20fefcf60aba212e031e5b27be3dbfd5caf09af1:1",
		"1",
	)
	ct.StateSet(
		contractId,
		"utxo_registry",
		`[[0,5000,1],[1,5000,1]]`,
	)
	ct.StateSet(
		contractId,
		"utxos0",
		`{"tx_id":"95af4aafb228696204ed86003e9ac6b904d6493d4311eda90ac34875c4ebab9a","vout":0,"amount":5000,"pk_script":"ACAqDOQIRoebQvp3OesVzat3ygG3gXqXh5sfWP61LkRHjA==","tag":"6ad59da3ece6b8fcfd0cd8c615ed5ec82504fbd81808b2aea5fb750adb01f20c"}`,
	)
	ct.StateSet(
		contractId,
		"utxos1",
		`{"tx_id":"4cfede180e58a2326aabd41c20fefcf60aba212e031e5b27be3dbfd5caf09af1","vout":1,"amount":5000,"pk_script":"ACC63J0lCXrLrpyBg0RUMqOyJOX7MbMjqDXkNkwDg974/w==","tag":""}`,
	)
	ct.StateSet(contractId, "utxo_id", "2")
	ct.StateSet(contractId, "tx_spends", "null")
	ct.StateSet(
		contractId,
		"supply",
		`{"active_supply":10000,"user_supply":10000,"fee_supply":0,"base_fee_rate":1}`,
	)
	ct.StateSet(contractId, "last_block_height", "114810")
	ct.StateSet(
		contractId,
		"block114810",
		"00e0eb20634e08b3fea4fe1467451c13c1b9637765925fde62d8c396df218a0c00000000486e3aeb4090e44737ef71a71855dae60dbd8cf0b7a067c760e5ef4b8365519435104a699f1f0319d229d24b",
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
			[]byte(`{"amount":7500,"recipient_btc_address":"tb1qxvxtxtjgcmu8r82ss4yhg899xt4rfdnvhjspp8"}`),
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

	txSpendsReg := []string{}
	err := json.Unmarshal([]byte(ct.StateGet(contractId, "tx_spend_registry")), &txSpendsReg)
	if err != nil {
		fmt.Printf("err unmarshalling txspends registry: %s", err.Error())
	}

	keysToPrint := []string{
		"balhive:milo-hpr",
		"observed_txs64240d2b706020087463530cd13304907033dd50b7938817e1016416376876bf:0",
		"utxo_registry",
		"utxo_id",
		"utxos0",
		"utxos1",
		"utxos2",
		"utxos3",
		"supply",
		"last_block_height",
		"tx_spend_registry",
	}

	for _, txSpend := range txSpendsReg {
		keysToPrint = append(keysToPrint, "tx_spend"+txSpend)
	}

	printKeys(
		&ct,
		contractId,
		keysToPrint,
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
	ct.StateSet(contractId, "utxo_id", "1")
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

const inputPubKey = `{"primary_public_key": "pubkey", "backup_public_key": "backupkey"}`

func TestRegisterKey(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)

	// keys := mapping.PublicKeys{
	// 	PrimaryPubKey: "pub",
	// 	BackupPubKey:  "back",
	// }

	// input, err := tinyjson.Marshal(keys)
	// if err != nil {
	// 	t.Fatalf("error marshalling input string: %s", err.Error())
	// }

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
		Payload:    json.RawMessage(inputPubKey),
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
			"pubkey",
			"backupkey",
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
		"0000002076bd5abaaf4f9b70901c84c29ce5211e85d0f5e2dc6be53619193b500007acadb1928b7931a92288bfd3ab925391b4913d7ebad46f92067399a5541d57aa6ed1c69ffff001df352048d",
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
