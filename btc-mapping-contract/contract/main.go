// Proof of Concept VSC Smart Contract in Golang
//
// Build command: tinygo build -o main.wasm -gc=custom -scheduler=none -panic=trap -no-debug -target=wasm-unknown main.go
// Inspect Output: wasmer inspect main.wasm
// Run command (only works w/o SDK imports): wasmedge run main.wasm entrypoint 0
//
// Caveats:
// - Go routines, channels, and defer are disabled
// - panic() always halts the program, since you can't recover in a deferred function call
// - must import sdk or build fails
// - to mark a function as a valid entrypoint, it must be manually exported (//go:wasmexport <entrypoint-name>)
//
// TODO:
// - when panic()ing, call `env.abort()` instead of executing the unreachable WASM instruction
// - Remove _initalize() export & double check not necessary

package main

import (
	"contract-template/contract/blocklist"
	"contract-template/contract/mapping"
	_ "contract-template/sdk" // ensure sdk is imported
	"fmt"

	"contract-template/sdk"

	"github.com/CosmWasm/tinyjson"
)

const oracleAddress = "did:vsc:oracle:btc"
const publicKeyStateKey = "public_key"

//go:wasmexport seed_blocks
func SeedBlocks(blockSeedInput *string) *string {
	// this should be oracle address for mainnet and owner address for testnet
	if sdk.GetEnv().Sender.Address.String() != *sdk.GetEnvKey("contract.owner") {
		sdk.Abort("no permission")
	}

	blockData := blocklist.BlockDataFromState()

	if len(blockData.BlockMap) > 0 {
		sdk.Abort(fmt.Sprintf("block data already seeded, last height: %d", blockData.LastHeight))
	}

	blockData.HandleSeedBlocks(blockSeedInput)
	blockData.SaveToState()

	outMsg := fmt.Sprintf("last height: %d", blockData.LastHeight)
	return &outMsg
}

//go:wasmexport add_blocks
func AddBlocks(addBlocksInput *string) *string {
	// this should be oracle address for mainnet and owner address for testnet
	if sdk.GetEnv().Sender.Address.String() != *sdk.GetEnvKey("contract.owner") {
		sdk.Abort("no permission")
	}

	var addBlocksObj blocklist.AddBlocksInput
	err := tinyjson.Unmarshal([]byte(*addBlocksInput), &addBlocksObj)
	if err != nil {
		sdk.Abort(err.Error())
	}

	blockHeaders, err := blocklist.DivideHeaderList(&addBlocksObj.Blocks)
	if err != nil {
		sdk.Abort(err.Error())
	}

	blockData := blocklist.BlockDataFromState()
	err = blockData.HandleAddBlocks(blockHeaders)
	// save it before handling add blocks error, because failure there is a more extreme fail case
	errCritical := blockData.SaveToState()
	if errCritical != nil {
		sdk.Abort(errCritical.Error())
	}
	// handle adding blocks error
	outMsg := blocklist.AddBlockOutput{
		LastBlockHeight: blockData.LastHeight,
		Success:         err == nil,
	}
	if err != nil {
		outMsg.Error = err.Error()
	}
	outMsgBytes, err := tinyjson.Marshal(outMsg)
	if err != nil {
		sdk.Abort(err.Error())
	}
	outMsgString := string(outMsgBytes)

	// update base fee rate, do this after blocks because blocks more likely to fail
	systemSupply, err := mapping.SupplyFromState()
	if err != nil {
		sdk.Abort(err.Error())
	}
	systemSupply.BaseFeeRate = addBlocksObj.LatestFee
	mapping.SaveSupplyToState(systemSupply)

	return &outMsgString
}

//go:wasmexport map
func Map(incomingTx *string) *string {
	var mapInstructions mapping.MappingInputData
	err := tinyjson.Unmarshal([]byte(*incomingTx), &mapInstructions)
	if err != nil {
		sdk.Abort(err.Error())
	}

	publicKey := sdk.StateGetObject(publicKeyStateKey)

	contractState, err := mapping.InitializeMappingState(*publicKey, mapInstructions.Instructions...)
	if err != nil {
		sdk.Abort(err.Error())
	}

	err = contractState.HandleMap(mapInstructions.TxData)
	if err != nil {
		sdk.Abort(err.Error())
	}

	err = contractState.SaveToState()
	if err != nil {
		sdk.Abort(err.Error())
	}

	ret := "success"
	return &ret
}

//go:wasmexport unmap
func Unmap(tx *string) *string {
	var unmapInstructions mapping.UnmappingInputData
	err := tinyjson.Unmarshal([]byte(*tx), &unmapInstructions)
	if err != nil {
		sdk.Abort(err.Error())
	}

	publicKey := sdk.StateGetObject(publicKeyStateKey)

	contractState, err := mapping.IntializeContractState(*publicKey)
	if err != nil {
		sdk.Abort(err.Error())
	}
	rawTx := contractState.HandleUnmap(&unmapInstructions)
	err = contractState.SaveToState()
	if err != nil {
		sdk.Abort(err.Error())
	}

	return &rawTx
}

//go:wasmexport transfer
func Transfer(tx *string) *string {
	var transferInstructions mapping.TransferInputData
	err := tinyjson.Unmarshal([]byte(*tx), &transferInstructions)
	if err != nil {
		sdk.Abort(err.Error())
	}

	balances, err := mapping.GetBalanceMap()
	if err != nil {
		sdk.Abort(err.Error())
	}
	mapping.HandleTrasfer(&transferInstructions, balances)
	err = mapping.SaveBalanceMap(balances)
	if err != nil {
		sdk.Abort(err.Error())
	}

	return tx
}

//go:wasmexport register_public_key
func RegisterPublicKey(key *string) *string {
	env := sdk.GetEnv()
	// leave this as owner always
	if env.Sender.Address.String() != *sdk.GetEnvKey("contract.owner") {
		sdk.Abort("no permission")
	}

	existing := sdk.StateGetObject(publicKeyStateKey)
	if *existing == "" {
		sdk.StateSetObject(publicKeyStateKey, *key)
		result := "success"
		return &result
	}
	result := fmt.Sprintf("key already registered: %s", *existing)
	return &result
}

//go:wasmexport create_key_pair
func CreateKeyPair(_ *string) *string {
	// leave this as owner always
	if sdk.GetEnv().Sender.Address.String() != *sdk.GetEnvKey("contract.owner") {
		sdk.Abort("no permission")
	}

	keyId := "main"
	sdk.TssCreateKey(keyId, "ecdsa")
	return &keyId
}
