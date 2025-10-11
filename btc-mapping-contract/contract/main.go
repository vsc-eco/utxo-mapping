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

const ORACLEADDRESS = "oracle_address"
const publicKeyStateKey = "public_key"

//go:wasmexport add_blocks
func AddBlocks(blocksHeaderHex *string) *string {
	if sdk.GetEnv().Sender.Address != ORACLEADDRESS {
		sdk.Abort("no permission")
	}

	blockHeaders, err := blocklist.DivideHeaderList(blocksHeaderHex)
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
		Success:         err != nil,
		Error:           err.Error(),
	}
	outMsgBytes, err := tinyjson.Marshal(outMsg)
	outMsgString := string(outMsgBytes)
	if err != nil {
		sdk.Abort(outMsgString)
	}

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

	contractState, err := mapping.IntializeContractState(*publicKey, mapInstructions.Instructions...)
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

type Recipient struct {
	Recipient string `json:"recipient"`
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
	// derived from tx
	amount := int64(0)
	recipientVscAddress := ""

	publicKey := sdk.StateGetObject(publicKeyStateKey)

	contractState, err := mapping.IntializeContractState(*publicKey)
	if err != nil {
		sdk.Abort(err.Error())
	}
	contractState.HandleTrasfer(amount, recipientVscAddress)

	return tx
}

//go:wasmexport create_key_pair
func CreateKeyPair(_ *string) *string {
	success := "success"
	return &success
}

//go:wasmexport register_public_key
func RegisterPublicKey(key *string) *string {
	existing := sdk.StateGetObject(publicKeyStateKey)
	if *existing == "" {
		sdk.StateSetObject(publicKeyStateKey, *key)
		result := "success"
		return &result
	}
	result := fmt.Sprintf("key already registered: %s", *existing)
	return &result
}
