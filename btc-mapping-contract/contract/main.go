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
const primaryPublicKeyStateKey = "pubkey"
const backupPublicKeyStateKey = "backupkey"

// passed via ldflags, will compile for testnet when set to "testnet"
var NetworkMode string

func checkAuth() {
	var adminAddress string
	if mapping.IsTestnet(NetworkMode) {
		adminAddress = *sdk.GetEnvKey("contract.owner")
	} else {
		adminAddress = oracleAddress
	}
	if sdk.GetEnv().Sender.Address.String() != adminAddress {
		sdk.Abort("no permission")
	}
}

//go:wasmexport seed_blocks
func SeedBlocks(blockSeedInput *string) *string {
	checkAuth()

	newLastHeight, err := blocklist.HandleSeedBlocks(blockSeedInput, NetworkMode)
	if err != nil {
		sdk.Abort(err.Error())
	}

	outMsg := fmt.Sprintf("last height: %d", newLastHeight)
	return &outMsg
}

//go:wasmexport add_blocks
func AddBlocks(addBlocksInput *string) *string {
	checkAuth()

	var addBlocksObj blocklist.AddBlocksInput
	err := tinyjson.Unmarshal([]byte(*addBlocksInput), &addBlocksObj)
	if err != nil {
		sdk.Abort(err.Error())
	}

	blockHeaders, err := blocklist.DivideHeaderList(&addBlocksObj.Blocks)
	if err != nil {
		sdk.Abort(err.Error())
	}

	lastHeight, err := blocklist.LastHeightFromState()
	if err != nil {
		sdk.Abort(err.Error())
	}

	err = blocklist.HandleAddBlocks(blockHeaders, lastHeight)
	// save it before handling add blocks error, because failure there is a more extreme fail case
	blocklist.LastHeightToState(lastHeight)

	// handle adding blocks error
	outMsg := blocklist.AddBlockOutput{
		LastBlockHeight: *lastHeight,
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

	publicKeys := mapping.PublicKeys{
		PrimaryPubKey: *sdk.StateGetObject(primaryPublicKeyStateKey),
		BackupPubKey:  *sdk.StateGetObject(backupPublicKeyStateKey),
	}

	contractState, err := mapping.InitializeMappingState(&publicKeys, NetworkMode, mapInstructions.Instructions...)
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
	publicKeys := mapping.PublicKeys{
		PrimaryPubKey: *sdk.StateGetObject(primaryPublicKeyStateKey),
		BackupPubKey:  *sdk.StateGetObject(backupPublicKeyStateKey),
	}
	if publicKeys.PrimaryPubKey == "" {
		sdk.Abort("No registered public key")
	}

	var unmapInstructions mapping.UnmappingInputData
	err := tinyjson.Unmarshal([]byte(*tx), &unmapInstructions)
	if err != nil {
		sdk.Abort(err.Error())
	}

	contractState, err := mapping.IntializeContractState(&publicKeys, NetworkMode)
	if err != nil {
		sdk.Abort(err.Error())
	}

	err = contractState.HandleUnmap(&unmapInstructions)
	if err != nil {
		sdk.Abort(fmt.Sprintf("%d %s", 1, err.Error()))
	}
	err = contractState.SaveToState()
	if err != nil {
		sdk.Abort(err.Error())
	}

	outMsg := fmt.Sprintf("%d", 0)
	return &outMsg
}

//go:wasmexport transfer
func Transfer(tx *string) *string {
	var transferInstructions mapping.TransferInputData
	err := tinyjson.Unmarshal([]byte(*tx), &transferInstructions)
	if err != nil {
		sdk.Abort(err.Error())
	}

	err = mapping.HandleTrasfer(&transferInstructions)
	if err != nil {
		sdk.Abort(fmt.Sprintf("%d %s", 1, err.Error()))
	}

	outMsg := fmt.Sprintf("%d", 0)
	return &outMsg
}

//go:wasmexport register_public_key
func RegisterPublicKey(keyStr *string) *string {
	env := sdk.GetEnv()
	// leave this as owner always
	if env.Sender.Address.String() != *sdk.GetEnvKey("contract.owner") {
		sdk.Abort("no permission")
	}

	var keys mapping.PublicKeys
	err := tinyjson.Unmarshal([]byte(*keyStr), &keys)
	if err != nil {
		sdk.Abort(fmt.Sprintf("error unmarshalling keys: %s", err.Error()))
	}

	result := mapping.PublicKeys{
		PrimaryPubKey: "unchanged",
		BackupPubKey:  "unchanged",
	}

	if keys.PrimaryPubKey != "" {
		existingPrimary := sdk.StateGetObject(primaryPublicKeyStateKey)
		if *existingPrimary == "" || mapping.IsTestnet(NetworkMode) {
			sdk.StateSetObject(primaryPublicKeyStateKey, keys.PrimaryPubKey)
			result.PrimaryPubKey = "set primary key"
		} else {
			result.PrimaryPubKey = fmt.Sprintf("primary key already registered: %s", *existingPrimary)
		}
	}

	if keys.BackupPubKey != "" {
		existingBackup := sdk.StateGetObject(backupPublicKeyStateKey)
		if *existingBackup == "" || mapping.IsTestnet(NetworkMode) {
			sdk.StateSetObject(backupPublicKeyStateKey, keys.BackupPubKey)
			result.BackupPubKey = "set backup key"
		} else {
			result.BackupPubKey = fmt.Sprintf("backup key already registered: %s", *existingBackup)
		}
	}

	resultBytes, err := tinyjson.Marshal(result)
	if err != nil {
		sdk.Abort(fmt.Sprintf("error marshalling result: %s", err.Error()))
	}
	resultMsg := string(resultBytes)
	return &resultMsg
}

//go:wasmexport create_key_pair
func CreateKeyPair(_ *string) *string {
	// leave this as owner always
	if sdk.GetEnv().Sender.Address.String() != *sdk.GetEnvKey("contract.owner") {
		sdk.Abort("no permission")
	}

	keyId := mapping.TssKeyName
	sdk.TssCreateKey(keyId, "ecdsa")
	return &keyId
}
