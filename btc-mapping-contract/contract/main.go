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
	"btc-mapping-contract/contract/blocklist"
	"btc-mapping-contract/contract/mapping"
	_ "btc-mapping-contract/sdk" // ensure sdk is imported
	"fmt"

	"btc-mapping-contract/sdk"

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
		sdk.Abort("1: no permission")
	}
}

//go:wasmexport seed_blocks
func SeedBlocks(blockSeedInput *string) *string {
	checkAuth()

	newLastHeight, err := blocklist.HandleSeedBlocks(blockSeedInput, mapping.IsTestnet(NetworkMode))
	if err != nil {
		sdk.Abort(fmt.Sprintf("1: %s", err.Error()))
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
		sdk.Abort(fmt.Sprintf("1: %s", err.Error()))
	}

	blockHeaders, err := blocklist.DivideHeaderList(&addBlocksObj.Blocks)
	if err != nil {
		sdk.Abort(fmt.Sprintf("1: %s", err.Error()))
	}

	// pointer to last height to be modified in the function
	lastHeight, err := blocklist.LastHeightFromState()
	if err != nil {
		sdk.Abort(fmt.Sprintf("1: %s", err.Error()))
	}

	initialLastHeight := *lastHeight

	exitMsg := ""
	err = blocklist.HandleAddBlocks(blockHeaders, lastHeight)
	if err != nil {
		if err != blocklist.ErrorSequenceIncorrect {
			sdk.Abort(fmt.Sprintf("error adding blocks: %s", err.Error()))
		} else {
			blocksAdded := *lastHeight - initialLastHeight
			exitMsg = fmt.Sprintf("1: error adding blocks: %s, %d blocks added before encountering error", err.Error(), blocksAdded)
		}
	} else {
		exitMsg = fmt.Sprintf("last height: %d", *lastHeight)
	}

	blocklist.LastHeightToState(lastHeight)

	// update base fee rate, do this after blocks because blocks more likely to fail
	systemSupply, err := mapping.SupplyFromState()
	if err != nil {
		sdk.Abort(fmt.Sprintf("error updating base fee rate: %s", err.Error()))
	}
	systemSupply.BaseFeeRate = addBlocksObj.LatestFee
	mapping.SaveSupplyToState(systemSupply)
	exitMsg += fmt.Sprintf(", base fee: %d", systemSupply.BaseFeeRate)

	return &exitMsg
}

//go:wasmexport map
func Map(incomingTx *string) *string {
	var mapInstructions mapping.MappingParams
	err := tinyjson.Unmarshal([]byte(*incomingTx), &mapInstructions)
	if err != nil {
		sdk.Abort(fmt.Sprintf("1: %s", err.Error()))
	}

	publicKeys := mapping.PublicKeys{
		PrimaryPubKey: *sdk.StateGetObject(primaryPublicKeyStateKey),
		BackupPubKey:  *sdk.StateGetObject(backupPublicKeyStateKey),
	}
	if publicKeys.PrimaryPubKey == "" {
		sdk.Abort("1: no registered public key")
	}

	contractState, err := mapping.InitializeMappingState(&publicKeys, NetworkMode, mapInstructions.Instructions...)
	if err != nil {
		sdk.Abort(fmt.Sprintf("1: %s", err.Error()))
	}

	err = contractState.HandleMap(mapInstructions.TxData)
	if err != nil {
		sdk.Abort(fmt.Sprintf("1: %s", err.Error()))
	}

	err = contractState.SaveToState()
	if err != nil {
		sdk.Abort(fmt.Sprintf("1: %s", err.Error()))
	}

	return mapping.StrPtr("0")
}

//go:wasmexport unmap
func Unmap(tx *string) *string {
	publicKeys := mapping.PublicKeys{
		PrimaryPubKey: *sdk.StateGetObject(primaryPublicKeyStateKey),
		BackupPubKey:  *sdk.StateGetObject(backupPublicKeyStateKey),
	}
	if publicKeys.PrimaryPubKey == "" {
		sdk.Abort("1: no registered public key")
	}

	var unmapInstructions mapping.SendParams
	err := tinyjson.Unmarshal([]byte(*tx), &unmapInstructions)
	if err != nil {
		sdk.Abort(fmt.Sprintf("1: %s", err.Error()))
	}

	contractState, err := mapping.IntializeContractState(&publicKeys, NetworkMode)
	if err != nil {
		sdk.Abort(fmt.Sprintf("1: %s", err.Error()))
	}

	err = contractState.HandleUnmap(&unmapInstructions)
	if err != nil {
		sdk.Abort(fmt.Sprintf("1: %s", err.Error()))
	}
	err = contractState.SaveToState()
	if err != nil {
		sdk.Abort(fmt.Sprintf("1: %s", err.Error()))
	}

	return mapping.StrPtr("0")
}

// Transfers funds from the Caller (immediate caller of the contract)
//
//go:wasmexport transfer
func Transfer(tx *string) *string {
	var transferInstructions mapping.SendParams
	err := tinyjson.Unmarshal([]byte(*tx), &transferInstructions)
	if err != nil {
		sdk.Abort(err.Error())
	}

	err = mapping.HandleTrasfer(&transferInstructions)
	if err != nil {
		sdk.Abort(fmt.Sprintf("1: %s", err.Error()))
	}

	return mapping.StrPtr("0")
}

// Draws funds from the Sender (original user who sent the transaction)
//
//go:wasmexport draw
func Draw(tx *string) *string {
	var drawInstructions mapping.SendParams
	err := tinyjson.Unmarshal([]byte(*tx), &drawInstructions)
	if err != nil {
		sdk.Abort(err.Error())
	}

	err = mapping.HandleDraw(&drawInstructions)
	if err != nil {
		sdk.Abort(fmt.Sprintf("1: %s", err.Error()))
	}

	return mapping.StrPtr("0")
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

	resultMsg := "0"

	if keys.PrimaryPubKey != "" {
		resultMsg += ":"
		existingPrimary := sdk.StateGetObject(primaryPublicKeyStateKey)
		if *existingPrimary == "" || mapping.IsTestnet(NetworkMode) {
			sdk.StateSetObject(primaryPublicKeyStateKey, keys.PrimaryPubKey)
			resultMsg += fmt.Sprintf(" set primary key to: %s", keys.PrimaryPubKey)
		} else {
			resultMsg += fmt.Sprintf(" primary key already registered: %s", *existingPrimary)
		}
	}

	if keys.BackupPubKey != "" {
		if len(resultMsg) > 1 {
			resultMsg += ","
		} else {
			resultMsg += ":"
		}
		existingBackup := sdk.StateGetObject(backupPublicKeyStateKey)
		if *existingBackup == "" || mapping.IsTestnet(NetworkMode) {
			sdk.StateSetObject(backupPublicKeyStateKey, keys.BackupPubKey)
			resultMsg += fmt.Sprintf(" set backup key to: %s", keys.BackupPubKey)
		} else {
			resultMsg += fmt.Sprintf(" backup key already registered: %s", *existingBackup)
		}
	}

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
	return mapping.StrPtr("key created, id: " + keyId)
}
