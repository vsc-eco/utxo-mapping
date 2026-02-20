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
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/contract/mapping"
	_ "btc-mapping-contract/sdk" // ensure sdk is imported
	"fmt"
	"strconv"
	"strings"

	"btc-mapping-contract/sdk"

	"github.com/CosmWasm/tinyjson"
)

const oracleAddress = "did:vsc:oracle:btc"
const primaryPublicKeyStateKey = "pubkey"
const backupPublicKeyStateKey = "backupkey"

// passed via ldflags, will compile for testnet when set to "testnet"
var NetworkMode string

func checkAdmin() {
	var adminAddress string
	if mapping.IsTestnet(NetworkMode) {
		adminAddress = *sdk.GetEnvKey("contract.owner")
	} else {
		adminAddress = oracleAddress
	}
	if sdk.GetEnv().Caller.String() != sdk.GetEnv().Sender.Address.String() {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "admin actions must be performed directly by the sender"),
		)
	}
	if sdk.GetEnv().Sender.Address.String() != adminAddress {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "this action must be performed by a contract administrator"),
		)
	}
}

//go:wasmexport seedBlocks
func SeedBlocks(blockSeedInput *string) *string {
	checkAdmin()

	newLastHeight, err := blocklist.HandleSeedBlocks(blockSeedInput, mapping.IsTestnet(NetworkMode))
	if err != nil {
		ce.CustomAbort(err)
	}

	outMsg := fmt.Sprintf("last height: %d", newLastHeight)
	return &outMsg
}

//go:wasmexport addBlocks
func AddBlocks(addBlocksInput *string) *string {
	checkAdmin()

	var addBlocksObj blocklist.AddBlocksInput
	err := tinyjson.Unmarshal([]byte(*addBlocksInput), &addBlocksObj)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	blockHeaders, err := blocklist.DivideHeaderList(&addBlocksObj.Blocks)
	if err != nil {
		ce.CustomAbort(err)
	}

	var resultBuilder strings.Builder
	lastHeight, added, err := blocklist.HandleAddBlocks(blockHeaders)
	if err != nil {
		if err != blocklist.ErrorSequenceIncorrect {
			ce.CustomAbort(err)
		} else {
			resultBuilder.WriteString("error adding blocks: " + err.Error())
			resultBuilder.WriteString(", added " + strconv.FormatUint(uint64(added), 10) + " blocks, ")
		}
	}
	resultBuilder.WriteString("last height: " + strconv.FormatUint(uint64(lastHeight), 10))

	blocklist.LastHeightToState(lastHeight)

	// update base fee rate, do this after blocks because blocks more likely to fail
	systemSupply, err := mapping.SupplyFromState()
	if err != nil {
		ce.CustomAbort(err)
	}
	systemSupply.BaseFeeRate = addBlocksObj.LatestFee
	mapping.SaveSupplyToState(systemSupply)
	resultBuilder.WriteString(", base fee: " + strconv.FormatInt(systemSupply.BaseFeeRate, 10))

	return mapping.StrPtr(resultBuilder.String())
}

//go:wasmexport map
func Map(incomingTx *string) *string {
	var mapInstructions mapping.MappingParams
	err := tinyjson.Unmarshal([]byte(*incomingTx), &mapInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	publicKeys := mapping.PublicKeys{
		PrimaryPubKey: *sdk.StateGetObject(primaryPublicKeyStateKey),
		BackupPubKey:  *sdk.StateGetObject(backupPublicKeyStateKey),
	}
	if publicKeys.PrimaryPubKey == "" {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInitialization, "not registered public key"),
		)
	}

	contractState, err := mapping.InitializeMappingState(&publicKeys, NetworkMode, mapInstructions.Instructions...)
	if err != nil {
		ce.CustomAbort(err)
	}

	err = contractState.HandleMap(mapInstructions.TxData)
	if err != nil {
		ce.CustomAbort(err)
	}

	err = contractState.SaveToState()
	if err != nil {
		ce.CustomAbort(err)
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
		ce.CustomAbort(ce.NewContractError(ce.ErrInitialization, ce.MsgNoPublicKey))
	}

	var unmapInstructions mapping.TransferParams
	err := tinyjson.Unmarshal([]byte(*tx), &unmapInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}
	if len(unmapInstructions.To) < 26 {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, "invalid address ["+unmapInstructions.To+"]"),
		)
	}

	contractState, err := mapping.IntializeContractState(&publicKeys, NetworkMode)
	if err != nil {
		err = ce.Prepend(err, "error initializing contract state")
		ce.CustomAbort(err)
	}

	err = contractState.HandleUnmap(&unmapInstructions)
	if err != nil {
		ce.CustomAbort(err)
	}
	err = contractState.SaveToState()
	if err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

// Transfers funds from the Caller (immediate caller of the contract)
//
//go:wasmexport transfer
func Transfer(tx *string) *string {
	var transferInstructions mapping.TransferParams
	err := tinyjson.Unmarshal([]byte(*tx), &transferInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	err = mapping.HandleTrasfer(&transferInstructions)
	if err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

// Draws funds from the Sender (original user who sent the transaction)
//
//go:wasmexport transferFrom
func TransferFrom(tx *string) *string {
	var drawInstructions mapping.TransferParams
	err := tinyjson.Unmarshal([]byte(*tx), &drawInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	err = mapping.HandleDraw(&drawInstructions)
	if err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

//go:wasmexport registerPublicKey
func RegisterPublicKey(keyStr *string) *string {
	env := sdk.GetEnv()
	// leave this as owner always
	if env.Sender.Address.String() != *sdk.GetEnvKey("contract.owner") {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "action must be performed by the contract owner"),
		)
	}

	var keys mapping.PublicKeys
	err := tinyjson.Unmarshal([]byte(*keyStr), &keys)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	var resultBuilder strings.Builder

	if keys.PrimaryPubKey != "" {
		existingPrimary := sdk.StateGetObject(primaryPublicKeyStateKey)
		if *existingPrimary == "" || mapping.IsTestnet(NetworkMode) {
			sdk.StateSetObject(primaryPublicKeyStateKey, keys.PrimaryPubKey)
			resultBuilder.WriteString("set primary key to: " + keys.PrimaryPubKey)
		} else {
			resultBuilder.WriteString("primary key already registered: " + *existingPrimary)
		}
	}

	if keys.BackupPubKey != "" {
		if resultBuilder.Len() > 0 {
			resultBuilder.WriteString(", ")
		}
		existingBackup := sdk.StateGetObject(backupPublicKeyStateKey)
		if *existingBackup == "" || mapping.IsTestnet(NetworkMode) {
			sdk.StateSetObject(backupPublicKeyStateKey, keys.BackupPubKey)
			resultBuilder.WriteString("set backup key to: " + keys.BackupPubKey)
		} else {
			resultBuilder.WriteString("backup key already registered: " + *existingBackup)
		}
	}

	return mapping.StrPtr(resultBuilder.String())
}

//go:wasmexport createKeyPair
func CreateKeyPair(_ *string) *string {
	// leave this as owner always
	if sdk.GetEnv().Sender.Address.String() != *sdk.GetEnvKey("contract.owner") {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "action must be performed by the contract owner"),
		)
	}

	keyId := mapping.TssKeyName
	sdk.TssCreateKey(keyId, "ecdsa")
	return mapping.StrPtr("key created, id: " + keyId)
}

//go:wasmexport registerRouter
func RegisterRouter(input *string) *string {
	env := sdk.GetEnv()
	// leave this as owner always
	if env.Sender.Address.String() != *sdk.GetEnvKey("contract.owner") {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "action must be performed by the contract owner"),
		)
	}

	var router mapping.RouterContract
	err := tinyjson.Unmarshal([]byte(*input), &router)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	var resultBuilder strings.Builder

	if router.ContractId != "" {
		existingPrimary := sdk.StateGetObject(mapping.RouterContractIdKey)
		if *existingPrimary == "" || mapping.IsTestnet(NetworkMode) {
			sdk.StateSetObject(mapping.RouterContractIdKey, router.ContractId)
			resultBuilder.WriteString("set router contract ID to: " + router.ContractId)
		} else {
			resultBuilder.WriteString("router contract ID already registered: " + *existingPrimary)
		}
	}

	return mapping.StrPtr(resultBuilder.String())
}
