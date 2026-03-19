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
	"dash-mapping-contract/contract/blocklist"
	"dash-mapping-contract/contract/constants"
	ce "dash-mapping-contract/contract/contracterrors"
	"dash-mapping-contract/contract/mapping"
	_ "dash-mapping-contract/sdk" // ensure sdk is imported
	"encoding/hex"
	"strconv"
	"strings"

	"dash-mapping-contract/sdk"

	"github.com/CosmWasm/tinyjson"
)

// passed via ldflags, will compile for testnet when set to "testnet"
var NetworkMode string

func checkAdmin() {
	caller := sdk.GetEnv().Caller.String()
	if caller == constants.OracleAddress {
		return
	}
	if constants.IsTestnet(NetworkMode) && caller == *sdk.GetEnvKey("contract.owner") {
		return
	}
	ce.CustomAbort(
		ce.NewContractError(ce.ErrNoPermission, "this action must be performed by a contract administrator"),
	)
}

//go:wasmexport seedBlocks
func SeedBlocks(blockSeedInput *string) *string {
	checkAdmin()

	var seedParams blocklist.SeedBlocksParams
	err := tinyjson.Unmarshal([]byte(*blockSeedInput), &seedParams)
	if err != nil {
		ce.CustomAbort(ce.WrapContractError(ce.ErrJson, err))
	}

	newLastHeight, err := blocklist.HandleSeedBlocks(seedParams, constants.IsTestnet(NetworkMode))
	if err != nil {
		ce.CustomAbort(err)
	}

	outMsg := "last height: " + strconv.FormatUint(uint64(newLastHeight), 10)
	return &outMsg
}

//go:wasmexport addBlocks
func AddBlocks(addBlocksInput *string) *string {
	checkAdmin()

	var addBlocksObj blocklist.AddBlocksParams
	err := tinyjson.Unmarshal([]byte(*addBlocksInput), &addBlocksObj)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	blockHeaders, err := blocklist.DivideHeaderList(&addBlocksObj.Blocks)
	if err != nil {
		ce.CustomAbort(
			ce.WrapContractError(ce.ErrInput, err, "error parsing block headers"),
		)
	}

	var resultBuilder strings.Builder
	lastHeight, added, err := blocklist.HandleAddBlocks(blockHeaders, NetworkMode)
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
	var mapInstructions mapping.MapParams
	err := tinyjson.Unmarshal([]byte(*incomingTx), &mapInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	publicKeys, err := loadPublicKeys()
	if err != nil {
		ce.CustomAbort(err)
	}

	contractState, err := mapping.InitializeMappingState(publicKeys, NetworkMode, mapInstructions.Instructions...)
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
	publicKeys, err := loadPublicKeys()
	if err != nil {
		ce.CustomAbort(err)
	}

	var unmapInstructions mapping.TransferParams
	err = tinyjson.Unmarshal([]byte(*tx), &unmapInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}
	if len(unmapInstructions.To) < 26 {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, "invalid destination address ["+unmapInstructions.To+"]"),
		)
	}

	contractState, err := mapping.IntializeContractState(publicKeys, NetworkMode)
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

	err = mapping.HandleTransfer(&transferInstructions)
	if err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

// Draws funds from a third-party account that has approved the caller.
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

	err = mapping.HandleTransfer(&drawInstructions)
	if err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

// Sets a spending allowance for a spender contract to use the caller's tokens.
//
//go:wasmexport approve
func Approve(input *string) *string {
	env := sdk.GetEnv()
	var params mapping.AllowanceParams
	err := tinyjson.Unmarshal([]byte(*input), &params)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput))
	}
	if params.Spender == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "spender address required"))
	}
	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "invalid amount value"))
	}
	if amount < 0 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "allowance amount must be non-negative"))
	}
	if params.Spender == env.Caller.String() {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "cannot approve self as spender"))
	}
	mapping.HandleApprove(env.Caller.String(), params.Spender, amount)
	return mapping.StrPtr("0")
}

// Increases the spending allowance for a spender contract.
//
//go:wasmexport increaseAllowance
func IncreaseAllowance(input *string) *string {
	env := sdk.GetEnv()
	var params mapping.AllowanceParams
	err := tinyjson.Unmarshal([]byte(*input), &params)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput))
	}
	if params.Spender == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "spender address required"))
	}
	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "invalid amount value"))
	}
	if amount <= 0 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "amount must be positive"))
	}
	err = mapping.HandleIncreaseAllowance(env.Caller.String(), params.Spender, amount)
	if err != nil {
		ce.CustomAbort(err)
	}
	return mapping.StrPtr("0")
}

// Decreases the spending allowance for a spender contract.
//
//go:wasmexport decreaseAllowance
func DecreaseAllowance(input *string) *string {
	env := sdk.GetEnv()
	var params mapping.AllowanceParams
	err := tinyjson.Unmarshal([]byte(*input), &params)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput))
	}
	if params.Spender == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "spender address required"))
	}
	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "invalid amount value"))
	}
	if amount <= 0 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "amount must be positive"))
	}
	err = mapping.HandleDecreaseAllowance(env.Caller.String(), params.Spender, amount)
	if err != nil {
		ce.CustomAbort(err)
	}
	return mapping.StrPtr("0")
}

// Confirms a pending spend transaction, promoting its unconfirmed change UTXOs
// to the confirmed pool. Called by the bot when a withdrawal TX is broadcast.
//
//go:wasmexport confirmSpend
func ConfirmSpend(input *string) *string {
	checkAdmin()

	var params mapping.ConfirmSpendParams
	err := tinyjson.Unmarshal([]byte(*input), &params)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput))
	}
	if params.TxId == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "tx_id required"))
	}

	publicKeys, err := loadPublicKeys()
	if err != nil {
		ce.CustomAbort(err)
	}

	contractState, err := mapping.IntializeContractState(publicKeys, NetworkMode)
	if err != nil {
		ce.CustomAbort(err)
	}

	err = contractState.HandleConfirmSpend(params.TxId)
	if err != nil {
		ce.CustomAbort(err)
	}

	err = contractState.SaveToState()
	if err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

func loadPublicKeys() (mapping.PublicKeys, error) {
	primaryRaw := *sdk.StateGetObject(constants.PrimaryPublicKeyStateKey)
	if primaryRaw == "" {
		return mapping.PublicKeys{}, ce.NewContractError(ce.ErrInitialization, "no registered public key")
	}
	backupRaw := *sdk.StateGetObject(constants.BackupPublicKeyStateKey)

	var keys mapping.PublicKeys
	if len(primaryRaw) != 33 {
		return keys, ce.NewContractError(ce.ErrInitialization, "stored primary key is not 33 bytes")
	}
	copy(keys.Primary[:], primaryRaw)
	if len(backupRaw) != 33 {
		return keys, ce.NewContractError(ce.ErrInitialization, "stored backup key is not 33 bytes")
	}
	copy(keys.Backup[:], backupRaw)
	return keys, nil
}

func validateAndDecodeKey(keyHex string) (mapping.CompressedPubKey, error) {
	key, err := mapping.DecodeCompressedPubKey(keyHex)
	if err != nil {
		return key, ce.WrapContractError(ce.ErrInput, err, "invalid compressed public key")
	}
	return key, nil
}

//go:wasmexport registerPublicKey
func RegisterPublicKey(keyStr *string) *string {
	env := sdk.GetEnv()
	// leave this as owner always
	if env.Caller.String() != *sdk.GetEnvKey("contract.owner") {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "action must be performed by the contract owner"),
		)
	}

	var keys mapping.RegisterKeyParams
	err := tinyjson.Unmarshal([]byte(*keyStr), &keys)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	var resultBuilder strings.Builder

	if keys.PrimaryPubKey != "" {
		key, err := validateAndDecodeKey(keys.PrimaryPubKey)
		if err != nil {
			ce.CustomAbort(ce.Prepend(err, "error registering primary public key"))
		}
		existingPrimary := sdk.StateGetObject(constants.PrimaryPublicKeyStateKey)
		if *existingPrimary == "" || constants.IsTestnet(NetworkMode) {
			sdk.StateSetObject(constants.PrimaryPublicKeyStateKey, string(key[:]))
			resultBuilder.WriteString("set primary key to: " + keys.PrimaryPubKey)
		} else {
			resultBuilder.WriteString("primary key already registered: " + hex.EncodeToString([]byte(*existingPrimary)))
		}
	}

	if keys.BackupPubKey != "" {
		key, err := validateAndDecodeKey(keys.BackupPubKey)
		if err != nil {
			ce.CustomAbort(ce.Prepend(err, "error registering backup public key"))
		}
		if resultBuilder.Len() > 0 {
			resultBuilder.WriteString(", ")
		}
		existingBackup := sdk.StateGetObject(constants.BackupPublicKeyStateKey)
		if *existingBackup == "" || constants.IsTestnet(NetworkMode) {
			sdk.StateSetObject(constants.BackupPublicKeyStateKey, string(key[:]))
			resultBuilder.WriteString("set backup key to: " + keys.BackupPubKey)
		} else {
			resultBuilder.WriteString("backup key already registered: " + hex.EncodeToString([]byte(*existingBackup)))
		}
	}

	return mapping.StrPtr(resultBuilder.String())
}

//go:wasmexport createKeyPair
func CreateKeyPair(_ *string) *string {
	// leave this as owner always
	if sdk.GetEnv().Caller.String() != *sdk.GetEnvKey("contract.owner") {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "action must be performed by the contract owner"),
		)
	}

	keyId := constants.TssKeyName
	sdk.TssCreateKey(keyId, "ecdsa")
	return mapping.StrPtr("key created, id: " + keyId)
}

//go:wasmexport registerRouter
func RegisterRouter(input *string) *string {
	env := sdk.GetEnv()
	// leave this as owner always
	if env.Caller.String() != *sdk.GetEnvKey("contract.owner") {
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
		existingPrimary := sdk.StateGetObject(constants.RouterContractIdKey)
		if *existingPrimary == "" || constants.IsTestnet(NetworkMode) {
			sdk.StateSetObject(constants.RouterContractIdKey, router.ContractId)
			resultBuilder.WriteString("set router contract ID to: " + router.ContractId)
		} else {
			resultBuilder.WriteString("router contract ID already registered: " + *existingPrimary)
		}
	}

	return mapping.StrPtr(resultBuilder.String())
}
