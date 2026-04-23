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
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/contract/mapping"
	_ "btc-mapping-contract/sdk" // ensure sdk is imported
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"

	"btc-mapping-contract/sdk"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/wire"
)

// passed via ldflags, will compile for testnet when set to "testnet"
var NetworkMode string

func checkOracle() {
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

func checkAdmin() {
	caller := sdk.GetEnv().Caller.String()
	if caller == constants.OracleAddress || caller == *sdk.GetEnvKey("contract.owner") {
		return
	}
	ce.CustomAbort(
		ce.NewContractError(ce.ErrNoPermission, "this action must be performed by a contract administrator"),
	)
}

func checkOwner() {
	if sdk.GetEnv().Caller.String() != *sdk.GetEnvKey("contract.owner") {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "action must be performed by the contract owner"),
		)
	}
}

func checkNotPaused() {
	s := sdk.StateGetObject(constants.PausedKey)
	if s != nil && *s == "1" {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrTransaction, "contract is paused"),
		)
	}
}

//go:wasmexport seedBlocks
func SeedBlocks(blockSeedInput *string) *string {
	checkAdmin()

	var seedParams blocklist.SeedBlocksParams
	err := tinyjson.Unmarshal([]byte(*blockSeedInput), &seedParams)
	if err != nil {
		ce.CustomAbort(ce.WrapContractError(ce.ErrJson, err, "error unmarshalling seed blocks input"))
	}

	newLastHeight, err := blocklist.HandleSeedBlocks(seedParams, constants.IsTestnet(NetworkMode))
	if err != nil {
		ce.CustomAbort(err)
	}

	// Fresh deployments start at the latest migration version so they skip all migrations.
	sdk.StateSetObject(constants.MigrateVersionKey, constants.LatestMigrateVersion)

	outMsg := "last height: " + strconv.FormatUint(uint64(newLastHeight), 10)
	return &outMsg
}

// initPruning sets the prune floor for contracts deployed before pruning was
// added. Must be called once by the contract owner after a code upgrade.
// The floor should be the original seed height (the lowest block header
// stored in state). After this, addBlocks will automatically prune old headers.
//
//go:wasmexport initPruning
func InitPruning(input *string) *string {
	checkAdmin()

	floor, err := strconv.ParseUint(*input, 10, 32)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "expected block height as integer string"))
	}

	existing := sdk.StateGetObject(constants.PruneFloorKey)
	if existing != nil && *existing != "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "prune floor already set"))
	}

	sdk.StateSetObject(constants.PruneFloorKey, strconv.FormatUint(floor, 10))
	sdk.StateSetObject(constants.SeedHeightKey, strconv.FormatUint(floor, 10))

	return mapping.StrPtr("prune floor set to " + strconv.FormatUint(floor, 10))
}

// prune removes old block headers beyond the retention window.
// Can be called independently of addBlocks to reduce state size.
// Returns the number of headers pruned and the current prune floor.
//
//go:wasmexport prune
func Prune(_ *string) *string {
	checkAdmin()

	lastHeight, err := blocklist.LastHeightFromState()
	if err != nil {
		ce.CustomAbort(ce.WrapContractError(ce.ErrStateAccess, err, "error reading last block height"))
	}

	pruned := blocklist.PruneOldHeaders(lastHeight)

	return mapping.StrPtr(
		"pruned " + strconv.Itoa(pruned) + " headers, last height: " + strconv.FormatUint(uint64(lastHeight), 10),
	)
}

//go:wasmexport addBlocks
func AddBlocks(addBlocksInput *string) *string {
	checkOracle()

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
	lastHeight, err := blocklist.HandleAddBlocks(blockHeaders, NetworkMode)
	if err != nil {
		ce.CustomAbort(err)
	}
	resultBuilder.WriteString("last height: " + strconv.FormatUint(uint64(lastHeight), 10))

	blocklist.LastHeightToState(lastHeight)

	// update base fee rate, do this after blocks because blocks more likely to fail
	systemSupply, err := mapping.SupplyFromState()
	if err != nil {
		ce.CustomAbort(err)
	}
	latestFee := addBlocksObj.LatestFee
	if latestFee == 0 {
		latestFee = 1
	}
	systemSupply.BaseFeeRate = latestFee
	mapping.SaveSupplyToState(systemSupply)
	resultBuilder.WriteString(", base fee: " + strconv.FormatInt(systemSupply.BaseFeeRate, 10))

	return mapping.StrPtr(resultBuilder.String())
}

//go:wasmexport replaceBlock
func ReplaceBlock(input *string) *string {
	checkAdmin()

	blockBytes, err := hex.DecodeString(*input)
	if err != nil {
		ce.CustomAbort(ce.WrapContractError(ce.ErrInvalidHex, err, "error decoding replacement block hex"))
	}
	if len(blockBytes) != 80 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "expected exactly 80 bytes (one block header)"))
	}

	var header blocklist.BlockHeaderBytes
	copy(header[:], blockBytes)

	height, err := blocklist.HandleReplaceBlock(header, NetworkMode)
	if err != nil {
		ce.CustomAbort(err)
	}

	outMsg := "replaced block at height: " + strconv.FormatUint(uint64(height), 10)
	return &outMsg
}

// replaceBlocks handles multi-block reorgs by replacing the top N blocks at once.
// Input is a concatenated hex string of 80-byte block headers, ordered lowest-to-highest.
// The first header replaces lastHeight-(N-1), the last replaces lastHeight.
//
//go:wasmexport replaceBlocks
func ReplaceBlocks(input *string) *string {
	checkAdmin()

	blockHeaders, err := blocklist.DivideHeaderList(input)
	if err != nil {
		ce.CustomAbort(ce.WrapContractError(ce.ErrInput, err, "error parsing replacement block headers"))
	}

	height, err := blocklist.HandleReplaceBlocks(blockHeaders, NetworkMode)
	if err != nil {
		ce.CustomAbort(err)
	}

	outMsg := "replaced " + strconv.Itoa(len(blockHeaders)) + " blocks, tip at height: " + strconv.FormatUint(uint64(height), 10)
	return &outMsg
}

//go:wasmexport map
func Map(incomingTx *string) *string {
	checkNotPaused()
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

// Withdraws BTC from the caller's own balance to a Bitcoin address.
// The `from` field is ignored — unmaps always draw from the caller's balance.
//
//go:wasmexport unmap
func Unmap(tx *string) *string {
	var unmapInstructions mapping.TransferParams
	err := tinyjson.Unmarshal([]byte(*tx), &unmapInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	// Enforce: unmap always uses caller as source
	unmapInstructions.From = ""

	doUnmap(&unmapInstructions)
	return mapping.StrPtr("0")
}

// Withdraws BTC from a third-party account that has approved the caller.
// Requires the `from` account to have set an allowance for the caller via `approve`.
//
//go:wasmexport unmapFrom
func UnmapFrom(tx *string) *string {
	var unmapInstructions mapping.TransferParams
	err := tinyjson.Unmarshal([]byte(*tx), &unmapInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	doUnmap(&unmapInstructions)
	return mapping.StrPtr("0")
}

func doUnmap(instructions *mapping.TransferParams) {
	checkNotPaused()
	if len(instructions.To) < 26 {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, "invalid destination address ["+instructions.To+"]"),
		)
	}

	publicKeys, err := loadPublicKeys()
	if err != nil {
		ce.CustomAbort(err)
	}

	contractState, err := mapping.IntializeContractState(publicKeys, NetworkMode)
	if err != nil {
		ce.CustomAbort(ce.Prepend(err, "error initializing contract state"))
	}

	err = contractState.HandleUnmap(instructions)
	if err != nil {
		ce.CustomAbort(err)
	}
	err = contractState.SaveToState()
	if err != nil {
		ce.CustomAbort(err)
	}
}

// Transfers funds from the Caller (immediate caller of the contract).
// The `from` field is ignored — transfers always draw from the caller's balance.
//
//go:wasmexport transfer
func Transfer(tx *string) *string {
	checkNotPaused()
	var transferInstructions mapping.TransferParams
	err := tinyjson.Unmarshal([]byte(*tx), &transferInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	// Enforce: transfer always uses caller as source
	transferInstructions.From = ""

	err = mapping.HandleTransfer(&transferInstructions)
	if err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

// Draws funds from a third-party account that has approved the caller.
// Requires the `from` account to have set an allowance for the caller via `approve`.
//
//go:wasmexport transferFrom
func TransferFrom(tx *string) *string {
	checkNotPaused()
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
	checkNotPaused()
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
	checkNotPaused()
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
	checkNotPaused()
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

// Confirms a pending spend transaction by verifying its Merkle inclusion proof,
// then promoting the unconfirmed change UTXOs at the specified output indices
// to the confirmed pool.
//
// mapPage accepts one page of a paginated `map` submission. When the
// submission completes (last page arrives), the assembled MapParams bytes are
// unmarshalled and handed to the regular HandleMap path. Duplicate pages are
// idempotent no-ops. See contract/mapping/pagination.go for full semantics.
//
//go:wasmexport mapPage
func MapPage(input *string) *string {
	checkNotPaused()
	var page mapping.MapPageParams
	err := tinyjson.Unmarshal([]byte(*input), &page)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput))
	}
	sender := sdk.GetEnv().Sender.Address.String()
	if sender == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "sender address required"))
	}
	txidBytes, err := hex.DecodeString(page.TxId)
	if err != nil || len(txidBytes) != 32 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "tx_id must be 64-char hex"))
	}
	var txid [32]byte
	copy(txid[:], txidBytes)

	assembled, err := mapping.SubmitPage(
		mapping.SdkPageStore{},
		mapping.PagePayloadMap,
		sender,
		txid,
		page.Vout,
		page.BlockHeight,
		page.PageIdx,
		page.TotalPages,
		[]byte(page.Payload),
	)
	if err != nil {
		ce.CustomAbort(err)
	}

	if assembled == nil {
		return mapping.StrPtr("0")
	}

	var mapInstructions mapping.MapParams
	err = tinyjson.Unmarshal(assembled, &mapInstructions)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput))
	}
	if mapInstructions.TxData == nil || mapInstructions.TxData.RawTxHex == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "tx_data.raw_tx_hex required"))
	}
	if mapInstructions.TxData.BlockHeight != page.BlockHeight {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "tx_data.block_height must match envelope block_height"))
	}
	txidFromPayload, err := txidFromRawTxHex(mapInstructions.TxData.RawTxHex)
	if err != nil {
		ce.CustomAbort(err)
	}
	if txidFromPayload != page.TxId {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "tx_data.raw_tx_hex txid must match envelope tx_id"))
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

//go:wasmexport confirmSpend
func ConfirmSpend(input *string) *string {
	checkNotPaused()
	var params mapping.ConfirmSpendParams
	err := tinyjson.Unmarshal([]byte(*input), &params)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput))
	}
	if params.TxData == nil || params.TxData.RawTxHex == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "tx_data.raw_tx_hex required"))
	}

	publicKeys, err := loadPublicKeys()
	if err != nil {
		ce.CustomAbort(err)
	}

	contractState, err := mapping.IntializeContractState(publicKeys, NetworkMode)
	if err != nil {
		ce.CustomAbort(err)
	}

	err = contractState.HandleConfirmSpend(params.TxData, params.Indices)
	if err != nil {
		ce.CustomAbort(err)
	}

	err = contractState.SaveToState()
	if err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

// Pauses all token operations (map, unmap, transfer, approve, confirmSpend).
// Admin/owner operations remain available while paused.
//
//go:wasmexport pause
func Pause(_ *string) *string {
	checkOwner()
	sdk.StateSetObject(constants.PausedKey, "1")
	return mapping.StrPtr("contract paused")
}

// Resumes all token operations after a pause.
//
//go:wasmexport unpause
func Unpause(_ *string) *string {
	checkOwner()
	sdk.StateDeleteObject(constants.PausedKey)
	return mapping.StrPtr("contract unpaused")
}

//go:wasmexport migrate
func Migrate(_ *string) *string {
	checkOwner()

	versionPtr := sdk.StateGetObject(constants.MigrateVersionKey)
	version := ""
	if versionPtr != nil {
		version = *versionPtr
	}

	// --- v1: migrate UTXO registry from 9-byte (uint8 ID + int64) to 8-byte
	// (uint16 ID + uint48) entries, and counter from 2 bytes to 4 bytes.
	// Old confirmed pool: 64–255 → new: 1024–65535 (offset +960).
	// Old unconfirmed pool: 0–63 → unchanged (0–1023 range, same IDs).
	// Individual UTXO blobs (u-<id>) are re-keyed to match the new hex IDs.
	if version < "1" {
		// Read old-format registry (9 bytes/entry: 1-byte ID + 8-byte amount BE)
		regRaw := sdk.StateGetObject(constants.UtxoRegistryKey)
		if regRaw != nil && len(*regRaw) > 0 {
			oldData := []byte(*regRaw)
			if len(oldData)%9 == 0 {
				entryCount := len(oldData) / 9
				newRegistry := make(mapping.UtxoRegistry, entryCount)
				for i := 0; i < entryCount; i++ {
					oldId := uint16(oldData[i*9])
					amount := int64(uint64(oldData[i*9+1])<<56 | uint64(oldData[i*9+2])<<48 |
						uint64(oldData[i*9+3])<<40 | uint64(oldData[i*9+4])<<32 |
						uint64(oldData[i*9+5])<<24 | uint64(oldData[i*9+6])<<16 |
						uint64(oldData[i*9+7])<<8 | uint64(oldData[i*9+8]))

					// Map old ID to new ID
					newId := oldId
					if oldId >= constants.OldUtxoConfirmedPoolStart {
						newId = oldId - constants.OldUtxoConfirmedPoolStart + constants.UtxoConfirmedPoolStart
					}
					newRegistry[i] = mapping.UtxoRegistryEntry{Id: newId, Amount: amount}

					// Re-key the UTXO blob: copy from old key to new key, delete old
					oldKey := constants.UtxoPrefix + strconv.FormatUint(uint64(oldId), 16)
					newKey := constants.UtxoPrefix + strconv.FormatUint(uint64(newId), 16)
					if oldKey != newKey {
						blob := sdk.StateGetObject(oldKey)
						if blob != nil && *blob != "" {
							sdk.StateSetObject(newKey, *blob)
							sdk.StateDeleteObject(oldKey)
						}
					}
				}
				// Write new-format registry (8 bytes/entry)
				sdk.StateSetObject(constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(newRegistry)))
			}
		}

		// Migrate counter from 2 bytes [uint8, uint8] to 4 bytes [uint16 BE, uint16 BE]
		counterRaw := sdk.StateGetObject(constants.UtxoLastIdKey)
		if counterRaw != nil && len(*counterRaw) == 2 {
			oldBytes := []byte(*counterRaw)
			oldConfirmed := uint16(oldBytes[0])
			oldUnconfirmed := uint16(oldBytes[1])

			newConfirmed := oldConfirmed
			if oldConfirmed >= constants.OldUtxoConfirmedPoolStart {
				newConfirmed = oldConfirmed - constants.OldUtxoConfirmedPoolStart + constants.UtxoConfirmedPoolStart
			}

			var buf [4]byte
			buf[0] = byte(newConfirmed >> 8)
			buf[1] = byte(newConfirmed)
			buf[2] = byte(oldUnconfirmed >> 8)
			buf[3] = byte(oldUnconfirmed)
			sdk.StateSetObject(constants.UtxoLastIdKey, string(buf[:]))
		}

		sdk.StateSetObject(constants.MigrateVersionKey, "1")
		sdk.Log("migrate|v=1")
	}

	// --- future migrations go here ---

	result := "migrated to v" + *sdk.StateGetObject(constants.MigrateVersionKey)
	return &result
}

//go:wasmexport getInfo
func GetInfo(_ *string) *string {
	return mapping.StrPtr(`{"name":"Bitcoin","symbol":"BTC","decimals":"8"}`)
}

// confirmSpendPage accepts one page of a paginated `confirmSpend` submission.
// When the last outstanding page arrives, the assembled ConfirmSpendParams
// bytes are unmarshalled and handed to the regular HandleConfirmSpend path.
// Duplicate pages are idempotent no-ops.
//
//go:wasmexport confirmSpendPage
func ConfirmSpendPage(input *string) *string {
	checkNotPaused()
	var page mapping.ConfirmSpendPageParams
	err := tinyjson.Unmarshal([]byte(*input), &page)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput))
	}
	sender := sdk.GetEnv().Sender.Address.String()
	if sender == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "sender address required"))
	}
	txidBytes, err := hex.DecodeString(page.TxId)
	if err != nil || len(txidBytes) != 32 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "tx_id must be 64-char hex"))
	}
	var txid [32]byte
	copy(txid[:], txidBytes)

	assembled, err := mapping.SubmitPage(
		mapping.SdkPageStore{},
		mapping.PagePayloadConfirmSpend,
		sender,
		txid,
		page.Vout,
		page.BlockHeight,
		page.PageIdx,
		page.TotalPages,
		[]byte(page.Payload),
	)
	if err != nil {
		ce.CustomAbort(err)
	}

	if assembled == nil {
		return mapping.StrPtr("0")
	}

	var params mapping.ConfirmSpendParams
	err = tinyjson.Unmarshal(assembled, &params)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput))
	}
	if params.TxData == nil || params.TxData.RawTxHex == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "tx_data.raw_tx_hex required"))
	}
	if params.TxData.BlockHeight != page.BlockHeight {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "tx_data.block_height must match envelope block_height"))
	}
	txidFromPayload, err := txidFromRawTxHex(params.TxData.RawTxHex)
	if err != nil {
		ce.CustomAbort(err)
	}
	if txidFromPayload != page.TxId {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "tx_data.raw_tx_hex txid must match envelope tx_id"))
	}

	publicKeys, err := loadPublicKeys()
	if err != nil {
		ce.CustomAbort(err)
	}

	contractState, err := mapping.IntializeContractState(publicKeys, NetworkMode)
	if err != nil {
		ce.CustomAbort(err)
	}

	err = contractState.HandleConfirmSpend(params.TxData, params.Indices)
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

func txidFromRawTxHex(rawTxHex string) (string, error) {
	rawTx, err := hex.DecodeString(rawTxHex)
	if err != nil {
		return "", ce.NewContractError(ce.ErrInvalidHex, "error decoding raw transaction hex")
	}
	var msgTx wire.MsgTx
	if err := msgTx.Deserialize(bytes.NewReader(rawTx)); err != nil {
		return "", ce.NewContractError(ce.ErrInput, "could not deserialize transaction")
	}
	return msgTx.TxID(), nil
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

//go:wasmexport createKey
func CreateKey(_ *string) *string {
	// leave this as owner always
	if sdk.GetEnv().Caller.String() != *sdk.GetEnvKey("contract.owner") {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "action must be performed by the contract owner"),
		)
	}

	keyId := constants.TssKeyName
	sdk.TssCreateKey(keyId, "ecdsa", 365)
	return mapping.StrPtr("key created, id: " + keyId)
}

//go:wasmexport renewKey
func RenewKey(_ *string) *string {
	// leave this as owner always
	if sdk.GetEnv().Caller.String() != *sdk.GetEnvKey("contract.owner") {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "action must be performed by the contract owner"),
		)
	}

	keyId := constants.TssKeyName
	sdk.TssRenewKey(keyId, 365)
	return mapping.StrPtr("key \"" + keyId + "\" renewed")
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
