package blocklist

import (
	"btc-mapping-contract/sdk"
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"strconv"

	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

type BlockHeaderBytes [80]byte

//tinyjson:json
type AddBlocksParams struct {
	Blocks    string
	LatestFee int64
}

//tinyjson:json
type SeedBlocksParams struct {
	BlockHeader string `json:"block_header"`
	BlockHeight uint32 `json:"block_height"`
}

var ErrorLastHeightDNE = errors.New("last height does not exist")

func LastHeightFromState() (uint32, error) {
	lastHeightString := sdk.StateGetObject(constants.LastHeightKey)
	if *lastHeightString == "" {
		return 0, ErrorLastHeightDNE
	}
	lastHeight, err := strconv.ParseUint(*lastHeightString, 10, 32)
	if err != nil {
		return 0, err
	}
	lastHeight32 := uint32(lastHeight)
	return lastHeight32, nil
}

func LastHeightToState(lastHeight uint32) {
	sdk.StateSetObject(constants.LastHeightKey, strconv.FormatUint(uint64(lastHeight), 10))
}

// seedHeightFromState returns the original seed height, or 0 if not set.
func seedHeightFromState() uint32 {
	s := sdk.StateGetObject(constants.SeedHeightKey)
	if s == nil || *s == "" {
		return 0
	}
	h, err := strconv.ParseUint(*s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(h)
}

// pruneFloorFromState returns the lowest height that hasn't been pruned yet.
// This cursor avoids re-scanning already-pruned regions on each call.
func pruneFloorFromState() uint32 {
	s := sdk.StateGetObject(constants.PruneFloorKey)
	if s == nil || *s == "" {
		return 0
	}
	h, err := strconv.ParseUint(*s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(h)
}

func DivideHeaderList(blocksHex *string) ([]BlockHeaderBytes, error) {
	blockBytes, err := hex.DecodeString(*blocksHex)
	if err != nil {
		return nil, ce.WrapContractError(ce.ErrInvalidHex, err, "error decoding block headers hex")
	}
	if len(blockBytes)%80 != 0 {
		return nil, ce.NewContractError(ce.ErrInput, "incorrect block length")
	}

	blockHeaders := make([]BlockHeaderBytes, len(blockBytes)/80)
	for i := 0; i < len(blockBytes); i += 80 {
		blockHeaders[i/80] = [80]byte(blockBytes[i : i+80])
	}
	return blockHeaders, nil
}

func HandleAddBlocks(rawHeaders []BlockHeaderBytes, networkMode string) (uint32, error) {
	var networkParams *chaincfg.Params
	switch networkMode {
	case constants.Testnet3:
		networkParams = &chaincfg.TestNet3Params
	case constants.Testnet4:
		networkParams = &chaincfg.TestNet4Params
	case constants.Regtest:
		networkParams = &chaincfg.RegressionNetParams
	default:
		networkParams = &chaincfg.MainNetParams
	}

	lastHeight, err := LastHeightFromState()
	if err != nil {
		return 0, ce.WrapContractError(ce.ErrStateAccess, err, "error reading last block height")
	}

	// block headers stored as raw 80 bytes
	lastBlockRaw := sdk.StateGetObject(constants.BlockPrefix + strconv.FormatInt(int64(lastHeight), 10))
	if lastBlockRaw == nil || *lastBlockRaw == "" {
		return 0, ce.NewContractError(ce.ErrStateAccess, "no block header found at height "+strconv.FormatInt(int64(lastHeight), 10))
	}
	lastBlockBytes := []byte(*lastBlockRaw)
	var lastBlockHeader wire.BlockHeader
	err = lastBlockHeader.BtcDecode(bytes.NewReader(lastBlockBytes), wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		return 0, ce.NewContractError(ce.ErrInput, "error decoding block header: "+err.Error())
	}

	powLimit := networkParams.PowLimit

	for _, headerBytes := range rawHeaders {
		// won't happen for 130 years but just in case
		if lastHeight == math.MaxUint32 {
			return 0, ce.NewContractError(ce.ErrArithmetic, "bitcoin block height exceeds max possible")
		}
		blockHeight := lastHeight + 1

		var blockHeader wire.BlockHeader
		err = blockHeader.BtcDecode(bytes.NewReader(headerBytes[:]), wire.ProtocolVersion, wire.LatestEncoding)
		if err != nil {
			return 0, ce.NewContractError(ce.ErrInput, "error decoding block header: "+err.Error())
		}
		msgBlock := wire.MsgBlock{Header: blockHeader}
		if err := blockchain.CheckProofOfWork(btcutil.NewBlock(&msgBlock), powLimit); err != nil {
			return 0, ce.NewContractError(
				ce.ErrInput,
				"block "+strconv.FormatUint(uint64(blockHeight), 10)+" failed PoW check: "+err.Error(),
			)
		}

		lastBlockHash := lastBlockHeader.BlockHash()
		if !blockHeader.PrevBlock.IsEqual(&lastBlockHash) {
			return 0, ce.NewContractError(ce.ErrInput, "block sequence incorrect")
		}

		// store raw 80 bytes (not hex)
		sdk.StateSetObject(
			constants.BlockPrefix+strconv.FormatUint(uint64(blockHeight), 10),
			string(headerBytes[:]),
		)
		lastHeight = blockHeight
		lastBlockHeader = blockHeader
	}

	PruneOldHeaders(lastHeight)

	return lastHeight, nil
}

// PruneOldHeaders removes block headers beyond the retention window.
// Uses a floor cursor to avoid re-scanning already-pruned regions.
// Returns the number of headers pruned in this call.
func PruneOldHeaders(lastHeight uint32) int {
	retainFrom := int64(lastHeight) - int64(constants.MaxBlockRetention) + 1
	if retainFrom <= 0 {
		return 0
	}
	pruneFloor := pruneFloorFromState()
	if pruneFloor == 0 {
		pruneFloor = seedHeightFromState()
	}
	if pruneFloor == 0 || int64(pruneFloor) >= retainFrom {
		return 0
	}
	pruned := 0
	h := int64(pruneFloor)
	for ; h < retainFrom && pruned < constants.MaxPrunePerCall; h++ {
		key := constants.BlockPrefix + strconv.FormatInt(h, 10)
		existing := sdk.StateGetObject(key)
		if existing != nil && *existing != "" {
			sdk.StateDeleteObject(key)
			pruned++
		}
		// Also prune the observed tx list for this block height
		observedKey := constants.ObservedBlockPrefix + strconv.FormatInt(h, 10)
		sdk.StateDeleteObject(observedKey)
	}
	sdk.StateSetObject(constants.PruneFloorKey, strconv.FormatInt(h, 10))
	return pruned
}

// HandleReplaceBlock replaces the block at the current tip height with a
// corrected header. This is used to fix a stale/orphaned tip that prevents
// new blocks from being appended. The replacement must pass PoW and chain
// correctly to the block at height-1.
func HandleReplaceBlock(rawHeader BlockHeaderBytes, networkMode string) (uint32, error) {
	var networkParams *chaincfg.Params
	switch networkMode {
	case constants.Testnet3:
		networkParams = &chaincfg.TestNet3Params
	case constants.Testnet4:
		networkParams = &chaincfg.TestNet4Params
	case constants.Regtest:
		networkParams = &chaincfg.RegressionNetParams
	default:
		networkParams = &chaincfg.MainNetParams
	}

	lastHeight, err := LastHeightFromState()
	if err != nil {
		return 0, ce.WrapContractError(ce.ErrStateAccess, err, "error reading last block height")
	}
	if lastHeight == 0 {
		return 0, ce.NewContractError(ce.ErrInput, "cannot replace block at height 0 (no previous block to chain to)")
	}

	// decode the replacement header
	var newHeader wire.BlockHeader
	err = newHeader.BtcDecode(bytes.NewReader(rawHeader[:]), wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		return 0, ce.NewContractError(ce.ErrInput, "error decoding replacement header: "+err.Error())
	}

	// PoW check
	msgBlock := wire.MsgBlock{Header: newHeader}
	if err := blockchain.CheckProofOfWork(btcutil.NewBlock(&msgBlock), networkParams.PowLimit); err != nil {
		return 0, ce.NewContractError(ce.ErrInput, "replacement block failed PoW check: "+err.Error())
	}

	// validate that the replacement chains to height-1
	prevHeight := lastHeight - 1
	prevBlockRaw := sdk.StateGetObject(constants.BlockPrefix + strconv.FormatUint(uint64(prevHeight), 10))
	if prevBlockRaw == nil || *prevBlockRaw == "" {
		return 0, ce.NewContractError(ce.ErrStateAccess, "no block found at height "+strconv.FormatUint(uint64(prevHeight), 10))
	}
	var prevHeader wire.BlockHeader
	err = prevHeader.BtcDecode(bytes.NewReader([]byte(*prevBlockRaw)), wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		return 0, ce.NewContractError(ce.ErrStateAccess, "error decoding block at height "+strconv.FormatUint(uint64(prevHeight), 10))
	}
	prevHash := prevHeader.BlockHash()
	if !newHeader.PrevBlock.IsEqual(&prevHash) {
		return 0, ce.NewContractError(ce.ErrInput, "replacement block does not chain to block at height "+strconv.FormatUint(uint64(prevHeight), 10))
	}

	// overwrite the tip
	sdk.StateSetObject(
		constants.BlockPrefix+strconv.FormatUint(uint64(lastHeight), 10),
		string(rawHeader[:]),
	)

	return lastHeight, nil
}

// HandleReplaceBlocks replaces the top N blocks (from the tip downward) with
// corrected headers. This handles multi-block reorgs where replaceBlock (single)
// would fail because the block below the tip is also orphaned.
//
// The headers slice must be ordered lowest-to-highest (oldest first), matching
// addBlocks ordering. The first header replaces lastHeight-(N-1), the last
// header replaces lastHeight. All must pass PoW and chain correctly.
func HandleReplaceBlocks(rawHeaders []BlockHeaderBytes, networkMode string) (uint32, error) {
	if len(rawHeaders) == 0 {
		return 0, ce.NewContractError(ce.ErrInput, "no replacement headers provided")
	}

	// Single header: delegate to the original single-block handler.
	if len(rawHeaders) == 1 {
		return HandleReplaceBlock(rawHeaders[0], networkMode)
	}

	// On mainnet, cap replacement depth to 2 blocks.
	if !constants.IsTestnet(networkMode) && len(rawHeaders) > 2 {
		return 0, ce.NewContractError(ce.ErrInput, "mainnet replacement limited to 2 blocks")
	}

	var networkParams *chaincfg.Params
	switch networkMode {
	case constants.Testnet3:
		networkParams = &chaincfg.TestNet3Params
	case constants.Testnet4:
		networkParams = &chaincfg.TestNet4Params
	case constants.Regtest:
		networkParams = &chaincfg.RegressionNetParams
	default:
		networkParams = &chaincfg.MainNetParams
	}

	lastHeight, err := LastHeightFromState()
	if err != nil {
		return 0, ce.WrapContractError(ce.ErrStateAccess, err, "error reading last block height")
	}

	n := uint32(len(rawHeaders))
	if n > lastHeight {
		return 0, ce.NewContractError(ce.ErrInput, "more replacement headers than stored blocks")
	}

	// The anchor is the block just below the reorg range that must remain valid.
	anchorHeight := lastHeight - n
	anchorBlockRaw := sdk.StateGetObject(constants.BlockPrefix + strconv.FormatUint(uint64(anchorHeight), 10))
	if anchorBlockRaw == nil || *anchorBlockRaw == "" {
		return 0, ce.NewContractError(ce.ErrStateAccess, "no block found at anchor height "+strconv.FormatUint(uint64(anchorHeight), 10))
	}
	var anchorHeader wire.BlockHeader
	err = anchorHeader.BtcDecode(bytes.NewReader([]byte(*anchorBlockRaw)), wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		return 0, ce.NewContractError(ce.ErrStateAccess, "error decoding block at anchor height "+strconv.FormatUint(uint64(anchorHeight), 10))
	}
	prevHash := anchorHeader.BlockHash()

	// Validate and overwrite each header in order.
	powLimit := networkParams.PowLimit
	for i, headerBytes := range rawHeaders {
		height := anchorHeight + 1 + uint32(i)

		var hdr wire.BlockHeader
		err = hdr.BtcDecode(bytes.NewReader(headerBytes[:]), wire.ProtocolVersion, wire.LatestEncoding)
		if err != nil {
			return 0, ce.NewContractError(ce.ErrInput, "error decoding replacement header at index "+strconv.Itoa(i))
		}

		msgBlock := wire.MsgBlock{Header: hdr}
		if err := blockchain.CheckProofOfWork(btcutil.NewBlock(&msgBlock), powLimit); err != nil {
			return 0, ce.NewContractError(ce.ErrInput,
				"replacement block at height "+strconv.FormatUint(uint64(height), 10)+" failed PoW check: "+err.Error())
		}

		if !hdr.PrevBlock.IsEqual(&prevHash) {
			return 0, ce.NewContractError(ce.ErrInput,
				"replacement block at height "+strconv.FormatUint(uint64(height), 10)+" does not chain to block at height "+strconv.FormatUint(uint64(height-1), 10))
		}

		sdk.StateSetObject(
			constants.BlockPrefix+strconv.FormatUint(uint64(height), 10),
			string(headerBytes[:]),
		)
		prevHash = hdr.BlockHash()
	}

	return lastHeight, nil
}

func HandleSeedBlocks(seedParams SeedBlocksParams, allowReseed bool) (uint32, error) {
	lastHeight, err := LastHeightFromState()
	if err != nil {
		if err != ErrorLastHeightDNE {
			return 0, err
		}
	} else if !allowReseed {
		return 0, ce.NewContractError(ce.ErrInitialization, "blocks already seeded last height "+strconv.FormatUint(uint64(lastHeight), 10))
	}

	if lastHeight == 0 || lastHeight < seedParams.BlockHeight {
		// decode hex input → store raw bytes
		headerBytes, err := hex.DecodeString(seedParams.BlockHeader)
		if err != nil {
			return 0, ce.WrapContractError(ce.ErrInvalidHex, err, "invalid block header hex")
		}
		sdk.StateSetObject(
			constants.BlockPrefix+strconv.FormatInt(int64(seedParams.BlockHeight), 10),
			string(headerBytes),
		)
		sdk.StateSetObject(constants.LastHeightKey, strconv.FormatInt(int64(seedParams.BlockHeight), 10))
		sdk.StateSetObject(constants.SeedHeightKey, strconv.FormatInt(int64(seedParams.BlockHeight), 10))
		return seedParams.BlockHeight, nil
	}

	return 0, ce.NewContractError(
		ce.ErrInput,
		"last height >= input block height. last height: "+strconv.FormatUint(uint64(lastHeight), 10),
	)
}
