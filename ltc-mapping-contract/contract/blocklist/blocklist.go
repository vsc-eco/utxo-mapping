package blocklist

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"strconv"

	"ltc-mapping-contract/contract/constants"
	ce "ltc-mapping-contract/contract/contracterrors"
	"ltc-mapping-contract/sdk"

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

// LastHeightKey is an alias for constants.LastHeightKey for backwards
// compatibility with test code that references blocklist.LastHeightKey.
const LastHeightKey = constants.LastHeightKey

var ErrorLastHeightDNE = errors.New("last height does not exist")

var ErrorSequenceIncorrect = errors.New("block sequence incorrect")

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

// HandleAddBlocks validates and stores LTC block headers.
// LTC uses Scrypt for PoW which is not available in btcsuite, so we skip PoW
// validation and only verify header format and prev-block chain linkage.
// The oracle consensus (2/3+ BLS signatures) provides the trust guarantee.
func HandleAddBlocks(rawHeaders []BlockHeaderBytes, networkMode string) (uint32, uint32, error) {
	_ = networkMode // LTC testnet/mainnet use same 80-byte header format

	lastHeight, err := LastHeightFromState()
	if err != nil {
		return 0, 0, ce.WrapContractError(ce.ErrStateAccess, err, "error reading last block height")
	}
	initialLastHeight := lastHeight

	// block headers stored as raw 80 bytes
	lastBlockRaw := sdk.StateGetObject(constants.BlockPrefix + strconv.FormatInt(int64(lastHeight), 10))
	lastBlockBytes := []byte(*lastBlockRaw)
	var lastBlockHeader wire.BlockHeader
	err = lastBlockHeader.BtcDecode(bytes.NewReader(lastBlockBytes), wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		return 0, 0, ce.NewContractError(ce.ErrInput, "error decoding block header: "+err.Error())
	}

	for _, headerBytes := range rawHeaders {
		if lastHeight == math.MaxUint32 {
			return 0, 0, ce.NewContractError(ce.ErrArithmetic, "block height exceeds max possible")
		}
		blockHeight := lastHeight + 1

		var blockHeader wire.BlockHeader
		err = blockHeader.BtcDecode(bytes.NewReader(headerBytes[:]), wire.ProtocolVersion, wire.LatestEncoding)
		if err != nil {
			return 0, 0, ce.NewContractError(ce.ErrInput, "error decoding block header: "+err.Error())
		}

		lastBlockHash := lastBlockHeader.BlockHash()
		if !blockHeader.PrevBlock.IsEqual(&lastBlockHash) {
			return 0, 0, ErrorSequenceIncorrect
		}

		// store raw 80 bytes (not hex)
		sdk.StateSetObject(
			constants.BlockPrefix+strconv.FormatUint(uint64(blockHeight), 10),
			string(headerBytes[:]),
		)
		lastHeight = blockHeight
		lastBlockHeader = blockHeader
	}
	return lastHeight, lastHeight - initialLastHeight, nil
}

// HandleReplaceBlock replaces the block at the current tip height with a
// corrected header. This is used to fix a stale/orphaned tip that prevents
// new blocks from being appended. The replacement must chain correctly to
// the block at height-1. PoW is not checked (LTC uses Scrypt).
func HandleReplaceBlock(rawHeader BlockHeaderBytes, networkMode string) (uint32, error) {
	_ = networkMode

	lastHeight, err := LastHeightFromState()
	if err != nil {
		return 0, ce.WrapContractError(ce.ErrStateAccess, err, "error reading last block height")
	}

	// decode the replacement header
	var newHeader wire.BlockHeader
	err = newHeader.BtcDecode(bytes.NewReader(rawHeader[:]), wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		return 0, ce.NewContractError(ce.ErrInput, "error decoding replacement header: "+err.Error())
	}

	// validate that the replacement chains to height-1
	prevHeight := lastHeight - 1
	prevBlockRaw := sdk.StateGetObject(constants.BlockPrefix + strconv.FormatUint(uint64(prevHeight), 10))
	if *prevBlockRaw == "" {
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
		return seedParams.BlockHeight, nil
	}

	return 0, ce.NewContractError(
		ce.ErrInput,
		"last height >= input block height. last height: "+strconv.FormatUint(uint64(lastHeight), 10),
	)
}
