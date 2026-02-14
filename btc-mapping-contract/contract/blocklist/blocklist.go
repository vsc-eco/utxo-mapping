package blocklist

import (
	"btc-mapping-contract/sdk"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	ce "btc-mapping-contract/contract/contracterrors"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/wire"
)

type BlockHeaderBytes [80]byte

//tinyjson:json
type AddBlocksInput struct {
	Blocks    string
	LatestFee int64
}

//tinyjson:json
type BlockSeedInput struct {
	BlockHeader string
	BlockHeight uint32
}

const BlockPrefix = "block/"
const lastHeightKey = "last_block_height"

var ErrorLastHeightDNE = errors.New("last height does not exist")

var ErrorSequenceIncorrect = errors.New("block sequence incorrect")

func LastHeightFromState() (uint32, error) {
	lastHeightString := sdk.StateGetObject(lastHeightKey)
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
	sdk.StateSetObject(lastHeightKey, strconv.FormatUint(uint64(lastHeight), 10))
}

func DivideHeaderList(blocksHex *string) ([]BlockHeaderBytes, error) {
	blockBytes, err := hex.DecodeString(*blocksHex)
	if err != nil {
		return nil, ce.WrapContractError(ce.ErrInvalidHex, err)
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

func HandleAddBlocks(rawHeaders []BlockHeaderBytes) (uint32, uint32, error) {
	lastHeight, err := LastHeightFromState()
	initialLastHeight := lastHeight
	if err != nil {
		return 0, 0, ce.WrapContractError(ce.ErrStateAccess, err)
	}
	lastBlockHex := sdk.StateGetObject(BlockPrefix + fmt.Sprintf("%d", lastHeight))
	lastBlockBytes, err := hex.DecodeString(*lastBlockHex)
	if err != nil {
		return 0, 0, ce.WrapContractError(ce.ErrInvalidHex, err)
	}
	var lastBlockHeader wire.BlockHeader
	err = lastBlockHeader.BtcDecode(bytes.NewReader(lastBlockBytes[:]), wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		return 0, 0, ce.NewContractError(ce.ErrInput, "error decoding block header: "+err.Error())
	}
	for _, headerBytes := range rawHeaders {
		var blockHeader wire.BlockHeader
		err = blockHeader.BtcDecode(bytes.NewReader(headerBytes[:]), wire.ProtocolVersion, wire.LatestEncoding)
		if err != nil {
			return 0, 0, ce.NewContractError(ce.ErrInput, "error decoding block header: "+err.Error())
		}

		lastBlockHash := lastBlockHeader.BlockHash()
		if !blockHeader.PrevBlock.IsEqual(&lastBlockHash) {
			return 0, 0, ErrorSequenceIncorrect
		}
		blockHeight := lastHeight + 1

		sdk.StateSetObject(BlockPrefix+fmt.Sprintf("%d", blockHeight), hex.EncodeToString(headerBytes[:]))
		lastHeight = blockHeight
		lastBlockHeader = blockHeader
	}
	return lastHeight, lastHeight - initialLastHeight, nil
}

func HandleSeedBlocks(seedInput *string, allowReseed bool) (uint32, error) {
	lastHeight, err := LastHeightFromState()
	if err != nil {
		if err != ErrorLastHeightDNE {
			return 0, err
		}
	} else if !allowReseed {
		return 0, ce.NewContractError(ce.ErrInitialization, "blocks already seeded last height "+strconv.FormatUint(uint64(lastHeight), 10))
	}

	var blockSeedData BlockSeedInput
	err = tinyjson.Unmarshal([]byte(*seedInput), &blockSeedData)
	if err != nil {
		return 0, ce.WrapContractError(ce.ErrJson, err)
	}

	if lastHeight == 0 || lastHeight < blockSeedData.BlockHeight {
		sdk.StateSetObject(BlockPrefix+fmt.Sprintf("%d", blockSeedData.BlockHeight), blockSeedData.BlockHeader)
		sdk.StateSetObject(lastHeightKey, fmt.Sprintf("%d", blockSeedData.BlockHeight))
		return blockSeedData.BlockHeight, nil
	}

	return 0, ce.NewContractError(
		ce.ErrInput,
		fmt.Sprintf("last height >= input block height. last height: %d", lastHeight),
	)
}
