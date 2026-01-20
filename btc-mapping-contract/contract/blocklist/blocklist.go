package blocklist

import (
	"btc-mapping-contract/sdk"
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"

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

var ErrorLastHeightDNE = fmt.Errorf("last height does not exist")

var ErrorSequenceIncorrect = fmt.Errorf("block sequence incorrect")

func LastHeightFromState() (*uint32, error) {
	lastHeightString := sdk.StateGetObject(lastHeightKey)
	if *lastHeightString == "" {
		return nil, ErrorLastHeightDNE
	}
	lastHeight, err := strconv.ParseUint(*lastHeightString, 10, 32)
	if err != nil {
		return nil, err
	}
	lastHeight32 := uint32(lastHeight)
	return &lastHeight32, nil
}

func LastHeightToState(lastHeight *uint32) {
	sdk.StateSetObject(lastHeightKey, fmt.Sprintf("%d", *lastHeight))
}

func DivideHeaderList(blocksHex *string) ([]BlockHeaderBytes, error) {
	blockBytes, err := hex.DecodeString(*blocksHex)
	if err != nil {
		return nil, err
	}
	if len(blockBytes)%80 != 0 {
		return nil, fmt.Errorf("incorrect block length")
	}

	blockHeaders := make([]BlockHeaderBytes, len(blockBytes)/80)
	for i := 0; i < len(blockBytes); i += 80 {
		blockHeaders[i/80] = [80]byte(blockBytes[i : i+80])
	}
	return blockHeaders, nil
}

func HandleAddBlocks(rawHeaders []BlockHeaderBytes, lastHeight *uint32) error {
	lastBlockHex := sdk.StateGetObject(BlockPrefix + fmt.Sprintf("%d", *lastHeight))
	lastBlockBytes, err := hex.DecodeString(*lastBlockHex)
	if err != nil {
		return err
	}
	var lastBlockHeader wire.BlockHeader
	err = lastBlockHeader.BtcDecode(bytes.NewReader(lastBlockBytes[:]), wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		return fmt.Errorf("error decoding block header: %w", err)
	}
	for _, headerBytes := range rawHeaders {
		var blockHeader wire.BlockHeader
		err = blockHeader.BtcDecode(bytes.NewReader(headerBytes[:]), wire.ProtocolVersion, wire.LatestEncoding)
		if err != nil {
			return fmt.Errorf("error decoding block header: %w", err)
		}

		lastBlockHash := lastBlockHeader.BlockHash()
		if !blockHeader.PrevBlock.IsEqual(&lastBlockHash) {
			return ErrorSequenceIncorrect
		}
		blockHeight := *lastHeight + 1

		sdk.StateSetObject(BlockPrefix+fmt.Sprintf("%d", blockHeight), hex.EncodeToString(headerBytes[:]))
		*lastHeight = blockHeight
		lastBlockHeader = blockHeader
	}
	return nil
}

func HandleSeedBlocks(seedInput *string, allowReseed bool) (uint32, error) {
	lastHeight, err := LastHeightFromState()
	if err != nil {
		if err != ErrorLastHeightDNE {
			return 0, err
		}
	} else if !allowReseed {
		return 0, fmt.Errorf("blocks already seeded, last height: %d", *lastHeight)
	}

	var blockSeedData BlockSeedInput
	err = tinyjson.Unmarshal([]byte(*seedInput), &blockSeedData)
	if err != nil {
		return 0, err
	}

	if lastHeight == nil || *lastHeight < blockSeedData.BlockHeight {
		sdk.StateSetObject(BlockPrefix+fmt.Sprintf("%d", blockSeedData.BlockHeight), blockSeedData.BlockHeader)
		sdk.StateSetObject(lastHeightKey, fmt.Sprintf("%d", blockSeedData.BlockHeight))
		return blockSeedData.BlockHeight, nil
	}

	return 0, fmt.Errorf("last height >= input block height. last height; %d", *lastHeight)
}
