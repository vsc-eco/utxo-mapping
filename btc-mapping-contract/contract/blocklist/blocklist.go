package blocklist

import (
	"bytes"
	"contract-template/sdk"
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
type AddBlockOutput struct {
	Success         bool
	Error           string
	LastBlockHeight uint32
}

//tinyjson:json
type BlockSeedInput struct {
	BlockHeader string
	BlockHeight uint32
}

const BlockPrefix = "block"
const lastHeightKey = "last_block_height"

var ErrorLastHeightDNE = fmt.Errorf("last height does not exist")

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
		sdk.Abort(err.Error())
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
		sdk.Abort(err.Error())
	}
	var lastBlockHeader wire.BlockHeader
	lastBlockHeader.BtcDecode(bytes.NewReader(lastBlockBytes[:]), wire.ProtocolVersion, wire.LatestEncoding)
	for _, headerBytes := range rawHeaders {
		var blockHeader wire.BlockHeader
		blockHeader.BtcDecode(bytes.NewReader(headerBytes[:]), wire.ProtocolVersion, wire.LatestEncoding)

		lastBlockHash := lastBlockHeader.BlockHash()
		if !blockHeader.PrevBlock.IsEqual(&lastBlockHash) {
			return fmt.Errorf("block sequence incorrect")
		}
		blockHeight := *lastHeight + 1

		sdk.StateSetObject(BlockPrefix+fmt.Sprintf("%d", blockHeight), hex.EncodeToString(headerBytes[:]))
		*lastHeight = blockHeight
		lastBlockHeader = blockHeader
	}
	return nil
}

func HandleSeedBlocks(seedInput *string) (uint32, error) {
	var blockSeedData BlockSeedInput
	err := tinyjson.Unmarshal([]byte(*seedInput), &blockSeedData)
	if err != nil {
		return 0, err
	}

	sdk.StateSetObject(BlockPrefix+fmt.Sprintf("%d", blockSeedData.BlockHeight), blockSeedData.BlockHeader)
	sdk.StateSetObject(lastHeightKey, fmt.Sprintf("%d", blockSeedData.BlockHeight))
	return blockSeedData.BlockHeight, nil
}
