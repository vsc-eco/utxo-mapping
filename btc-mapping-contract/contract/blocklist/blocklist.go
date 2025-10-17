package blocklist

import (
	"bytes"
	"contract-template/sdk"
	"encoding/hex"
	"fmt"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/wire"
)

type BlockHeaderBytes [80]byte

//tinyjson:json
type BlockData struct {
	BlockMap   map[uint32]string // maps block heights to hex representation of 80-byte block headers
	LastHeight uint32
}

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

const blockDataKey = "blocklist"

func BlockDataFromState() *BlockData {
	jsonData := sdk.StateGetObject(blockDataKey)
	var blockData BlockData
	tinyjson.Unmarshal([]byte(*jsonData), &blockData)
	return &blockData
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

func (bd *BlockData) SaveToState() error {
	jsonBytes, err := tinyjson.Marshal(bd)
	if err != nil {
		return err
	}
	sdk.StateSetObject(blockDataKey, string(jsonBytes))
	return nil
}

func (bd *BlockData) HandleAddBlocks(rawHeaders []BlockHeaderBytes) error {
	lastBlockHex := bd.BlockMap[bd.LastHeight]
	lastBlockBytes, err := hex.DecodeString(lastBlockHex)
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
		blockHeight := bd.LastHeight + 1
		if _, ok := bd.BlockMap[blockHeight]; ok {
			return fmt.Errorf("block already present")
		}
		bd.BlockMap[blockHeight] = hex.EncodeToString(headerBytes[:])
		bd.LastHeight = blockHeight
		lastBlockHeader = blockHeader
	}
	return nil
}

func (bd *BlockData) HandleSeedBlocks(seedInput *string) error {
	var blockSeedData BlockSeedInput
	err := tinyjson.Unmarshal([]byte(*seedInput), &blockSeedData)
	if err != nil {
		return err
	}

	if bd.BlockMap == nil {
		bd.BlockMap = make(map[uint32]string, 1)
	}
	bd.BlockMap[blockSeedData.BlockHeight] = blockSeedData.BlockHeader
	bd.LastHeight = blockSeedData.BlockHeight
	return nil
}
