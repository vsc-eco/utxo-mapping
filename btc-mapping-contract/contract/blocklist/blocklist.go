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

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
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

const LastHeightKey = "lsthgt"

var ErrorLastHeightDNE = errors.New("last height does not exist")

var ErrorSequenceIncorrect = errors.New("block sequence incorrect")

func LastHeightFromState() (uint32, error) {
	lastHeightString := sdk.StateGetObject(LastHeightKey)
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
	sdk.StateSetObject(LastHeightKey, strconv.FormatUint(uint64(lastHeight), 10))
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

func HandleAddBlocks(rawHeaders []BlockHeaderBytes, networkMode string) (uint32, uint32, error) {
	var networkParams *chaincfg.Params
	switch networkMode {
	case constants.Testnet3:
		networkParams = &chaincfg.TestNet3Params
	case constants.Testnet4:
		networkParams = &chaincfg.TestNet4Params
	default:
		networkParams = &chaincfg.MainNetParams
	}

	lastHeight, err := LastHeightFromState()
	if err != nil {
		return 0, 0, ce.WrapContractError(ce.ErrStateAccess, err)
	}
	initialLastHeight := lastHeight

	lastBlockHex := sdk.StateGetObject(constants.BlockPrefix + strconv.FormatInt(int64(lastHeight), 10))
	lastBlockBytes, err := hex.DecodeString(*lastBlockHex)
	if err != nil {
		return 0, 0, ce.WrapContractError(ce.ErrInvalidHex, err)
	}
	var lastBlockHeader wire.BlockHeader
	err = lastBlockHeader.BtcDecode(bytes.NewReader(lastBlockBytes[:]), wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		return 0, 0, ce.NewContractError(ce.ErrInput, "error decoding block header: "+err.Error())
	}

	timeSource := blockchain.NewMedianTime()
	timeSource.AddTimeSample("local", lastBlockHeader.Timestamp)
	powLimit := networkParams.PowLimit

	for _, headerBytes := range rawHeaders {
		// won't happen for 130 years but just in case
		if lastHeight == math.MaxUint32 {
			return 0, 0, ce.NewContractError(ce.ErrArithmetic, "bitcoin block height exceeds max possible")
		}
		blockHeight := lastHeight + 1

		var blockHeader wire.BlockHeader
		err = blockHeader.BtcDecode(bytes.NewReader(headerBytes[:]), wire.ProtocolVersion, wire.LatestEncoding)
		if err != nil {
			return 0, 0, ce.NewContractError(ce.ErrInput, "error decoding block header: "+err.Error())
		}
		if err := blockchain.CheckBlockHeaderSanity(&blockHeader, powLimit, timeSource, blockchain.BFNone); err != nil {
			return 0, 0, ce.NewContractError(
				ce.ErrInput,
				"block "+strconv.FormatUint(uint64(blockHeight), 10)+" failed sanity check: "+err.Error(),
			)
		}

		lastBlockHash := lastBlockHeader.BlockHash()
		if !blockHeader.PrevBlock.IsEqual(&lastBlockHash) {
			return 0, 0, ErrorSequenceIncorrect
		}

		sdk.StateSetObject(
			constants.BlockPrefix+strconv.FormatUint(uint64(blockHeight), 10),
			hex.EncodeToString(headerBytes[:]),
		)
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
		sdk.StateSetObject(
			constants.BlockPrefix+strconv.FormatInt(int64(blockSeedData.BlockHeight), 10),
			blockSeedData.BlockHeader,
		)
		sdk.StateSetObject(LastHeightKey, strconv.FormatInt(int64(blockSeedData.BlockHeight), 10))
		return blockSeedData.BlockHeight, nil
	}

	return 0, ce.NewContractError(
		ce.ErrInput,
		"last height >= input block height. last height: "+strconv.FormatUint(uint64(lastHeight), 10),
	)
}
