package blocklist

import (
	"doge-mapping-contract/sdk"
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"strconv"

	"doge-mapping-contract/contract/constants"
	ce "doge-mapping-contract/contract/contracterrors"

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

func HandleAddBlocks(rawHeaders []BlockHeaderBytes, networkMode string) (uint32, error) {
	var networkParams *chaincfg.Params
	switch networkMode {
	case constants.Testnet:
		networkParams = &chaincfg.TestNet3Params
	case constants.Regtest:
		networkParams = &chaincfg.RegressionNetParams
	default:
		networkParams = &chaincfg.MainNetParams
	}

	lastHeight, err := LastHeightFromState()
	if err != nil {
		return 0, ce.WrapContractError(ce.ErrStateAccess, err)
	}

	// block headers stored as raw 80 bytes
	lastBlockRaw := sdk.StateGetObject(constants.BlockPrefix + strconv.FormatInt(int64(lastHeight), 10))
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
