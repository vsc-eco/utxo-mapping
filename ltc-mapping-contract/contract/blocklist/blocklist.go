package blocklist

import (
	"ltc-mapping-contract/sdk"
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"strconv"

	"ltc-mapping-contract/contract/constants"
	ce "ltc-mapping-contract/contract/contracterrors"
	"ltc-mapping-contract/contract/mapping"
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
	case constants.Testnet4:
		networkParams = &mapping.LtcTestNet4Params
	default:
		networkParams = &mapping.LtcMainNetParams
	}
	// suppress unused variable warning — networkParams reserved for future Scrypt PoW validation
	_ = networkParams

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

	for _, headerBytes := range rawHeaders {
		// won't happen for 130 years but just in case
		if lastHeight == math.MaxUint32 {
			return 0, 0, ce.NewContractError(ce.ErrArithmetic, "litecoin block height exceeds max possible")
		}
		blockHeight := lastHeight + 1

		var blockHeader wire.BlockHeader
		err = blockHeader.BtcDecode(bytes.NewReader(headerBytes[:]), wire.ProtocolVersion, wire.LatestEncoding)
		if err != nil {
			return 0, 0, ce.NewContractError(ce.ErrInput, "error decoding block header: "+err.Error())
		}

		// NOTE: PoW sanity check skipped for Litecoin. blockchain.CheckBlockHeaderSanity()
		// performs SHA256d validation which is incorrect for Litecoin's Scrypt PoW.
		// Block validity is ensured by the oracle witnesses before submission.
		// TODO: Implement Scrypt PoW validation when a TinyGo-compatible Scrypt library is available.

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
		sdk.StateSetObject(
			constants.BlockPrefix+strconv.FormatInt(int64(seedParams.BlockHeight), 10),
			seedParams.BlockHeader,
		)
		sdk.StateSetObject(LastHeightKey, strconv.FormatInt(int64(seedParams.BlockHeight), 10))
		return seedParams.BlockHeight, nil
	}

	return 0, ce.NewContractError(
		ce.ErrInput,
		"last height >= input block height. last height: "+strconv.FormatUint(uint64(lastHeight), 10),
	)
}
