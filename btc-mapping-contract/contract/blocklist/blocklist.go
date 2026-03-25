package blocklist

import (
	"btc-mapping-contract/sdk"
	"bytes"
	"encoding/binary"
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

const blockSlotPayloadLen = 4 + 80 // LE uint32 height + raw header

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

func blockSlotKey(height uint32) string {
	mod := height % constants.BlockHeaderModulus
	return constants.BlockPrefix + strconv.FormatUint(uint64(mod), 10)
}

func legacyBlockKey(height uint32) string {
	return constants.BlockPrefix + strconv.FormatUint(uint64(height), 10)
}

// For heights 0-99, blockSlotKey(h) equals legacyBlockKey(h) (same state key).
// Production chains use tip heights in the millions, so this overlap is irrelevant.
// Reads still disambiguate: modulus values are blockSlotPayloadLen bytes (LE height + header);
// legacy values are exactly 80 raw header bytes (see GetBlockHeaderBytes).

func encodeBlockSlot(height uint32, raw [80]byte) string {
	var buf [blockSlotPayloadLen]byte
	binary.LittleEndian.PutUint32(buf[0:4], height)
	copy(buf[4:], raw[:])
	return string(buf[:])
}

// EncodeBlockSlot packs height + 80-byte header for contract state (tests / tooling).
func EncodeBlockSlot(height uint32, raw80 []byte) (string, error) {
	if len(raw80) != 80 {
		return "", ce.NewContractError(ce.ErrInput, "header must be 80 bytes")
	}
	var fixed [80]byte
	copy(fixed[:], raw80)
	return encodeBlockSlot(height, fixed), nil
}

// GetBlockHeaderBytes returns the raw 80-byte header at height, using the modulus
// ring buffer, with fallback to legacy per-height keys (pre-modulus deployments).
// When slot and legacy keys collide (heights 0-99), len 84 vs len 80 distinguishes formats.
func GetBlockHeaderBytes(height uint32) ([]byte, error) {
	slot := sdk.StateGetObject(blockSlotKey(height))
	if *slot != "" {
		b := []byte(*slot)
		if len(b) == blockSlotPayloadLen {
			got := binary.LittleEndian.Uint32(b[0:4])
			if uint32(got) == height {
				out := make([]byte, 80)
				copy(out, b[4:])
				return out, nil
			}
		}
	}
	legacy := sdk.StateGetObject(legacyBlockKey(height))
	if *legacy != "" && len(*legacy) == 80 {
		return []byte(*legacy), nil
	}
	return nil, ce.NewContractError(
		ce.ErrStateAccess,
		"no block header at height "+strconv.FormatUint(uint64(height), 10),
	)
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
		return 0, ce.WrapContractError(ce.ErrStateAccess, err)
	}

	lastBlockBytes, err := GetBlockHeaderBytes(lastHeight)
	if err != nil {
		return 0, err
	}
	var lastBlockHeader wire.BlockHeader
	err = lastBlockHeader.BtcDecode(bytes.NewReader(lastBlockBytes), wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		return 0, ce.NewContractError(ce.ErrInput, "error decoding block header: "+err.Error())
	}

	powLimit := networkParams.PowLimit

	for _, headerBytes := range rawHeaders {
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

		sdk.StateSetObject(blockSlotKey(blockHeight), encodeBlockSlot(blockHeight, headerBytes))
		lastHeight = blockHeight
		lastBlockHeader = blockHeader
	}

	return lastHeight, nil
}

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
		return 0, ce.WrapContractError(ce.ErrStateAccess, err)
	}

	var newHeader wire.BlockHeader
	err = newHeader.BtcDecode(bytes.NewReader(rawHeader[:]), wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		return 0, ce.NewContractError(ce.ErrInput, "error decoding replacement header: "+err.Error())
	}

	msgBlock := wire.MsgBlock{Header: newHeader}
	if err := blockchain.CheckProofOfWork(btcutil.NewBlock(&msgBlock), networkParams.PowLimit); err != nil {
		return 0, ce.NewContractError(ce.ErrInput, "replacement block failed PoW check: "+err.Error())
	}

	prevHeight := lastHeight - 1
	prevBlockBytes, err := GetBlockHeaderBytes(prevHeight)
	if err != nil {
		return 0, err
	}
	var prevHeader wire.BlockHeader
	err = prevHeader.BtcDecode(bytes.NewReader(prevBlockBytes), wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		return 0, ce.NewContractError(ce.ErrStateAccess, "error decoding block at height "+strconv.FormatUint(uint64(prevHeight), 10))
	}
	prevHash := prevHeader.BlockHash()
	if !newHeader.PrevBlock.IsEqual(&prevHash) {
		return 0, ce.NewContractError(ce.ErrInput, "replacement block does not chain to block at height "+strconv.FormatUint(uint64(prevHeight), 10))
	}

	sdk.StateSetObject(blockSlotKey(lastHeight), encodeBlockSlot(lastHeight, rawHeader))

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
		headerBytes, err := hex.DecodeString(seedParams.BlockHeader)
		if err != nil {
			return 0, ce.WrapContractError(ce.ErrInvalidHex, err, "invalid block header hex")
		}
		if len(headerBytes) != 80 {
			return 0, ce.NewContractError(ce.ErrInput, "block header must be 80 bytes")
		}
		var fixed [80]byte
		copy(fixed[:], headerBytes)
		sdk.StateSetObject(blockSlotKey(seedParams.BlockHeight), encodeBlockSlot(seedParams.BlockHeight, fixed))
		sdk.StateSetObject(constants.LastHeightKey, strconv.FormatInt(int64(seedParams.BlockHeight), 10))
		sdk.StateSetObject(constants.SeedHeightKey, strconv.FormatInt(int64(seedParams.BlockHeight), 10))
		return seedParams.BlockHeight, nil
	}

	return 0, ce.NewContractError(
		ce.ErrInput,
		"last height >= input block height. last height: "+strconv.FormatUint(uint64(lastHeight), 10),
	)
}
