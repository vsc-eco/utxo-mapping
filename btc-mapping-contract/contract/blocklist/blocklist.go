package blocklist

import (
	"btc-mapping-contract/sdk"
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
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
func seedHeightFromState() int64 {
	s := sdk.StateGetObject(constants.SeedHeightKey)
	if s == nil || *s == "" {
		return 0
	}
	h, err := strconv.ParseInt(*s, 10, 32)
	if err != nil {
		return 0
	}
	return h
}

// pruneFloorFromState returns the lowest height that hasn't been pruned yet.
// This cursor avoids re-scanning already-pruned regions on each call.
func pruneFloorFromState() int64 {
	s := sdk.StateGetObject(constants.PruneFloorKey)
	if s == nil || *s == "" {
		return 0
	}
	h, err := strconv.ParseInt(*s, 10, 32)
	if err != nil {
		return 0
	}
	return h
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
		return 0, ce.NewContractError(
			ce.ErrStateAccess,
			"no block header found at height "+strconv.FormatInt(int64(lastHeight), 10),
		)
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

		// BTC-HDR-1: CheckProofOfWork above only asserts the hash meets the
		// header's OWN declared target, and that the target is no easier than
		// PowLimit. It never asks whether that target is the one the retarget
		// rules require, so a header claiming minimum difficulty passed.
		if err := validateDifficulty(networkParams, blockHeight, &blockHeader, &lastBlockHeader); err != nil {
			return 0, err
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

// validateDifficulty enforces Bitcoin's difficulty rules on an incoming header
// (BTC-HDR-1).
//
// THE GAP. blockchain.CheckProofOfWork answers only "does this hash meet the
// target this header declares, and is that target no easier than PowLimit?".
// Both are true of a header mined at MINIMUM difficulty. Nothing asked whether
// the declared target is the one the retarget schedule actually requires, so
// the only thing standing between the contract and a fabricated chain was the
// 2/3 oracle quorum. That matters because the header chain is what SPV deposit
// proofs are checked against: a cheap fake chain mints unbacked wrapped BTC,
// and the amount is bounded only by the pool depth it is swapped into -- which
// makes this the amplifier that turns an oracle compromise into an unbounded
// loss rather than a bounded one.
//
// THE RULES, which are entirely local and need no chain walk:
//
//   - Between retargets (2015 of every 2016 blocks) nBits must be IDENTICAL to
//     the parent's. This single check is what kills the attack: difficulty can
//     then only ease at a boundary, and only by RetargetAdjustmentFactor (4x),
//     so walking mainnet difficulty down to the minimum needs ~23 consecutive
//     retargets -- ~46,000 blocks, each still mined at the prevailing (high)
//     difficulty. Computationally out of reach.
//   - At a boundary, nBits must equal the value the retarget formula produces
//     from the period's first block. Verified against real mainnet history
//     before being written: at height 973,728 the formula reproduces the live
//     chain's 0x1701e5ac exactly (see the difficulty tests).
//
// Test networks are exempt because ReduceMinDifficulty is true for them: the
// 20-minute rule lets a testnet/regtest block legitimately carry minimum
// difficulty, so "nBits unchanged" is simply not a rule there. Mainnet is the
// only network the contract uses that has ReduceMinDifficulty false, and it is
// the only one holding funds.
func validateDifficulty(
	networkParams *chaincfg.Params,
	blockHeight uint32,
	blockHeader *wire.BlockHeader,
	lastBlockHeader *wire.BlockHeader,
) error {
	if networkParams.ReduceMinDifficulty {
		return nil
	}
	interval := retargetInterval(networkParams)
	if interval == 0 {
		return nil
	}

	if blockHeight%interval != 0 {
		if blockHeader.Bits != lastBlockHeader.Bits {
			return ce.NewContractError(
				ce.ErrInput,
				"block "+strconv.FormatUint(uint64(blockHeight), 10)+
					" changes difficulty outside a retarget boundary: bits "+
					strconv.FormatUint(uint64(blockHeader.Bits), 16)+" != parent "+
					strconv.FormatUint(uint64(lastBlockHeader.Bits), 16),
			)
		}
		return nil
	}

	// Retarget boundary. Reject anything easier than the network floor up front
	// (CheckProofOfWork covers this too, but this keeps the branch total).
	newTarget := blockchain.CompactToBig(blockHeader.Bits)
	if newTarget.Sign() <= 0 || newTarget.Cmp(networkParams.PowLimit) > 0 {
		return ce.NewContractError(
			ce.ErrInput,
			"block "+strconv.FormatUint(uint64(blockHeight), 10)+" retarget target out of range",
		)
	}

	// The period's first block is blockHeight-interval: with retention at 4608
	// and the interval 2016 it is normally still in state.
	if firstHeader, ok := loadHeaderAt(blockHeight - interval); ok {
		expected := calcNextRequiredBits(networkParams, lastBlockHeader, firstHeader)
		if blockHeader.Bits != expected {
			return ce.NewContractError(
				ce.ErrInput,
				"block "+strconv.FormatUint(uint64(blockHeight), 10)+
					" retarget bits "+strconv.FormatUint(uint64(blockHeader.Bits), 16)+
					" != required "+strconv.FormatUint(uint64(expected), 16),
			)
		}
		return nil
	}

	// The first header is gone (pruned, or the contract was seeded inside this
	// period). Fall back to the protocol's own clamp rather than fail: the exact
	// value cannot be recomputed, but the ADJUSTMENT can still be bounded, which
	// is what keeps the walk-down attack infeasible. Refusing instead would stall
	// the whole bridge at a boundary for a header that is almost certainly honest.
	oldTarget := blockchain.CompactToBig(lastBlockHeader.Bits)
	factor := big.NewInt(networkParams.RetargetAdjustmentFactor)
	maxTarget := new(big.Int).Mul(oldTarget, factor)
	if maxTarget.Cmp(networkParams.PowLimit) > 0 {
		maxTarget.Set(networkParams.PowLimit)
	}
	minTarget := new(big.Int).Div(oldTarget, factor)
	if newTarget.Cmp(maxTarget) > 0 || newTarget.Cmp(minTarget) < 0 {
		return ce.NewContractError(
			ce.ErrInput,
			"block "+strconv.FormatUint(uint64(blockHeight), 10)+
				" retarget exceeds the permitted "+strconv.FormatInt(networkParams.RetargetAdjustmentFactor, 10)+
				"x adjustment (first header of the period unavailable)",
		)
	}
	return nil
}

// retargetInterval is the number of blocks between difficulty retargets (2016
// on mainnet), derived from the network params rather than hard-coded.
func retargetInterval(networkParams *chaincfg.Params) uint32 {
	if networkParams.TargetTimePerBlock <= 0 {
		return 0
	}
	return uint32(networkParams.TargetTimespan / networkParams.TargetTimePerBlock)
}

// calcNextRequiredBits is Bitcoin's retarget formula: scale the previous
// period's target by how long that period actually took against how long it
// should have taken, clamped to a factor of RetargetAdjustmentFactor either way
// and capped at PowLimit.
//
// `lastHeader` is the period's last block (the new block's parent) and
// `firstHeader` its first, which for a new block at height H are H-1 and
// H-interval. Matches Bitcoin Core's CalculateNextWorkRequired, and is
// checked against real mainnet history in the tests.
func calcNextRequiredBits(
	networkParams *chaincfg.Params,
	lastHeader *wire.BlockHeader,
	firstHeader *wire.BlockHeader,
) uint32 {
	targetTimespan := int64(networkParams.TargetTimespan / 1e9) // ns -> s
	actualTimespan := lastHeader.Timestamp.Unix() - firstHeader.Timestamp.Unix()

	minTimespan := targetTimespan / networkParams.RetargetAdjustmentFactor
	maxTimespan := targetTimespan * networkParams.RetargetAdjustmentFactor
	if actualTimespan < minTimespan {
		actualTimespan = minTimespan
	} else if actualTimespan > maxTimespan {
		actualTimespan = maxTimespan
	}

	newTarget := blockchain.CompactToBig(lastHeader.Bits)
	newTarget.Mul(newTarget, big.NewInt(actualTimespan))
	newTarget.Div(newTarget, big.NewInt(targetTimespan))
	if newTarget.Cmp(networkParams.PowLimit) > 0 {
		newTarget.Set(networkParams.PowLimit)
	}
	return blockchain.BigToCompact(newTarget)
}

// loadHeaderAt reads and decodes the stored 80-byte header at a height.
// ok=false when no header is stored there (pruned, or below the seed height).
func loadHeaderAt(height uint32) (*wire.BlockHeader, bool) {
	raw := sdk.StateGetObject(constants.BlockPrefix + strconv.FormatUint(uint64(height), 10))
	if raw == nil || *raw == "" {
		return nil, false
	}
	var header wire.BlockHeader
	if err := header.BtcDecode(bytes.NewReader([]byte(*raw)), wire.ProtocolVersion, wire.LatestEncoding); err != nil {
		return nil, false
	}
	return &header, true
}

// PruneOldHeaders removes block headers beyond the retention window.
// Uses a floor cursor to avoid re-scanning already-pruned regions.
// Returns the number of headers pruned in this call.
func PruneOldHeaders(lastHeight uint32) int {
	retainFrom := int64(lastHeight) - int64(constants.MaxBlockRetention) + 1
	if retainFrom <= 0 {
		return 0
	}
	// VR2-03: never prune below the oldest live pending spend.
	//
	// confirmSpend needs the exact header at the height its transaction was mined,
	// and pruning had no idea any spend was still waiting for one. A sweep mined on
	// Bitcoin but not reported to the contract within the retention window lost its
	// proof permanently: it could never settle, redrive could not help (the coins
	// had already moved), and the generation stayed "funded" forever — blocking
	// every future rotation and holding every witness's bond.
	//
	// Anchoring on BUILD height is sound and conservative: a transaction cannot be
	// mined below the tip it was built against, so its confirmation height is always
	// at or above the height retained here. Clamping rather than SKIPPING keeps the
	// pruned region contiguous, so the existing single floor cursor still works and
	// no header is stranded behind a hole.
	//
	// The clamp is itself bounded. Retention is held open at most
	// MaxRetentionWithPendingSpend, so a stuck spend cannot pin state growth
	// forever. That bound is a stopgap, not a fix: past it the original stranding
	// returns on a longer timer, and recovering such a spend needs a reconcile
	// operation that does not exist yet.
	if raw := sdk.StateGetObject(constants.PendingSpendFloorKey); raw != nil && *raw != "" {
		if pending, perr := strconv.ParseInt(*raw, 10, 64); perr == nil && pending > 0 && pending < retainFrom {
			floor := int64(lastHeight) - int64(constants.MaxRetentionWithPendingSpend) + 1
			if pending > floor {
				retainFrom = pending
			} else if floor > 0 {
				retainFrom = floor
			}
		}
	}

	pruneFloor := pruneFloorFromState()
	if pruneFloor == 0 {
		pruneFloor = seedHeightFromState()
	}
	if pruneFloor == 0 || int64(pruneFloor) >= retainFrom {
		return 0
	}
	pruned := 0
	h := pruneFloor
	// limit size of search to prevent blow-up in case of gap after re-seed
	for ; h < retainFrom && h-pruneFloor < constants.MaxPrunePerCall; h++ {
		key := constants.BlockPrefix + strconv.FormatInt(h, 10)
		existing := sdk.StateGetObject(key)
		if existing != nil && *existing != "" {
			sdk.StateDeleteObject(key)
			// Also prune the observed tx list for this block height
			// Safe to do here because saveObservedList is only ever
			// called on a proven height
			observedKey := constants.ObservedBlockPrefix + strconv.FormatInt(h, 10)
			sdk.StateDeleteObject(observedKey)
			pruned++
		}
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
		return 0, ce.NewContractError(
			ce.ErrStateAccess,
			"no block found at height "+strconv.FormatUint(uint64(prevHeight), 10),
		)
	}
	var prevHeader wire.BlockHeader
	err = prevHeader.BtcDecode(bytes.NewReader([]byte(*prevBlockRaw)), wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		return 0, ce.NewContractError(
			ce.ErrStateAccess,
			"error decoding block at height "+strconv.FormatUint(uint64(prevHeight), 10),
		)
	}
	prevHash := prevHeader.BlockHash()
	if !newHeader.PrevBlock.IsEqual(&prevHash) {
		return 0, ce.NewContractError(
			ce.ErrInput,
			"replacement block does not chain to block at height "+strconv.FormatUint(uint64(prevHeight), 10),
		)
	}

	// BTC-HDR-1 also applies to a REPLACEMENT. The PoW check above proves only
	// that the header beats networkParams.PowLimit -- the network MINIMUM -- so
	// without this a minimum-difficulty header that addBlocks refuses is
	// accepted here as the tip, and mid-period addBlocks afterwards only compares
	// bits against that poisoned parent, so the forgery sticks. The add path had
	// this check and the replace paths did not: the same guard missing from the
	// second of two entry points into one store. Reported by lordbutterfly
	// reviewing #39.
	if err := validateDifficulty(networkParams, lastHeight, &newHeader, &prevHeader); err != nil {
		return 0, err
	}

	// overwrite the tip
	sdk.StateSetObject(
		constants.BlockPrefix+strconv.FormatUint(uint64(lastHeight), 10),
		string(rawHeader[:]),
	)

	// The observed TX list remains populated during a replacement, to protect against double mint where
	// transactions are re-included in the replacement block. An incorrect mint from a replaced block can
	// technically persist after replacement, but the oracle waits for 2 confirmations and a 3+ block
	// reorg is unprecendented on BTC mainnet, so very low likelihood of encountering this guard at all

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
		return 0, ce.NewContractError(
			ce.ErrStateAccess,
			"no block found at anchor height "+strconv.FormatUint(uint64(anchorHeight), 10),
		)
	}
	var anchorHeader wire.BlockHeader
	err = anchorHeader.BtcDecode(bytes.NewReader([]byte(*anchorBlockRaw)), wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		return 0, ce.NewContractError(
			ce.ErrStateAccess,
			"error decoding block at anchor height "+strconv.FormatUint(uint64(anchorHeight), 10),
		)
	}
	prevHash := anchorHeader.BlockHash()
	// BTC-HDR-1: the difficulty check needs the PARENT header, not just its
	// hash, so carry it alongside prevHash. For the first replacement that is
	// the anchor; after that it is the header this loop just validated.
	prevHeader := anchorHeader

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
			return 0, ce.NewContractError(
				ce.ErrInput,
				"replacement block at height "+strconv.FormatUint(
					uint64(height),
					10,
				)+" does not chain to block at height "+strconv.FormatUint(
					uint64(height-1),
					10,
				),
			)
		}

		// BTC-HDR-1, as in HandleReplaceBlock above: PoW only proves the header
		// beats the network minimum, so the difficulty schedule has to be
		// checked here too or a replacement is the way around it.
		if err := validateDifficulty(networkParams, height, &hdr, &prevHeader); err != nil {
			return 0, err
		}

		sdk.StateSetObject(
			constants.BlockPrefix+strconv.FormatUint(uint64(height), 10),
			string(headerBytes[:]),
		)
		// The observed TX list remains populated during a replacement, to protect against double mint where
		// transactions are re-included in the replacement block. An incorrect mint from a replaced block can
		// technically persist after replacement, but the oracle waits for 2 confirmations and a 3+ block
		// reorg is unprecendented on BTC mainnet, so very low likelihood of encountering this guard at all
		prevHash = hdr.BlockHash()
		prevHeader = hdr
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
