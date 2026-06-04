package mapping

import (
	"dash-mapping-contract/contract/constants"
	ce "dash-mapping-contract/contract/contracterrors"
	"dash-mapping-contract/sdk"
	"bytes"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// constants in sats
const dustThreshold = 546

const splitThreshold = 1000000 // 0.01 BTC
const maxChangeOutputs = 4

// VscFeeMinSats is the minimum VSC protocol fee in satoshis.
const VscFeeMinSats int64 = 0

// VscFeeRateBps is the VSC protocol fee as basis points (1 bps = 0.01%).
const VscFeeRateBps int64 = 0

func calcVscFee(amount int64) (int64, error) {
	if VscFeeMinSats == 0 && VscFeeRateBps == 0 {
		return 0, nil
	}
	// divide first to avoid overflow on large amounts, then compensate for remainder
	percentageFee := (amount/10000)*VscFeeRateBps + (amount%10000)*VscFeeRateBps/10000
	finalFee := VscFeeMinSats
	if percentageFee > VscFeeMinSats {
		finalFee = percentageFee
	}
	if finalFee >= amount {
		return 0, ce.NewContractError(ce.ErrBalance, "transaction too small to cover fee")
	}
	return finalFee, nil
}

func getInputUtxos(registryEntries []uint16) ([]*Utxo, error) {
	result := make([]*Utxo, len(registryEntries))
	for i, internalId := range registryEntries {
		utxo, err := loadUtxo(internalId)
		if err != nil {
			return nil, ce.WrapContractError(ce.ErrStateAccess, err, "error loading saved utxo")
		}
		result[i] = utxo
	}
	return result, nil
}

// estimateP2SHTxBytes returns the estimated on-chain wire-format size
// of a Dash unmap spend transaction in BYTES (not vsize).
//
// Audit R16-OPS-calculate-segwit-fee-p2sh-underpay-mainnet (HIGH):
// the prior implementation applied a SegWit ÷4 vsize discount to the
// scriptSig data ("witness data"). But Dash never activated SegWit
// (which is why deposit addresses are P2SH — see commit acfb268), so
// the signature + redeem script live INSIDE each input's scriptSig
// and count at full weight on the wire. The discounted formula
// under-estimated unmap fees by roughly 3-4× on a typical multi-input
// spend, leaving mainnet unmap txs chronically below the dynamic fee
// floor + at risk of stuck-in-mempool.
//
// The correct fee is simply (nonScriptSize + scriptDataSize) *
// feeRate. No /4 discount, no +2 witness-flag overhead.
//
//	nonScriptSize  = wire-format tx size with EMPTY scriptSigs
//	                 (10 header + 41/input + 43/output, or
//	                 tx.SerializeSize() on a tx whose scriptSigs
//	                 haven't been populated yet)
//	scriptDataSize = per-input (signature + branch selector +
//	                 redeem script + push-opcode framing) summed
//	                 across all inputs
//
// Total wire bytes for the broadcast-ready tx = nonScriptSize +
// scriptDataSize because varint length encoding of a populated
// scriptSig (~190 bytes < 253) stays at 1 byte, same as the empty
// scriptSig length byte already counted in nonScriptSize.
func estimateP2SHTxBytes(nonScriptSize, scriptDataSize int64) int64 {
	return nonScriptSize + scriptDataSize
}

// clampedFeeRate returns the base fee rate clamped to MaxBaseFeeRate.
func clampedFeeRate(rate int64) int64 {
	if rate > constants.MaxBaseFeeRate {
		return constants.MaxBaseFeeRate
	}
	if rate < 1 {
		return 1
	}
	return rate
}

// Helper function to estimate fee for a given number of inputs and outputs.
// Accounts for the base fee before deciding how many change outputs to include,
// and only adds change outputs that remain above dust after fee adjustment.
//
// Uses the corrected P2SH fee math (audit R16-OPS-calculate-segwit-
// fee-p2sh-underpay-mainnet). The pre-fix version applied a SegWit
// /4 vsize discount to scriptSig data; Dash is non-SegWit so all
// bytes count at full weight.
func (cs *ContractState) estimateFee(numInputs int64, amount, inputAmount int64) (int64, error) {
	feeRate := clampedFeeRate(cs.Supply.BaseFeeRate)
	totalChange := inputAmount - amount

	// Base transaction overhead (version, locktime, etc.)
	baseSize := int64(10)
	// Input size: outpoint (36) + scriptSig length byte (1) + sequence (4)
	// The scriptSig BYTES themselves are counted separately in
	// scriptDataSize below.
	inputSize := numInputs * 41
	// Output size: value (8) + script length (1) + P2SH script (~34)
	outputSize := int64(43) // 1 destination output

	// Per-input scriptSig content for our P2SH redeem-script branch:
	//   <sig>     OP_PUSHDATA + 72-byte signature
	//   <branch>  OP_PUSHDATA + 1-byte branch selector
	//   <script>  OP_PUSHDATA + N-byte redeem script
	// Plus ~3 bytes of push-opcode framing (one per push). Total per
	// input ≈ 72 + 1 + len(redeemScript) + 5. Redeem-script is ~79
	// bytes for change UTXOs (no tag) and ~112 bytes for deposit UTXOs
	// (with 32-byte tag); use 112 as conservative upper bound.
	scriptDataSize := numInputs * (72 + 112 + 5)

	// Compute base fee (no change outputs) first
	nonScriptSize := baseSize + inputSize + outputSize
	baseFee, err := safeMultiply64(estimateP2SHTxBytes(nonScriptSize, scriptDataSize), feeRate)
	if err != nil {
		return 0, ce.WrapContractError(ce.ErrArithmetic, err, "fee estimation overflow")
	}

	availableChange := totalChange - baseFee
	if availableChange < 0 {
		availableChange = 0
	}

	if availableChange > dustThreshold {
		numChangeOutputs := min(max(availableChange/splitThreshold, 1), maxChangeOutputs)

		// Add change outputs one at a time, stopping when per-output amount is dust
		addedOutputs := int64(0)
		for i := int64(0); i < numChangeOutputs; i++ {
			newNonScript := nonScriptSize + (addedOutputs+1)*43
			newFee, err := safeMultiply64(estimateP2SHTxBytes(newNonScript, scriptDataSize), feeRate)
			if err != nil {
				return 0, ce.WrapContractError(ce.ErrArithmetic, err, "fee estimation overflow")
			}
			newAvailable := totalChange - newFee
			if newAvailable < 0 {
				newAvailable = 0
			}
			if newAvailable/(addedOutputs+1) <= dustThreshold {
				break
			}
			addedOutputs++
			nonScriptSize = newNonScript
		}
	}

	fee, err := safeMultiply64(estimateP2SHTxBytes(nonScriptSize, scriptDataSize), feeRate)
	if err != nil {
		return 0, ce.WrapContractError(ce.ErrArithmetic, err, "fee estimation overflow")
	}
	return fee, nil
}

// returns a list of internal ids of inputs for making a tx
func (cs *ContractState) getInputUtxoIds(amount int64) ([]uint16, int64, error) {
	inputs := []uint16{}

	// accumulates amount of all inputs
	accAmount := int64(0)

	// first loop: find single confirmed UTXO sufficient to cover spend
	for _, entry := range cs.UtxoList {
		if entry.Id < constants.UtxoConfirmedPoolStart {
			continue
		}
		fee, err := cs.estimateFee(1, amount, entry.Amount)
		if err != nil {
			return nil, 0, err
		}
		requiredAmount := amount + fee
		if entry.Amount >= requiredAmount {
			return []uint16{entry.Id}, entry.Amount, nil
		}
	}

	// second loop: accumulate confirmed UTXOs, fall back to unconfirmed if needed
	type unconfirmedEntry struct {
		id     uint16
		amount int64
	}
	unconfirmedTxs := []unconfirmedEntry{}

	var err error
	for _, entry := range cs.UtxoList {
		if entry.Id >= constants.UtxoConfirmedPoolStart {
			inputs = append(inputs, entry.Id)
			accAmount, err = safeAdd64(accAmount, entry.Amount)
			if err != nil {
				return nil, 0, ce.WrapContractError(ce.ErrArithmetic, err, "error gathering utxos")
			}

			fee, err := cs.estimateFee(int64(len(inputs)), amount, accAmount)
			if err != nil {
				return nil, 0, err
			}
			requiredAmount := amount + fee

			if accAmount >= requiredAmount {
				return inputs, accAmount, nil
			}
		} else {
			unconfirmedTxs = append(unconfirmedTxs, unconfirmedEntry{
				id:     entry.Id,
				amount: entry.Amount,
			})
		}
	}

	// uses unconfirmed txs only if all confirmed txs are insufficient
	for _, u := range unconfirmedTxs {
		inputs = append(inputs, u.id)
		accAmount, err = safeAdd64(accAmount, u.amount)
		if err != nil {
			return nil, 0, ce.WrapContractError(ce.ErrArithmetic, err, "error gathering utxos")
		}

		fee, err := cs.estimateFee(int64(len(inputs)), amount, accAmount)
		if err != nil {
			return nil, 0, err
		}
		requiredAmount := amount + fee

		if accAmount >= requiredAmount {
			return inputs, accAmount, nil
		}
	}
	// this really should never happen
	return nil, 0, ce.NewContractError(ce.ErrBalance, "total available balance insufficient to complete transaction")
}

// calculateP2SHFee computes the unmap-tx fee for a Dash P2SH spend.
//
// Audit R16-OPS-calculate-segwit-fee-p2sh-underpay-mainnet (HIGH):
// the prior function was named calculateSegwitFee and applied the
// SegWit ÷4 vsize discount to scriptSig data. Dash never activated
// SegWit (which is exactly why deposit addresses are P2SH per commit
// acfb268), so every on-wire byte counts at full weight. The discounted
// formula under-estimated unmap fees by ~3-4× on a typical multi-input
// spend, leaving mainnet unmap txs chronically below the dynamic
// fee floor + at risk of stuck-in-mempool.
//
// Correct fee = (nonScriptSize + scriptDataSize) * feeRate, where:
//
//	nonScriptSize  — wire-format tx size with EMPTY scriptSigs
//	                 (caller passes tx.SerializeSize() pre-signing)
//	scriptDataSize — Σ over inputs of (signature + branch selector +
//	                 redeem script + push-opcode framing)
//
// No /4 discount; no +2 witness-flag overhead.
// Audit R17-CONS-calculate-p2sh-fee-redeemscripts-param-name-drift:
// callers pass a `witnessScripts` map[int][]byte (variable name kept
// because the same map is threaded into btcd's PrevOut.WitnessScript
// field downstream, where the name is fixed by the btcd API). Within
// THIS function the values are the P2SH redeem scripts that will be
// embedded in each input's scriptSig, so the parameter name reads
// `redeemScripts`. The two names describe the same bytes from
// different vantage points; the parameter rename was a deliberate
// audit R15-CONS-01 alignment.
func (cs *ContractState) calculateP2SHFee(nonScriptSize int64, redeemScripts map[int][]byte) (int64, error) {
	feeRate := clampedFeeRate(cs.Supply.BaseFeeRate)
	// Per-input scriptSig content; matches the per-input estimate in
	// estimateFee above. 72-byte ECDSA sig + 1-byte branch selector +
	// N-byte redeem script + ~5 bytes of push-opcode framing.
	scriptDataSize := int64(0)
	for _, redeemScript := range redeemScripts {
		scriptDataSize += 72 + int64(len(redeemScript)) + 5
	}
	fee, err := safeMultiply64(estimateP2SHTxBytes(nonScriptSize, scriptDataSize), feeRate)
	if err != nil {
		return 0, ce.WrapContractError(ce.ErrArithmetic, err, "fee calculation overflow")
	}
	return fee, nil
}

// buildSpendTransaction constructs the Bitcoin withdrawal transaction and
// computes the miner fee, but does NOT request TSS signing. Call
// signSpendTransaction after all validation checks pass.
func (cs *ContractState) buildSpendTransaction(
	inputs []*Utxo,
	totalInputsAmount int64,
	destAddress string,
	changeAddress string,
	sendAmount int64,
) (*wire.MsgTx, map[int][]byte, int64, error) {
	tx := wire.NewMsgTx(wire.TxVersion)

	// create all witness scripts now for better size estimation
	witnessScripts := make(map[int][]byte)
	for index, utxo := range inputs {
		txHash, err := chainhash.NewHashFromStr(utxo.TxId)
		if err != nil {
			return nil, nil, 0, err
		}

		outPoint := wire.NewOutPoint(txHash, utxo.Vout)
		txIn := wire.NewTxIn(outPoint, nil, nil)
		tx.AddTxIn(txIn)

		_, witnessScript, err := createP2SHAddressWithBackup(
			cs.PublicKeys.Primary,
			cs.PublicKeys.Backup,
			utxo.Tag, // already []byte
			cs.NetworkParams,
		)

		if err != nil {
			return nil, nil, 0, err
		}
		witnessScripts[index] = witnessScript
	}

	destAddr, err := btcutil.DecodeAddress(destAddress, cs.NetworkParams)
	if err != nil {
		return nil, nil, 0, ce.WrapContractError(
			ce.ErrInput,
			err,
			"error decoding destination btc address ["+destAddress+"]",
		)
	}

	// Create output script for destination
	destScript, err := txscript.PayToAddrScript(destAddr)
	if err != nil {
		return nil, nil, 0, err
	}

	destTxOut := wire.NewTxOut(sendAmount, destScript)
	tx.AddTxOut(destTxOut)

	baseSize := int64(tx.SerializeSize())
	fee, err := cs.calculateP2SHFee(baseSize, witnessScripts)
	if err != nil {
		return nil, nil, 0, err
	}

	totalChange := totalInputsAmount - sendAmount

	// Account for the base fee before computing available change
	availableChange := totalChange - fee
	if availableChange < 0 {
		availableChange = 0
	}

	// Add change outputs if above dust, splitting across multiple outputs
	if availableChange > dustThreshold {
		changeAddressObj, err := btcutil.DecodeAddress(changeAddress, cs.NetworkParams)
		if err != nil {
			return nil, nil, 0, err
		}
		changeScript, err := txscript.PayToAddrScript(changeAddressObj)
		if err != nil {
			return nil, nil, 0, err
		}
		changeOutputSize := int64(wire.NewTxOut(int64(0), changeScript).SerializeSize())

		numChangeOuputs := min(max(availableChange/splitThreshold, 1), maxChangeOutputs)

		// Add change outputs one at a time, recalculating fee after each
		addedOutputs := int64(0)
		for range numChangeOuputs {
			newBaseSize := baseSize + (addedOutputs+1)*changeOutputSize
			newFee, err := cs.calculateP2SHFee(newBaseSize, witnessScripts)
			if err != nil {
				return nil, nil, 0, err
			}
			newAvailable := totalChange - newFee
			if newAvailable < 0 {
				newAvailable = 0
			}

			// Check if adding this output still leaves enough for all outputs to be above dust
			perOutput := newAvailable / (addedOutputs + 1)
			if perOutput <= dustThreshold {
				break
			}

			addedOutputs++
			baseSize = newBaseSize
			fee = newFee
			availableChange = newAvailable
		}

		if addedOutputs > 0 {
			eachChangeAmount := availableChange / addedOutputs
			remainder := availableChange - eachChangeAmount*addedOutputs

			txOutChange := wire.NewTxOut(eachChangeAmount+remainder, changeScript)
			tx.AddTxOut(txOutChange)

			for range addedOutputs - 1 {
				txOutChange := wire.NewTxOut(eachChangeAmount, changeScript)
				tx.AddTxOut(txOutChange)
			}
		}
	}

	// Pentest finding BTC-C5: when availableChange ≤ dustThreshold the
	// change output is omitted; the residual sats are implicitly paid
	// to the miner. The size-based fee variable above does NOT capture
	// that absorbed dust, so callers (HandleUnmap) under-decrement
	// ActiveSupply, drifting the contract's BTC accounting up to 545
	// sats per affected withdrawal. Recompute the fee from the actual
	// tx outputs so the returned value reflects real outflow in every
	// branch (normal change-output paths balance trivially; the math
	// is equivalent there).
	var outSum int64
	for _, o := range tx.TxOut {
		outSum += o.Value
	}
	fee = totalInputsAmount - outSum

	return tx, witnessScripts, fee, nil
}

// signSpendTransaction computes witness sighashes and requests TSS signing
// for each input. Call this only after all validation checks have passed.
func signSpendTransaction(tx *wire.MsgTx, inputs []*Utxo, witnessScripts map[int][]byte) (*SigningData, error) {
	unsignedSigHashes := make([]UnsignedSigHash, len(inputs))
	for i, utxo := range inputs {
		witnessScript := witnessScripts[i]

		sigHashes := txscript.NewTxSigHashes(tx, txscript.NewCannedPrevOutputFetcher(utxo.PkScript, utxo.Amount))

		sigHash, err := txscript.CalcWitnessSigHash(
			witnessScript,
			sigHashes,
			txscript.SigHashAll,
			tx,
			i,
			utxo.Amount,
		)

		if err != nil {
			return nil, err
		}

		sdk.TssSignKey(constants.TssKeyName, sigHash)

		unsignedSigHashes[i] = UnsignedSigHash{
			Index:         uint32(i),
			SigHash:       sigHash,
			WitnessScript: witnessScript,
		}
	}

	var buf bytes.Buffer
	err := tx.Serialize(&buf)
	if err != nil {
		return nil, err
	}

	return &SigningData{
		Tx:                buf.Bytes(),
		UnsignedSigHashes: unsignedSigHashes,
	}, nil
}

func indexUnconfimedOutputs(tx *wire.MsgTx, changeAddress string, network *chaincfg.Params) ([]*Utxo, error) {
	// 1 output will be to the destination, the others will be to change address
	utxos := make([]*Utxo, len(tx.TxOut)-1)

	i := 0
	for index, txOut := range tx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, network)
		if err != nil {
			return nil, err
		}
		// must be 1 because it's a standard P2SH output (one script-hash address)
		if len(addrs) != 1 {
			return nil, ce.NewContractError(ce.ErrTransaction, "incorrect number of addresses for transaction output")
		}
		if addrs[0].EncodeAddress() == changeAddress {
			utxo := Utxo{
				TxId:     tx.TxID(),
				Vout:     uint32(index),
				Amount:   txOut.Value,
				PkScript: txOut.PkScript,
				Tag:      nil, // change outputs have no tag
			}
			if i < len(utxos) {
				utxos[i] = &utxo
				i++
			} else {
				utxos = append(utxos, &utxo)
			}
		}
	}

	return utxos, nil
}
