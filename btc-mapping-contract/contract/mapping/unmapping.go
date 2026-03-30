package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
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

func getInputUtxos(registryEntries []uint8) ([]*Utxo, error) {
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

// estimateVSize returns the estimated vSize for given non-witness and witness data sizes.
func estimateVSize(nonWitnessSize, witnessDataSize int64) int64 {
	totalSize := nonWitnessSize + witnessDataSize
	return (nonWitnessSize*3+totalSize+3)/4 + 2
}

// Helper function to estimate fee for a given number of inputs and outputs.
// Accounts for the base fee before deciding how many change outputs to include,
// and only adds change outputs that remain above dust after fee adjustment.
func (cs *ContractState) estimateFee(numInputs int64, amount, inputAmount int64) int64 {
	totalChange := inputAmount - amount

	// Base transaction overhead (version, locktime, etc.)
	baseSize := int64(10)
	// Input size: outpoint (36) + script sig length (1) + sequence (4)
	inputSize := numInputs * 41
	// Output size: value (8) + script length (1) + P2WSH script (34)
	outputSize := int64(43) // 1 destination output

	// Witness stack per input: <sig> <branch_selector> <witness_script>
	// Serialized: item_count(1) + sig_len(1) + sig(72) + branch_len(1) + branch(1) + script_len(1) + script(N)
	// Witness script is ~79 bytes for change UTXOs (no tag) or ~112 bytes for
	// deposit UTXOs (with 32-byte tag). Use 112 as conservative upper bound
	// to ensure fee estimate >= actual fee from calculateSegwitFee.
	witnessDataSize := numInputs * (72 + 112 + 5)

	// Compute base fee (no change outputs) first
	nonWitnessSize := baseSize + inputSize + outputSize
	baseFee := estimateVSize(nonWitnessSize, witnessDataSize) * cs.Supply.BaseFeeRate

	availableChange := totalChange - baseFee
	if availableChange < 0 {
		availableChange = 0
	}

	if availableChange > dustThreshold {
		numChangeOutputs := min(max(availableChange/splitThreshold, 1), maxChangeOutputs)

		// Add change outputs one at a time, stopping when per-output amount is dust
		addedOutputs := int64(0)
		for i := int64(0); i < numChangeOutputs; i++ {
			newNonWitness := nonWitnessSize + (addedOutputs+1)*43
			newFee := estimateVSize(newNonWitness, witnessDataSize) * cs.Supply.BaseFeeRate
			newAvailable := totalChange - newFee
			if newAvailable < 0 {
				newAvailable = 0
			}
			if newAvailable/(addedOutputs+1) <= dustThreshold {
				break
			}
			addedOutputs++
			nonWitnessSize = newNonWitness
		}
	}

	return estimateVSize(nonWitnessSize, witnessDataSize) * cs.Supply.BaseFeeRate
}

// returns a list of internal ids of inputs for making a tx
func (cs *ContractState) getInputUtxoIds(amount int64) ([]uint8, int64, error) {
	inputs := []uint8{}

	// accumulates amount of all inputs
	accAmount := int64(0)

	// first loop: find single confirmed UTXO sufficient to cover spend
	for _, entry := range cs.UtxoList {
		if entry.Id < constants.UtxoConfirmedPoolStart {
			continue
		}
		fee := cs.estimateFee(1, amount, entry.Amount)
		requiredAmount := amount + fee
		if entry.Amount >= requiredAmount {
			return []uint8{entry.Id}, entry.Amount, nil
		}
	}

	// second loop: accumulate confirmed UTXOs, fall back to unconfirmed if needed
	type unconfirmedEntry struct {
		id     uint8
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

			fee := cs.estimateFee(int64(len(inputs)), amount, accAmount)
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

		fee := cs.estimateFee(int64(len(inputs)), amount, accAmount)
		requiredAmount := amount + fee

		if accAmount >= requiredAmount {
			return inputs, accAmount, nil
		}
	}
	// this really should never happen
	return nil, 0, ce.NewContractError(ce.ErrBalance, "total available balance insufficient to complete transaction")
}

func (cs *ContractState) calculateSegwitFee(baseSize int64, witnessScripts map[int][]byte) int64 {
	// Witness stack per input: <sig> <branch_selector> <witness_script>
	// Serialized: item_count(1) + sig_len(1) + sig(72) + branch_len(1) + branch(1) + script_len(1) + script(N)
	witnessDataSize := int64(0)
	for _, witnessScript := range witnessScripts {
		witnessDataSize += 72 + int64(len(witnessScript)) + 5
	}
	totalSize := baseSize + witnessDataSize
	// +3 to round up, + 2 for has witness data flag
	vSize := (baseSize*3+totalSize+3)/4 + 2
	return vSize * cs.Supply.BaseFeeRate
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

		_, witnessScript, err := createP2WSHAddressWithBackup(
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
	fee := cs.calculateSegwitFee(baseSize, witnessScripts)

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
			newFee := cs.calculateSegwitFee(newBaseSize, witnessScripts)
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
		// must be 1 because it's P2WSH
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
