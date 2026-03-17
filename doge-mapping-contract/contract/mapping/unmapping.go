package mapping

import (
	"doge-mapping-contract/contract/constants"
	ce "doge-mapping-contract/contract/contracterrors"
	"doge-mapping-contract/sdk"
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

func calcVscFee(amount int64) (int64, error) {
	const minFee int64 = 1000
	const feeRateBps int64 = 100 // 100 basis points, 1%
	// divide first to avoid overflow on large amounts, then compensate for remainder
	percentageFee := (amount / 10000) * feeRateBps
	remainder := (amount % 10000) * feeRateBps / 10000
	percentageFee += remainder
	finalFee := minFee
	if percentageFee > minFee {
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

// Helper function to estimate fee for a given number of inputs and outputs
func (cs *ContractState) estimateFee(numInputs int64, amount, inputAmount int64) int64 {
	numOutputs := int64(1)
	totalChange := inputAmount - amount
	if totalChange > dustThreshold {
		// total number of change outputs
		numOutputs += min(max(totalChange/splitThreshold, 1), maxChangeOutputs)
	}

	// Base transaction overhead (version, locktime, etc.)
	baseSize := int64(10)

	// Input size: outpoint (36) + script sig length (1) + sequence (4)
	inputSize := numInputs * 41

	// Output size: value (8) + script length (1) + P2WSH script (34)
	outputSize := numOutputs * 43

	// Witness data per input (signature + witness script)
	// 72 bytes sig + 68 bytes witness script + 3 bytes for size markers
	witnessDataSize := numInputs * (72 + 68 + 3)

	totalSize := baseSize + inputSize + outputSize
	// Calculate vSize: (base_size * 3 + total_size + witness_data) / 4 + witness flag overhead
	vSize := (totalSize*3+totalSize+witnessDataSize+3)/4 + 2

	return vSize * cs.Supply.BaseFeeRate
}

// returns a list of internal ids of inputs for making a tx
func (cs *ContractState) getInputUtxoIds(amount int64) ([]uint8, int64, error) {
	// approximate size of including a new PSWSH input (base tx size plus signature)
	// slight overestimate (+1 at the end) to make sure there's enough balance
	const P2WSHAPPROXINPUTSIZE = 40 + 1 + (72+68+3)/4 + 1

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
	// estimates size of segwit signatures
	witnessDataSize := int64(0)
	for _, witnessScript := range witnessScripts {
		// +3 is for size flags, but small enough to be represented by themselves so just 1 byte per
		witnessDataSize += 72 + int64(len(witnessScript)) + 3
	}
	totalSize := baseSize + witnessDataSize
	// +3 to round up, + 2 for has witness data flag
	vSize := (baseSize*3+totalSize+3)/4 + 2
	return vSize * cs.Supply.BaseFeeRate
}

func (cs *ContractState) createSpendTransaction(
	inputs []*Utxo,
	totalInputsAmount int64,
	destAddress string,
	changeAddress string,
	sendAmount int64,
) (*SigningData, *wire.MsgTx, int64, error) {
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

	// if change is not dust
	if totalChange > dustThreshold {
		// split if above SPLITTHRESHOLD, taking into account the added fee
		// for each split (about 34 bytes per output)
		changeAddressObj, err := btcutil.DecodeAddress(changeAddress, cs.NetworkParams)
		if err != nil {
			return nil, nil, 0, err
		}
		changeScript, err := txscript.PayToAddrScript(changeAddressObj)
		if err != nil {
			return nil, nil, 0, err
		}
		// create a dummy change output to calculate additional fee for adding change outputs
		changeOutputSize := int64(wire.NewTxOut(int64(0), changeScript).SerializeSize())

		numChangeOuputs := min(max(totalChange/splitThreshold, 1), maxChangeOutputs)

		// recalculate the size/fee
		baseSize += numChangeOuputs * changeOutputSize
		fee = cs.calculateSegwitFee(baseSize, witnessScripts)

		eachChangeAmount := (totalChange - fee) / numChangeOuputs
		firstChangeAmount := eachChangeAmount
		if (eachChangeAmount * numChangeOuputs) != (totalChange - fee) {
			firstChangeAmount += (totalChange - fee - eachChangeAmount*numChangeOuputs)
		}

		txOutChange := wire.NewTxOut(firstChangeAmount, changeScript)
		tx.AddTxOut(txOutChange)

		for range numChangeOuputs - 1 {
			txOutChange := wire.NewTxOut(eachChangeAmount, changeScript)
			tx.AddTxOut(txOutChange)
		}
	}

	// P2WSH: Calculate witness sighash
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
			return nil, nil, 0, err
		}

		sdk.TssSignKey(constants.TssKeyName, sigHash)

		unsignedSigHashes[i] = UnsignedSigHash{
			Index:         uint32(i),
			SigHash:       sigHash,
			WitnessScript: witnessScript,
		}
	}

	var buf bytes.Buffer
	err = tx.Serialize(&buf)
	if err != nil {
		return nil, nil, 0, err
	}

	return &SigningData{
		Tx:                buf.Bytes(),
		UnsignedSigHashes: unsignedSigHashes,
	}, tx, fee, nil
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
