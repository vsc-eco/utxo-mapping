package mapping

import (
	"bytes"
	"contract-template/sdk"
	"encoding/hex"
	"fmt"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// constants in sats
const dustThreshold = 546

// 0.01 BTC
const splitThreshold = 1000000
const maxChangeOutputs = 4

func calcVscFee(amount int64) (int64, error) {
	const minFee int64 = 1000
	const feeRate float64 = 0.01
	percentageFee := int64(float64(amount) * feeRate)
	finalFee := max(minFee, percentageFee)
	if finalFee >= amount {
		return 0, fmt.Errorf("transaction too small to cover fee.")
	}
	return finalFee, nil
}

func getInputUtxos(registryEntries []uint32) ([]*Utxo, error) {
	result := make([]*Utxo, len(registryEntries))
	for i, internalId := range registryEntries {
		utxo := Utxo{}
		utxoJson := sdk.StateGetObject(fmt.Sprintf("%s%x", utxoPrefix, internalId))
		err := tinyjson.Unmarshal([]byte(*utxoJson), &utxo)
		if err != nil {
			return nil, err
		}
		result[i] = &utxo
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
func (cs *ContractState) getInputUtxoIds(amount int64) ([]uint32, int64, error) {
	// approximate size of including a new PSWSH input (base tx size plus signature)
	// slight overestimate (+1 at the end) to make sure there's enough balance
	const P2WSHAPPROXINPUTSIZE = 40 + 1 + (72+68+3)/4 + 1

	inputs := []uint32{}

	// accumulates amount of all inputs
	accAmount := int64(0)

	// first loops, find first tx sufficient to cover spend
	for _, utxo := range cs.UtxoList {
		internalId, utxoAmount, confirmed := unpackUtxo(utxo)
		if confirmed == 0 {
			continue
		}
		fee := cs.estimateFee(1, amount, utxoAmount)
		requiredAmount := amount + fee
		// calculates amount required to cover initial tx plus the addition of itself as an input
		if utxoAmount >= requiredAmount {
			return []uint32{internalId}, utxoAmount, nil
		}
	}
	// second loop, only if first did not find anything
	// accumulate utxos until enough combined balance to cover spend
	// avoids unconfirmed txs
	type unconfirmedUtxo struct {
		internalId uint32
		amount     int64
	}

	unconfirmedTxs := []unconfirmedUtxo{}
	for _, utxo := range cs.UtxoList {
		internalId, utxoAmount, confirmed := unpackUtxo(utxo)
		if confirmed != 0 {
			inputs = append(inputs, internalId)
			accAmount += utxoAmount
			// greater than or equal

			fee := cs.estimateFee(int64(len(inputs)), amount, accAmount)
			requiredAmount := amount + fee

			if accAmount >= requiredAmount {
				return inputs, accAmount, nil
			}
		} else {
			unconfirmedTxs = append(unconfirmedTxs, unconfirmedUtxo{
				internalId: internalId,
				amount:     utxoAmount,
			})
		}

	}
	// uses unconfirmed txs only if all confirmed txs are insufficient
	for _, utxo := range unconfirmedTxs {
		inputs = append(inputs, utxo.internalId)
		accAmount += utxo.amount

		fee := cs.estimateFee(int64(len(inputs)), amount, accAmount)
		requiredAmount := amount + fee

		if accAmount >= requiredAmount {
			return inputs, accAmount, nil
		}
	}
	// this really should never happen
	return nil, 0, fmt.Errorf("Total available balance insufficient to complete transaction")
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

	// create all witness script now for better size estimation
	witnessScripts := make(map[int][]byte)
	for index, utxo := range inputs {
		txHash, err := chainhash.NewHashFromStr(utxo.TxId)
		if err != nil {
			return nil, nil, 0, err
		}

		outPoint := wire.NewOutPoint(txHash, utxo.Vout)
		txIn := wire.NewTxIn(outPoint, nil, nil)
		tx.AddTxIn(txIn)

		tag, err := hex.DecodeString(utxo.Tag)

		if err != nil {
			return nil, nil, 0, err
		}

		_, witnessScript, err := createP2WSHAddressWithBackup(
			cs.PublicKeys.PrimaryPubKey,
			cs.PublicKeys.BackupPubKey,
			tag,
			cs.NetworkParams,
		)

		if err != nil {
			return nil, nil, 0, err
		}
		witnessScripts[index] = witnessScript
	}

	// sdk.Log(fmt.Sprintf("witness scripts created %v", witnessScripts))

	destAddr, err := btcutil.DecodeAddress(destAddress, cs.NetworkParams)
	if err != nil {
		return nil, nil, 0, err
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
		// create a dummy change ouput to calculate additional fee for adding change outputs
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

		sdk.TssSignKey(TssKeyName, sigHash)

		unsignedSigHashes[i] = UnsignedSigHash{
			Index:         uint32(i),
			SigHash:       hex.EncodeToString(sigHash),
			WitnessScript: hex.EncodeToString(witnessScript),
		}
	}

	// sdk.Log(fmt.Sprintf("created sig hashes: %v", unsignedSigHashes))

	var buf bytes.Buffer
	err = tx.Serialize(&buf)
	if err != nil {
		return nil, nil, 0, err
	}
	txHex := hex.EncodeToString(buf.Bytes())

	return &SigningData{
		Tx:                txHex,
		UnsignedSigHashes: unsignedSigHashes,
	}, tx, fee, nil
}

func indexUnconfimedOutputs(tx *wire.MsgTx, changeAddress string, network *chaincfg.Params) ([]*Utxo, error) {
	sdk.Log(fmt.Sprintf("len tx.txOut: %d", len(tx.TxOut)))

	// 1 output will be to the destination, the others will be to change address
	utxos := make([]*Utxo, len(tx.TxOut)-1)

	i := 0
	for index, txOut := range tx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, network)
		if err != nil {
			return nil, err
		}
		if addrs[0].EncodeAddress() == changeAddress {
			sdk.Log(fmt.Sprintf("utxo amt to change address: %d", txOut.Value))
			utxo := Utxo{
				TxId:     tx.TxID(),
				Vout:     uint32(index),
				Amount:   txOut.Value,
				PkScript: txOut.PkScript,
				Tag:      "",
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
