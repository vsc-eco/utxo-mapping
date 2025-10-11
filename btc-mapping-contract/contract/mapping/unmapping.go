package mapping

import (
	"bytes"
	"contract-template/sdk"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func deductVscFee(amount int64) (int64, error) {
	const minFee int64 = 1000
	const feeRate float64 = 0.01
	percentageFee := int64(float64(amount) * feeRate)
	finalFee := minFee
	if percentageFee > minFee {
		finalFee = percentageFee
	}
	sdk.Log(fmt.Sprintf("amount: %d, finalFee: %d", amount, finalFee))
	if finalFee >= amount {
		return 0, errors.New("transaction too small to cover fee.")
	}
	return finalFee, nil
}

func (cs *ContractState) getInputUtxos(amount int64) ([]*Utxo, int64, error) {
	// approximate size of including a new PSWSH input (base tx size plus signature)
	// slight overestimate (+1 at the end) to make sure there's enough balance
	const P2WSHAPPROXINPUTSIZE = 40 + 1 + (72+68+3)/4 + 1

	inputs := []*Utxo{}

	// base size (10 bytes) + size of 1 output (34 bytes)
	initialSize := int64(10 + 34)

	// amount + basic fee
	requiredAmount := amount + initialSize*int64(cs.Supply.BaseFeeRate)
	// assume the larger for first tx since this is just estimation

	// accumulates amount of all inputs
	accAmount := int64(0)

	// first loops, find first tx sufficient to cover spend
	for _, utxo := range cs.Utxos {
		if !utxo.Confirmed {
			continue
		}
		// calculates amount required to cover initial tx plus the addition of itself as an input
		wouldBeRequired := requiredAmount + (P2WSHAPPROXINPUTSIZE * cs.Supply.BaseFeeRate)
		if utxo.Amount >= wouldBeRequired {
			return []*Utxo{utxo}, utxo.Amount, nil
		}
	}
	// second loop, only if first did not find anything
	// accumulate utxos until enough combined balance to cover spend
	// avoids unconfirmed txs
	unconfirmedTxs := []*Utxo{}
	for _, utxo := range cs.Utxos {
		if utxo.Confirmed {
			inputs = append(inputs, utxo)
			accAmount += utxo.Amount
			requiredAmount += (P2WSHAPPROXINPUTSIZE * cs.Supply.BaseFeeRate)
			// greater than or equal
			if accAmount >= requiredAmount {
				return inputs, accAmount, nil
			}
		} else {
			unconfirmedTxs = append(unconfirmedTxs, utxo)
		}

	}
	// uses unconfirmed txs only if all confirmed txs are insufficient
	for _, utxo := range unconfirmedTxs {
		inputs = append(inputs, utxo)
		accAmount += utxo.Amount
		requiredAmount += (P2WSHAPPROXINPUTSIZE * cs.Supply.BaseFeeRate)
		if accAmount >= requiredAmount {
			return inputs, accAmount, nil
		}
	}
	// this really should never happen
	return nil, 0, errors.New("Total available balance insufficient to complete transaction.")
}

func (cs *ContractState) calculatSegwitFee(baseSize int64, witnessScripts map[int][]byte) int64 {
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
) (*SigningData, *wire.MsgTx, error) {
	tx := wire.NewMsgTx(wire.TxVersion)

	// create all witness script now for better size estimation
	witnessScripts := make(map[int][]byte)
	for index, utxo := range inputs {
		txHash, err := chainhash.NewHashFromStr(utxo.TxId)
		if err != nil {
			return nil, nil, err
		}

		outPoint := wire.NewOutPoint(txHash, utxo.Vout)
		txIn := wire.NewTxIn(outPoint, nil, nil)
		tx.AddTxIn(txIn)

		_, addrs, _, err := txscript.ExtractPkScriptAddrs(utxo.PkScript, &chaincfg.TestNet3Params)
		if err != nil {
			return nil, nil, err
		}
		address := addrs[0].EncodeAddress()
		tag := cs.AddressRegistry[address].Tag
		tagBytes, err := hex.DecodeString(tag)
		if err != nil {
			return nil, nil, err
		}
		_, witnessScript, err := createP2WSHAddress(cs.PublicKey, tagBytes, &chaincfg.TestNet3Params)
		if err != nil {
			return nil, nil, err
		}
		witnessScripts[index] = witnessScript
	}

	destAddr, err := btcutil.DecodeAddress(destAddress, &chaincfg.TestNet3Params)
	if err != nil {
		return nil, nil, err
	}

	// Create output script for destination
	destScript, err := txscript.PayToAddrScript(destAddr)
	if err != nil {
		return nil, nil, err
	}

	destTxOut := wire.NewTxOut(sendAmount, destScript)
	tx.AddTxOut(destTxOut)

	baseSize := int64(tx.SerializeSize())
	fee := cs.calculatSegwitFee(baseSize, witnessScripts)

	totalChange := totalInputsAmount - sendAmount

	// constants in sats
	const DUSTTHRESHOLD = 546
	// 0.01 BTC
	const SPLITTHRESHOLD = 1000000
	const MAXCHANGEOUTPUTS = 4

	// if change is not dust
	if totalChange > DUSTTHRESHOLD {
		// split if above SPLITTHRESHOLD, taking into account the added fee
		// for each split (about 34 bytes per output)
		changeAddressObj, err := btcutil.DecodeAddress(changeAddress, &chaincfg.TestNet3Params)
		if err != nil {
			return nil, nil, err
		}
		changeScript, err := txscript.PayToAddrScript(changeAddressObj)
		if err != nil {
			return nil, nil, err
		}
		// create a dummy change ouput to calculate additional fee for adding change outputs
		changeOutputSize := int64(wire.NewTxOut(int64(0), changeScript).SerializeSize())

		numChangeOuputs := totalChange / SPLITTHRESHOLD
		if numChangeOuputs < 1 {
			numChangeOuputs = 1
		}
		if numChangeOuputs > MAXCHANGEOUTPUTS {
			numChangeOuputs = MAXCHANGEOUTPUTS
		}
		// recalculate the size/fee
		baseSize += numChangeOuputs * changeOutputSize
		fee = cs.calculatSegwitFee(baseSize, witnessScripts)

		eachChangeAmount := totalChange / numChangeOuputs

		for i := int64(0); i < numChangeOuputs; i++ {
			txOutChange := wire.NewTxOut(eachChangeAmount, changeScript)
			tx.AddTxOut(txOutChange)
		}
	}

	// modify the value of the destination amount to deduct the final fee
	tx.TxOut[0].Value = sendAmount - fee

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
			return nil, nil, err
		}

		unsignedSigHashes[i] = UnsignedSigHash{
			Index:         uint32(i),
			SigHash:       sigHash,
			WitnessScript: witnessScript,
		}
	}

	var buf bytes.Buffer
	err = tx.Serialize(&buf)
	if err != nil {
		return nil, nil, err
	}
	txHex := hex.EncodeToString(buf.Bytes())

	return &SigningData{
		Tx:                txHex,
		UnsignedSigHashes: unsignedSigHashes,
	}, tx, nil
}

func attachSignatures(tx *wire.MsgTx, signingData *SigningData, signatures map[uint32][]byte) {
	for _, inputData := range signingData.UnsignedSigHashes {
		signature := signatures[inputData.Index]

		witness := wire.TxWitness{
			signature,
			inputData.WitnessScript,
		}

		tx.TxIn[inputData.Index].Witness = witness
	}
}

func indexUnconfimedOutputs(tx *wire.MsgTx) []Utxo {
	utxos := make([]Utxo, len(tx.TxOut))
	for index, txOut := range tx.TxOut {
		utxo := Utxo{
			TxId:      tx.TxID(),
			Vout:      uint32(index),
			Amount:    txOut.Value,
			PkScript:  txOut.PkScript,
			Confirmed: false,
		}
		utxos = append(utxos, utxo)
	}
	return utxos
}
