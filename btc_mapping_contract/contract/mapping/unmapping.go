package mapping

import (
	"errors"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func (cs *ContractState) createSpendTransaction(
	inputs []*Utxo,
	totalInputsAmount int64,
	destAddress string,
	changeAddress string,
	sendAmount int64,
) (*SigningData, error) {
	tx := wire.NewMsgTx(wire.TxVersion)

	for _, utxo := range inputs {
		txHash, err := chainhash.NewHashFromStr(utxo.txId)
		if err != nil {
			return nil, err
		}

		outPoint := wire.NewOutPoint(txHash, utxo.vout)
		txIn := wire.NewTxIn(outPoint, nil, nil)
		tx.AddTxIn(txIn)
	}

	destAddr, err := btcutil.DecodeAddress(destAddress, &chaincfg.TestNet3Params)
	if err != nil {
		return nil, err
	}

	// Create output script for destination
	destScript, err := txscript.PayToAddrScript(destAddr)
	if err != nil {
		return nil, err
	}

	txOut := wire.NewTxOut(sendAmount, destScript)
	tx.AddTxOut(txOut)

	basicFee := int64(tx.SerializeSize()) * cs.baseFeeRate

	totalChange := totalInputsAmount - sendAmount - basicFee

	// constants in sats
	const DUSTTHRESHOLD = 546
	// 0.01 BTC
	const SPLITTHRESHOLD = 1000000
	const MAXCHANGEOUTPUTS = 4

	// if change is not dust
	if totalChange > DUSTTHRESHOLD {
		// split if above SPLITTHRESHOLD, taking into account the added fee
		// for each split (about 34 bytes per output)
		changeOuputs := totalChange / (SPLITTHRESHOLD + 34*cs.baseFeeRate)
		if changeOuputs < 1 {
			changeOuputs = 1
		}
		if changeOuputs > MAXCHANGEOUTPUTS {
			changeOuputs = MAXCHANGEOUTPUTS
		}
		eachChangeAmount := (totalChange / changeOuputs) - 34*cs.baseFeeRate
		changeAddressObj, err := btcutil.DecodeAddress(changeAddress, &chaincfg.TestNet3Params)
		if err != nil {
			return nil, err
		}
		changePkScript, err := txscript.PayToAddrScript(changeAddressObj)
		if err != nil {
			return nil, err
		}

		for i := int64(0); i < changeOuputs; i++ {
			txOutChange := wire.NewTxOut(int64(eachChangeAmount), changePkScript)
			tx.AddTxOut(txOutChange)
		}
	}

	// P2WSH: Calculate witness sighash
	unsignedSignHashes := make([]UnsignedSigHash, len(inputs))
	for i, utxo := range inputs {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, &chaincfg.TestNet3Params)
		if err != nil {
			return nil, err
		}
		address := addrs[0].EncodeAddress()
		tag := cs.addressTagLookup[address]
		_, witnessScript, err := createP2WSHAddress(cs.publicKey, tag, &chaincfg.TestNet3Params)
		if err != nil {
			return nil, err
		}

		sigHashes := txscript.NewTxSigHashes(tx, txscript.NewCannedPrevOutputFetcher(utxo.pkScript, utxo.amount))

		sigHash, err := txscript.CalcWitnessSigHash(
			witnessScript,
			sigHashes,
			txscript.SigHashAll,
			tx,
			i,
			utxo.amount,
		)

		if err != nil {
			return nil, err
		}

		unsignedSignHashes[i] = UnsignedSigHash{
			index:         i,
			sigHash:       sigHash,
			witnessScript: witnessScript,
			amount:        utxo.amount,
		}
	}

	return &SigningData{
		Tx:                 tx,
		UnsignedSignHashes: unsignedSignHashes,
	}, nil
}

func (cs *ContractState) getInputUtxos(amount int64) ([]*Utxo, int64, error) {
	// approximate size of including a new PSWSH input (base tx size plus signature)
	// slight overestimate to make sure there's enough balance
	const P2WSHAPPROXINPUTSIZE = 40 + 1 + 260/4

	inputs := []*Utxo{}

	// base size (10 bytes) + size of 1 output (34 bytes)
	initialSize := int64(10 + 34)

	requiredAmount := initialSize * int64(cs.baseFeeRate)
	// assume the larger for first tx since this is just estimation

	// accumulates amount of all inputs
	accAmount := int64(0)

	// first loops, find first tx sufficient to cover spend
	for _, utxo := range cs.utxos {
		// calculates amount required to cover initial tx plus the addition of itself as an input
		wouldBeRequired := requiredAmount + P2WSHAPPROXINPUTSIZE
		// less than or equal
		if amount <= wouldBeRequired {
			return []*Utxo{&utxo}, utxo.amount, nil
		}
	}
	// second loop, only if first did not find anything
	// accumulate utxos until enough combined balance to cover spend
	// avoids unconfirmed txs
	unconfirmedTxs := []*Utxo{}
	for _, utxo := range cs.utxos {
		if utxo.confirmed {
			inputs = append(inputs, &utxo)
			accAmount += utxo.amount
			requiredAmount += P2WSHAPPROXINPUTSIZE
			// greater than or equal
			if accAmount >= requiredAmount {
				return inputs, accAmount, nil
			}
		} else {
			unconfirmedTxs = append(unconfirmedTxs, &utxo)
		}

	}
	// uses unconfirmed txs only if all confirmed txs are insufficient
	for _, utxo := range unconfirmedTxs {
		inputs = append(inputs, utxo)
		accAmount += utxo.amount
		if accAmount >= requiredAmount {
			return inputs, accAmount, nil
		}
	}
	// this really should never happen
	return nil, 0, errors.New("Total available balance insufficient to complete transaction.")
}
