package mapping

import (
	"bytes"
	"contract-template/sdk"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func (cs *ContractState) HandleMap(rawTxHex *string, proofHex *string, instructionsString *string) error {
	var totalMapped uint64

	rawTx, err := hex.DecodeString(*rawTxHex)
	if err != nil {
		return err
	}
	proof, err := hex.DecodeString(*proofHex)
	if err != nil {
		return err
	}
	verifyProof(&proof)
	// TODO: create from instruction string once format is known
	cs.setInstructions(instructionsString)

	var msgTx wire.MsgTx
	err = msgTx.Deserialize(bytes.NewReader(rawTx))
	if err != nil {
		return err
	}

	// gets all outputs the address of which is specified in the instructions
	relevantOutputs := *cs.indexOutputs(&msgTx)

	// create new utxos entries for all of the relevant outputs in the incoming transaction
	for _, utxo := range relevantOutputs {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(utxo.pkScript, &chaincfg.TestNet3Params)
		if err != nil {
			sdk.Abort(err.Error())
		}
		if vscAddress, ok := cs.getInternalAddressForBitcoinAddress(addrs[0].EncodeAddress()); ok {
			// Create UTXO entry
			utxoKey := fmt.Sprintf("%s:%d", utxo.txId, utxo.vout)
			cs.utxos[utxoKey] = utxo
			cs.observedTxs[utxoKey] = true

			// increment balance for recipient account (vsc account not btc account)
			balance := cs.balances[vscAddress]
			balance += uint64(utxo.amount)
			cs.balances[vscAddress] = balance

			totalMapped += uint64(utxo.amount)
		}
	}

	if totalMapped != 0 {
		cs.activeSupply += totalMapped
	}

	return nil
}

func (cs *ContractState) HandleUnmap(amount int64, destinationAddress string) {
	inputUtxos, totalInputAmt, err := cs.getInputUtxos(amount)
	if err != nil {
		sdk.Abort(err.Error())
	}
	signingData := cs.createSpendTransaction(inputUtxos)
}
