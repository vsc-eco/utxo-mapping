package mapping

import (
	"bytes"
	"contract-template/sdk"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func (cs *ContractState) HandleMap(txData *VerificationRequest) error {
	var totalMapped int64

	rawTx, err := hex.DecodeString(txData.RawTxHex)
	if err != nil {
		return err
	}
	proofBytes, err := hex.DecodeString(txData.MerkleProofHex)
	if err != nil {
		return err
	}
	if len(proofBytes)%32 != 0 {
		return errors.New("Invalid proof strcuture")
	}
	merkleProof := make([]chainhash.Hash, len(proofBytes)/32)
	for i := 0; i < len(proofBytes); i += 32 {
		merkleProof[i/32] = chainhash.Hash(proofBytes[i : i+32])
	}
	if err := verifyTransaction(txData, rawTx); err != nil {
		return err
	}

	var msgTx wire.MsgTx
	err = msgTx.Deserialize(bytes.NewReader(rawTx))
	if err != nil {
		return err
	}

	// removes this tx from utxo spends if present
	cs.updateUtxoSpends(msgTx.TxID())

	// gets all outputs the address of which is specified in the instructions
	relevantOutputs := *cs.indexOutputs(&msgTx)

	// create new utxos entries for all of the relevant outputs in the incoming transaction
	for _, utxo := range relevantOutputs {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(utxo.PkScript, &chaincfg.TestNet3Params)
		if err != nil {
			sdk.Abort(err.Error())
		}
		if metadata, ok := cs.AddressRegistry[addrs[0].EncodeAddress()]; ok {
			// Create UTXO entry
			utxoKey := fmt.Sprintf("%s:%d", utxo.TxId, utxo.Vout)
			cs.Utxos[utxoKey] = &utxo
			cs.ObservedTxs[utxoKey] = true

			// increment balance for recipient account (vsc account not btc account)
			cs.Balances[metadata.VscAddress] += utxo.Amount

			totalMapped += utxo.Amount
		}
	}

	if totalMapped != 0 {
		cs.Supply.ActiveSupply += totalMapped
		cs.Supply.UserSupply += totalMapped
	}

	return nil
}

// Returns: raw tx hex to be broadcast
func (cs *ContractState) HandleUnmap(instructions *UnmappingInputData) string {
	amount := instructions.Amount
	senderVscAddr := sdk.GetEnv().Sender.Address.String()
	senderBalance := cs.Balances[senderVscAddr]
	if senderBalance < amount {
		sdk.Abort(fmt.Sprintf("sender balance insufficient. has %d, needs %d", senderBalance, amount))
	}
	vscFee, err := deductVscFee(amount)
	if err != nil {
		sdk.Abort(err.Error())
	}
	postFeeAmount := amount - vscFee
	inputUtxos, totalInputAmt, err := cs.getInputUtxos(postFeeAmount)
	if err != nil {
		sdk.Abort(fmt.Sprintf("error getting input utxos: %w", err))
	}
	changeAddress, _, err := createP2WSHAddress(cs.PublicKey, nil, &chaincfg.TestNet3Params)
	signingData, tx, err := cs.createSpendTransaction(
		inputUtxos,
		totalInputAmt,
		instructions.RecipientBtcAddress,
		changeAddress,
		postFeeAmount,
	)
	if err != nil {
		sdk.Abort(err.Error())
	}

	unconfirmedUtxos, err := indexUnconfimedOutputs(tx, changeAddress)
	if err != nil {
		sdk.Abort(err.Error())
	}
	for _, utxo := range unconfirmedUtxos {
		// create utxo entry
		utxoKey := fmt.Sprintf("%s:%d", utxo.TxId, utxo.Vout)
		cs.Utxos[utxoKey] = &utxo
	}

	cs.TxSpends[tx.TxID()] = signingData
	cs.Balances[senderVscAddr] -= amount
	cs.Supply.ActiveSupply -= postFeeAmount
	cs.Supply.UserSupply -= amount
	cs.Supply.FeeSupply += vscFee

	return "success"
}

func (cs *ContractState) HandleTrasfer(instructions *TransferInputData) {
	amount := instructions.Amount
	senderVscAddr := sdk.GetEnv().Sender.Address.String()
	senderBalance := cs.Balances[senderVscAddr]
	if senderBalance < amount {
		sdk.Abort(fmt.Sprintf("sender balance insufficient. has %d, needs %d", senderBalance, amount))
	}
	cs.Balances[sdk.GetEnv().Sender.Address.String()] -= amount
	cs.Balances[instructions.RecipientVscAddress] += amount
}
