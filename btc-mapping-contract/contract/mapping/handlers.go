package mapping

import (
	"bytes"
	"contract-template/sdk"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func (ms *MappingState) HandleMap(txData *VerificationRequest) error {
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
		return fmt.Errorf("Invalid proof strcuture")
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
	ms.updateUtxoSpends(msgTx.TxID())

	// gets all outputs the address of which is specified in the instructions
	relevantOutputs := *ms.indexOutputs(&msgTx)

	// create new utxos entries for all of the relevant outputs in the incoming transaction
	for _, utxo := range relevantOutputs {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(utxo.PkScript, ms.NetworkParams)
		if err != nil {
			sdk.Abort(err.Error())
		}
		if metadata, ok := ms.AddressRegistry[addrs[0].EncodeAddress()]; ok {
			// Create UTXO entry
			utxoKey := fmt.Sprintf("%s:%d", utxo.TxId, utxo.Vout)
			ms.Utxos[utxoKey] = &utxo
			ms.ObservedTxs[utxoKey] = true

			// increment balance for recipient account (vsc account not btc account)
			ms.Balances[metadata.VscAddress] += utxo.Amount

			totalMapped += utxo.Amount
		}
	}

	if totalMapped != 0 {
		ms.Supply.ActiveSupply += totalMapped
		ms.Supply.UserSupply += totalMapped
	}

	return nil
}

// Returns: raw tx hex to be broadcast
func (cs *ContractState) HandleUnmap(instructions *UnmappingInputData) string {
	amount := instructions.Amount
	env := sdk.GetEnv()

	err := checkSender(env, amount, cs.Balances)
	if err != nil {
		sdk.Abort(err.Error())
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
	changeAddress, _, err := createP2WSHAddress(cs.PublicKey, nil, cs.NetworkParams)
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

	unconfirmedUtxos, err := indexUnconfimedOutputs(tx, changeAddress, cs.NetworkParams)
	if err != nil {
		sdk.Abort(err.Error())
	}
	for _, utxo := range unconfirmedUtxos {
		// create utxo entry
		utxoKey := fmt.Sprintf("%s:%d", utxo.TxId, utxo.Vout)
		cs.Utxos[utxoKey] = &utxo
	}

	cs.TxSpends[tx.TxID()] = signingData
	cs.Balances[env.Sender.Address.String()] -= amount
	cs.Supply.ActiveSupply -= postFeeAmount
	cs.Supply.UserSupply -= amount
	cs.Supply.FeeSupply += vscFee

	return "success"
}

func HandleTrasfer(instructions *TransferInputData, balances AccountBalanceMap) {
	amount := instructions.Amount
	env := sdk.GetEnv()
	err := checkSender(env, amount, balances)
	if err != nil {
		sdk.Abort(err.Error())
	}
	balances[env.Sender.Address.String()] -= amount
	balances[instructions.RecipientVscAddress] += amount
	// cs.Balances[instructions.RecipientVscAddress] = bal + amount
}
