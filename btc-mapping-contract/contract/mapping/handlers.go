package mapping

import (
	"bytes"
	"contract-template/sdk"
	"encoding/hex"
	"fmt"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func (ms *MappingState) HandleMap(txData *VerificationRequest) error {
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
	relevantOutputs := ms.indexOutputs(&msgTx)

	ms.processUtxos(relevantOutputs)

	return nil
}

// Returns: raw tx hex to be broadcast
func (cs *ContractState) HandleUnmap(instructions *UnmappingInputData) string {
	amount := instructions.Amount
	env := sdk.GetEnv()

	senderBal, err := checkSender(env, amount)
	if err != nil {
		sdk.Abort(err.Error())
	}

	vscFee, err := deductVscFee(amount)
	if err != nil {
		sdk.Abort(err.Error())
	}

	postFeeAmount := amount - vscFee
	inputUtxoIds, totalInputAmt, err := cs.getInputUtxoIds(postFeeAmount)
	if err != nil {
		sdk.Abort(fmt.Sprintf("error getting input utxos: %w", err))
	}

	inputUtxos, err := getInputUtxos(inputUtxoIds)
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
		internalId := cs.UtxoLastId
		cs.UtxoLastId++

		utxoLookup := packUtxo(internalId, utxo.Amount, 0)
		cs.UtxoList = append(cs.UtxoList, utxoLookup)
	}

	signingDataJson, err := tinyjson.Marshal(signingData)
	if err != nil {
		sdk.Abort(fmt.Sprintf("error marshalling signing data: %s", err.Error()))
	}

	// use this key, then increment
	sdk.StateSetObject(txSpendsPrefix+tx.TxID(), string(signingDataJson))
	cs.TxSpendsList = append(cs.TxSpendsList, tx.TxID())

	setAccBal(env.Sender.Address.String(), senderBal-amount)

	cs.Supply.ActiveSupply -= postFeeAmount
	cs.Supply.UserSupply -= amount
	cs.Supply.FeeSupply += vscFee

	return "success"
}

func HandleTrasfer(instructions *TransferInputData) {
	amount := instructions.Amount
	env := sdk.GetEnv()
	senderBal, err := checkSender(env, amount)
	if err != nil {
		sdk.Abort(err.Error())
	}

	recipientBal, err := getAccBal(instructions.RecipientVscAddress)
	if err != nil {
		sdk.Abort(err.Error())
	}

	setAccBal(env.Sender.Address.String(), senderBal-amount)
	setAccBal(instructions.RecipientVscAddress, recipientBal+amount)
}
