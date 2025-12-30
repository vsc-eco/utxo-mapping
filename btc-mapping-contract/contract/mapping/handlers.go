package mapping

import (
	"bytes"
	"contract-template/sdk"
	"encoding/hex"
	"fmt"
	"slices"

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

	// gets all outputs the address of which is specified in the instructions
	relevantOutputs, err := ms.indexOutputs(&msgTx)
	if err != nil {
		return fmt.Errorf("error indexing outputs: %w", err)
	}

	// removes this tx from utxo spends if present
	ms.updateUtxoSpends(msgTx.TxID())

	_, _, err = ms.processUtxos(relevantOutputs)
	if err != nil {
		return fmt.Errorf("error processing utxos: %w", err)
	}

	return nil
}

// Returns: raw tx hex to be broadcast
func (cs *ContractState) HandleUnmap(instructions *UnmappingInputData) error {
	amount := instructions.Amount
	env := sdk.GetEnv()

	vscFee, err := calcVscFee(amount)
	if err != nil {
		return err
	}

	sdk.Log(fmt.Sprintf("vsc fee: %d SATS", vscFee))

	inputUtxoIds, totalInputAmt, err := cs.getInputUtxoIds(amount)
	if err != nil {
		return fmt.Errorf("error getting input utxos: %w", err)
	}

	sdk.Log(fmt.Sprintf("inputids: %v, totalinputamt: %d", inputUtxoIds, totalInputAmt))

	inputUtxos, err := getInputUtxos(inputUtxoIds)
	if err != nil {
		return fmt.Errorf("error getting input utxos: %w", err)
	}

	changeAddress, _, err := createP2WSHAddressWithBackup(
		cs.PublicKeys.PrimaryPubKey,
		cs.PublicKeys.BackupPubKey,
		nil,
		cs.NetworkParams,
	)
	signingData, tx, btcFee, err := cs.createSpendTransaction(
		inputUtxos,
		totalInputAmt,
		instructions.RecipientBtcAddress,
		changeAddress,
		amount,
	)
	if err != nil {
		return err
	}

	sdk.Log(fmt.Sprintf("btc fee: %d SATS", btcFee))

	finalAmt := amount + vscFee + btcFee

	// check whether sender has enough balance to cover transaction
	senderBal, err := checkSender(env, finalAmt)
	if err != nil {
		return err
	}

	unconfirmedUtxos, err := indexUnconfimedOutputs(tx, changeAddress, cs.NetworkParams)
	if err != nil {
		return err
	}
	for _, utxo := range unconfirmedUtxos {
		utxoJson, err := tinyjson.Marshal(utxo)
		if err != nil {
			return fmt.Errorf("error marhalling utxo json: %w", err)
		}
		// create utxo entry
		internalId := cs.UtxoNextId
		cs.UtxoNextId++

		utxoLookup := packUtxo(internalId, utxo.Amount, 0)

		// sdk.Log(fmt.Sprintf("appending utxo with internal id: %d, amount: %d", internalId, utxo.Amount))
		cs.UtxoList = append(cs.UtxoList, utxoLookup)
		sdk.StateSetObject(fmt.Sprintf("%s%x", utxoPrefix, internalId), string(utxoJson))
	}

	for _, inputId := range inputUtxoIds {
		cs.UtxoList = slices.DeleteFunc(
			cs.UtxoList,
			func(utxo [3]int64) bool { return int64(inputId) == utxo[0] },
		)
		sdk.StateDeleteObject(fmt.Sprintf("%s%x", utxoPrefix, inputId))
	}

	signingDataJson, err := tinyjson.Marshal(signingData)
	if err != nil {
		return fmt.Errorf("error marshalling signing data: %w", err)
	}

	// use this key, then increment
	sdk.StateSetObject(txSpendsPrefix+tx.TxID(), string(signingDataJson))
	cs.TxSpendsList = append(cs.TxSpendsList, tx.TxID())

	setAccBal(env.Sender.Address.String(), senderBal-finalAmt)

	cs.Supply.ActiveSupply -= finalAmt
	cs.Supply.UserSupply -= finalAmt
	cs.Supply.FeeSupply += vscFee

	return nil
}

func HandleTrasfer(instructions *TransferInputData) error {
	amount := instructions.Amount
	env := sdk.GetEnv()
	senderBal, err := checkSender(env, amount)
	if err != nil {
		return err
	}

	recipientBal, err := getAccBal(instructions.RecipientVscAddress)
	if err != nil {
		return err
	}

	setAccBal(env.Sender.Address.String(), senderBal-amount)
	setAccBal(instructions.RecipientVscAddress, recipientBal+amount)

	return nil
}
