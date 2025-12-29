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

	// removes this tx from utxo spends if present
	ms.updateUtxoSpends(msgTx.TxID())

	// gets all outputs the address of which is specified in the instructions
	relevantOutputs := ms.indexOutputs(&msgTx)

	ms.processUtxos(relevantOutputs)

	return nil
}

// Returns: raw tx hex to be broadcast
func (cs *ContractState) HandleUnmap(instructions *UnmappingInputData) (uint8, error) {
	amount := instructions.Amount
	env := sdk.GetEnv()

	vscFee, err := calcVscFee(amount)
	if err != nil {
		return 1, err
	}
	vscCoverRequired := amount + vscFee

	senderBal, err := checkSender(env, amount)
	if err != nil {
		return 1, err
	}

	inputUtxoIds, totalInputAmt, err := cs.getInputUtxoIds(amount)
	if err != nil {
		sdk.Abort(fmt.Sprintf("error getting input utxos: %s", err.Error()))
	}

	inputUtxos, err := getInputUtxos(inputUtxoIds)
	if err != nil {
		sdk.Abort(fmt.Sprintf("error getting input utxos: %s", err.Error()))
	}

	changeAddress, _, err := createP2WSHAddressWithBackup(
		cs.PublicKeys.PrimaryPubKey,
		cs.PublicKeys.BackupPubKey,
		nil,
		cs.NetworkParams,
	)
	signingData, tx, err := cs.createSpendTransaction(
		inputUtxos,
		totalInputAmt,
		instructions.RecipientBtcAddress,
		changeAddress,
		vscCoverRequired,
	)

	if err != nil {
		return 1, err
	}

	unconfirmedUtxos, err := indexUnconfimedOutputs(tx, changeAddress, cs.NetworkParams)
	if err != nil {
		return 1, err
	}
	for _, utxo := range unconfirmedUtxos {
		utxoJson, err := tinyjson.Marshal(utxo)
		if err != nil {
			return 1, fmt.Errorf("error marhalling utxo json: %w", err)
		}
		// create utxo entry
		internalId := cs.UtxoLastId
		cs.UtxoLastId++

		utxoLookup := packUtxo(internalId, utxo.Amount, 0)

		sdk.Log(fmt.Sprintf("appending utxo with internal id: %d, amount: %d", internalId, utxo.Amount))
		cs.UtxoList = append(cs.UtxoList, utxoLookup)
		sdk.StateSetObject(fmt.Sprintf("%s%x", utxoPrefix, internalId), string(utxoJson))
	}

	for _, inputId := range inputUtxoIds {
		cs.UtxoList = slices.DeleteFunc(
			cs.UtxoList,
			func(ss [3]int64) bool { return int64(inputId) == ss[0] },
		)
		sdk.StateDeleteObject(fmt.Sprintf("%s%x", utxoPrefix, inputId))
	}

	signingDataJson, err := tinyjson.Marshal(signingData)
	if err != nil {
		return 1, fmt.Errorf("error marshalling signing data: %w", err)
	}

	// use this key, then increment
	sdk.StateSetObject(txSpendsPrefix+tx.TxID(), string(signingDataJson))
	cs.TxSpendsList = append(cs.TxSpendsList, tx.TxID())

	setAccBal(env.Sender.Address.String(), senderBal-amount)

	cs.Supply.ActiveSupply -= vscCoverRequired
	cs.Supply.UserSupply -= amount
	cs.Supply.FeeSupply += vscFee

	return 0, nil
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
