package mapping

import (
	"ltc-mapping-contract/sdk"
	"bytes"
	"encoding/hex"
	"slices"
	"strconv"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/wire"

	ce "ltc-mapping-contract/contract/contracterrors"
)

func (ms *MappingState) HandleMap(txData *VerificationRequest) error {
	rawTx, err := hex.DecodeString(txData.RawTxHex)
	if err != nil {
		return ce.WrapContractError("", err)
	}
	if err := verifyTransaction(txData, rawTx); err != nil {
		return err
	}

	var msgTx wire.MsgTx
	err = msgTx.Deserialize(bytes.NewReader(rawTx))
	if err != nil {
		return err
	}

	// gets all outputs the address of which is specified in the deposit instructions
	relevantOutputs, err := ms.indexOutputs(&msgTx)
	if err != nil {
		return ce.Prepend(err, "error indexing outputs")
	}

	// removes this tx from utxo spends if present
	if err := ms.updateUtxoSpends(msgTx.TxID()); err != nil {
		return ce.Prepend(err, "error updating utxo spends")
	}

	// TODO: return mapping results for each relevenat address as part of contract output, or at least log them
	err = ms.processUtxos(relevantOutputs)
	if err != nil {
		return err
	}

	return nil
}

// Returns: raw tx hex to be broadcast
func (cs *ContractState) HandleUnmap(instructions *TransferParams) error {
	env := sdk.GetEnv()
	err := checkAuth(env)
	if err != nil {
		return err
	}
	amount := instructions.Amount
	if amount <= 0 {
		return ce.NewContractError(ce.ErrInput, "amount must be positive")
	}

	vscFee, err := calcVscFee(amount)
	if err != nil {
		return err
	}

	// Preliminary balance check before expensive UTXO selection and TSS signing
	prelimBal, err := getAccBal(env.Sender.Address.String())
	if err != nil {
		return ce.NewContractError(ce.ErrStateAccess, "could not fetch sender balance")
	}
	prelimRequired, err := safeAdd64(amount, vscFee)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error computing preliminary required amount")
	}
	if prelimBal < prelimRequired {
		return ce.NewContractError(ce.ErrBalance,
			"sender balance "+strconv.FormatInt(prelimBal, 10)+" insufficient for amount+fee "+strconv.FormatInt(prelimRequired, 10),
		)
	}

	inputUtxoIds, totalInputAmt, err := cs.getInputUtxoIds(amount)
	if err != nil {
		return ce.Prepend(err, "error getting input utxos")
	}

	// sdk.Log(fmt.Sprintf("inputids: %v, totalinputamt: %d", inputUtxoIds, totalInputAmt))

	inputUtxos, err := getInputUtxos(inputUtxoIds)
	if err != nil {
		return ce.Prepend(err, "error getting input utxos")
	}

	changeAddress, _, err := createP2WSHAddressWithBackup(
		cs.PublicKeys.PrimaryPubKey,
		cs.PublicKeys.BackupPubKey,
		nil,
		cs.NetworkParams,
	)
	if err != nil {
		return ce.WrapContractError(ce.ErrTransaction, err, "error creating change address")
	}
	signingData, tx, btcFee, err := cs.createSpendTransaction(
		inputUtxos,
		totalInputAmt,
		instructions.To,
		changeAddress,
		amount,
	)
	if err != nil {
		return err
	}

	sdk.Log(createFeeLog(vscFee, btcFee))

	finalAmt, err := safeAdd64(amount, vscFee)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error computing final amount")
	}
	finalAmt, err = safeAdd64(finalAmt, btcFee)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error computing final amount")
	}

	// check whether sender has enough balance to cover transaction
	err = checkAndDeductBalance(env, env.Sender.Address.String(), finalAmt)
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
			return ce.WrapContractError(ce.ErrJson, err, "error marhalling utxo")
		}
		// create utxo entry
		internalId := cs.UtxoNextId
		cs.UtxoNextId++

		utxoLookup := packUtxo(internalId, utxo.Amount, 0)

		// sdk.Log(fmt.Sprintf("appending utxo with internal id: %d, amount: %d", internalId, utxo.Amount))
		cs.UtxoList = append(cs.UtxoList, utxoLookup)
		sdk.StateSetObject(UtxoPrefix+strconv.FormatUint(uint64(internalId), 16), string(utxoJson))
	}

	for _, inputId := range inputUtxoIds {
		cs.UtxoList = slices.DeleteFunc(
			cs.UtxoList,
			func(utxo [3]int64) bool { return int64(inputId) == utxo[0] },
		)
		sdk.StateDeleteObject(getUtxoKey(inputId))
	}

	signingDataJson, err := tinyjson.Marshal(signingData)
	if err != nil {
		return ce.WrapContractError(ce.ErrJson, err, "error marshalling signing data")
	}

	// use this key, then increment
	sdk.StateSetObject(TxSpendsPrefix+tx.TxID(), string(signingDataJson))
	cs.TxSpendsList = append(cs.TxSpendsList, tx.TxID())

	// update supply
	newActive, err := safeSubtract64(cs.Supply.ActiveSupply, finalAmt)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error decrementing active supply")
	}
	cs.Supply.ActiveSupply = newActive

	newUser, err := safeSubtract64(cs.Supply.UserSupply, finalAmt)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error decrementing user supply")
	}
	cs.Supply.UserSupply = newUser

	newFee, err := safeAdd64(cs.Supply.FeeSupply, vscFee)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error incrementing fee supply")
	}
	cs.Supply.FeeSupply = newFee

	return nil
}

// handles a transfer where funds are drawn from the caller
func HandleTransfer(instructions *TransferParams) error {
	env := sdk.GetEnv()
	err := checkAuth(env)
	if err != nil {
		return err
	}
	amount := instructions.Amount
	if amount <= 0 {
		return ce.NewContractError(ce.ErrInput, "amount must be positive")
	}

	recipientAddress := sdk.Address(instructions.To)
	if !recipientAddress.IsValid() {
		return ce.NewContractError(ce.ErrInput, "invalid recipient address")
	}

	switch instructions.From {
	case "":
		fallthrough
	case env.Caller.String():
		err = checkAndDeductBalance(env, env.Caller.String(), amount)
		if err != nil {
			return err
		}
	case env.Sender.Address.String():
		err = checkAndDeductBalance(env, env.Sender.Address.String(), amount)
		if err != nil {
			return err
		}
	default:
		return ce.NewContractError(ce.ErrInput, "must transfer from caller or sender")
	}

	recipientBal, err := getAccBal(instructions.To)
	if err != nil {
		return err
	}

	newBal, err := safeAdd64(recipientBal, amount)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error incremting user balance")
	}
	setAccBal(instructions.To, newBal)

	return nil
}
