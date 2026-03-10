package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"slices"
	"strconv"
)

const MaxMerkleProofLength = 33 // 2^33 blocks > total BTC supply

// Returns: raw tx hex to be broadcast
func (cs *ContractState) HandleUnmap(instructions *TransferParams) error {
	env := sdk.GetEnv()
	err := checkAuth(env)
	if err != nil {
		return err
	}
	amount, err := strconv.ParseInt(instructions.Amount, 10, 64)
	if err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "invalid amount value")
	}
	if amount <= 0 {
		return ce.NewContractError(ce.ErrInput, "amount must be positive")
	}

	vscFee, err := calcVscFee(amount)
	if err != nil {
		return err
	}

	inputUtxoIds, totalInputAmt, err := cs.getInputUtxoIds(amount)
	if err != nil {
		return ce.Prepend(err, "error getting input utxos")
	}

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

	finalAmt := amount + vscFee + btcFee

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
		internalId, err := cs.allocateUnconfirmedId()
		if err != nil {
			return err
		}
		cs.UtxoList = append(cs.UtxoList, UtxoRegistryEntry{Id: internalId, Amount: utxo.Amount})
		saveUtxo(internalId, utxo)
	}

	for _, inputId := range inputUtxoIds {
		cs.UtxoList = slices.DeleteFunc(
			cs.UtxoList,
			func(entry UtxoRegistryEntry) bool { return entry.Id == inputId },
		)
		sdk.StateDeleteObject(getUtxoKey(inputId))
	}

	signingDataBytes, err := MarshalSigningData(signingData)
	if err != nil {
		return ce.WrapContractError(ce.ErrJson, err, "error marshalling signing data")
	}

	sdk.StateSetObject(constants.TxSpendsPrefix+tx.TxID(), string(signingDataBytes))
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
	amount, err := strconv.ParseInt(instructions.Amount, 10, 64)
	if err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "invalid amount value")
	}
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
		return ce.NewContractError(
			ce.ErrInput,
			"must transfer from caller ["+env.Caller.String()+
				"] or sender ["+env.Sender.Address.String()+
				" ] got ["+instructions.From+"]",
		)
	}

	recipientBal := getAccBal(instructions.To)

	newBal, err := safeAdd64(recipientBal, amount)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error incremting user balance")
	}
	setAccBal(instructions.To, newBal)

	return nil
}
