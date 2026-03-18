package mapping

import (
	"bch-mapping-contract/contract/constants"
	"bch-mapping-contract/sdk"
	"bytes"
	"encoding/hex"
	"slices"
	"strconv"

	"github.com/btcsuite/btcd/wire"

	ce "bch-mapping-contract/contract/contracterrors"
)

const MaxMerkleProofLength = 33 // 2^33 blocks > total BTC supply

func (ms *MappingState) HandleMap(txData *VerificationRequest) error {
	rawTx, err := hex.DecodeString(txData.RawTxHex)
	if err != nil {
		return ce.WrapContractError("", err)
	}
	if err := verifyTransaction(txData, rawTx); err != nil {
		return ce.Prepend(err, "error verifying tranasction")
	}

	var msgTx wire.MsgTx
	err = msgTx.Deserialize(bytes.NewReader(rawTx))
	if err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "could not construct BTC transaction from input")
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
	err = ms.processUtxos(relevantOutputs, senderLabel(msgTx.TxIn, ms.NetworkParams))
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

	// Preliminary balance check before expensive UTXO selection and TSS signing
	prelimBal := getAccBal(env.Caller.String())
	prelimRequired, err := safeAdd64(amount, vscFee)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error computing preliminary required amount")
	}
	if prelimBal < prelimRequired {
		return ce.NewContractError(
			ce.ErrBalance,
			"caller balance "+strconv.FormatInt(
				prelimBal,
				10,
			)+" insufficient for amount+fee "+strconv.FormatInt(
				prelimRequired,
				10,
			),
		)
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
		cs.PublicKeys.Primary,
		cs.PublicKeys.Backup,
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

	// check whether caller has enough balance to cover transaction
	err = checkAndDeductBalance(env, env.Caller.String(), finalAmt)
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
	sdk.Log(createUnmapLog(tx.TxID()))

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

// HandleApprove sets the spending allowance for spender to spend owner's tokens.
func HandleApprove(owner, spender string, amount int64) {
	setAllowance(owner, spender, amount)
}

// HandleIncreaseAllowance increases spender's allowance by amount.
func HandleIncreaseAllowance(owner, spender string, amount int64) error {
	current := getAllowance(owner, spender)
	newAmount, err := safeAdd64(current, amount)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "overflow increasing allowance")
	}
	setAllowance(owner, spender, newAmount)
	return nil
}

// HandleDecreaseAllowance decreases spender's allowance by amount; reverts if it would go below zero.
func HandleDecreaseAllowance(owner, spender string, amount int64) error {
	current := getAllowance(owner, spender)
	newAmount, err := safeSubtract64(current, amount)
	if err != nil || newAmount < 0 {
		return ce.NewContractError(ce.ErrArithmetic, "allowance cannot go below zero")
	}
	setAllowance(owner, spender, newAmount)
	return nil
}

// HandleConfirmSpend confirms a pending spend transaction by promoting its
// unconfirmed change UTXOs to the confirmed pool. Called by the bot/oracle
// when a withdrawal transaction is confirmed on the Bitcoin network.
func (cs *ContractState) HandleConfirmSpend(txId string) error {
	return cs.updateUtxoSpends(txId)
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

	if sdk.VerifyAddress(instructions.To) == "unknown" {
		return ce.NewContractError(ce.ErrInput, "invalid recipient address")
	}

	from := instructions.From
	if from == "" {
		from = env.Caller.String()
	}
	err = checkAndDeductBalance(env, from, amount)
	if err != nil {
		return err
	}

	recipientBal := getAccBal(instructions.To)

	newBal, err := safeAdd64(recipientBal, amount)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error incremting user balance")
	}
	setAccBal(instructions.To, newBal)

	return nil
}
