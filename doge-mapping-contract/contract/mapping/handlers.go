package mapping

import (
	"doge-mapping-contract/contract/constants"
	"doge-mapping-contract/sdk"
	"bytes"
	"encoding/hex"
	"slices"
	"strconv"

	"github.com/btcsuite/btcd/wire"

	ce "doge-mapping-contract/contract/contracterrors"
)

const MaxMerkleProofLength = 33 // 2^33 blocks > total BTC supply

func (ms *MappingState) HandleMap(txData *VerificationRequest) error {
	rawTx, err := hex.DecodeString(txData.RawTxHex)
	if err != nil {
		return ce.WrapContractError(ce.ErrInvalidHex, err, "error decoding raw transaction hex")
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
	var prelimRequired int64
	if instructions.DeductFee {
		prelimRequired = amount
	} else {
		prelimRequired, err = safeAdd64(amount, vscFee)
		if err != nil {
			return ce.WrapContractError(ce.ErrArithmetic, err, "error computing preliminary required amount")
		}
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

	// When deducting fees from amount, UTXOs need to cover (amount - vscFee),
	// since sendAmount + btcFee = amount - vscFee.
	utxoSelectionAmount := amount
	if instructions.DeductFee {
		utxoSelectionAmount, err = safeSubtract64(amount, vscFee)
		if err != nil || utxoSelectionAmount <= 0 {
			return ce.NewContractError(ce.ErrBalance, "amount too small to cover vsc fee")
		}
	}

	inputUtxoIds, totalInputAmt, err := cs.getInputUtxoIds(utxoSelectionAmount)
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
	// When deduct_fee=true, estimate btcFee to derive the send amount so that
	// vscFee + btcFee + sendAmount ≈ amount. The actual fee from
	// createSpendTransaction may differ slightly; any discrepancy is absorbed
	// by the change output.
	sendAmount := amount
	if instructions.DeductFee {
		btcFeeEst := cs.estimateFee(int64(len(inputUtxoIds)), utxoSelectionAmount, totalInputAmt)
		sendAmount, err = safeSubtract64(utxoSelectionAmount, btcFeeEst)
		if err != nil || sendAmount <= dustThreshold {
			return ce.NewContractError(ce.ErrBalance, "amount too small to cover fees")
		}
	}

	signingData, tx, btcFee, err := cs.createSpendTransaction(
		inputUtxos,
		totalInputAmt,
		instructions.To,
		changeAddress,
		sendAmount,
	)
	if err != nil {
		return err
	}

	sdk.Log(createFeeLog(vscFee, btcFee))

	var finalAmt int64
	if instructions.DeductFee {
		finalAmt = amount
	} else {
		finalAmt, err = safeAdd64(amount, vscFee)
		if err != nil {
			return ce.WrapContractError(ce.ErrArithmetic, err, "error computing final amount")
		}
		finalAmt, err = safeAdd64(finalAmt, btcFee)
		if err != nil {
			return ce.WrapContractError(ce.ErrArithmetic, err, "error computing final amount")
		}
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
// when a withdrawal transaction is confirmed on the Dogecoin network.
//
// SECURITY: This function performs no cryptographic verification of the transaction.
// Access control is enforced by the caller (main.go ConfirmSpend) via checkAdmin().
// Unlike the BTC contract which requires an SPV Merkle proof, alt-chain confirmSpend
// relies on oracle trust.
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
		return ce.WrapContractError(ce.ErrArithmetic, err, "error incrementing user balance")
	}
	setAccBal(instructions.To, newBal)

	return nil
}
