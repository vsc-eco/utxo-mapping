package mapping

import (
	"dash-mapping-contract/contract/constants"
	"dash-mapping-contract/sdk"
	"bytes"
	"encoding/hex"
	"slices"
	"strconv"

	"github.com/btcsuite/btcd/wire"

	ce "dash-mapping-contract/contract/contracterrors"
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
	err = ms.processUtxos(relevantOutputs, senderLabel(msgTx.TxIn, ms.NetworkParams), txData.BlockHeight)
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
	if amount <= dustThreshold {
		return ce.NewContractError(ce.ErrInput, "amount below dust threshold")
	}

	vscFee, err := calcVscFee(amount)
	if err != nil {
		return err
	}

	from := instructions.From
	if from == "" {
		from = env.Caller.String()
	}

	// Preliminary balance check before expensive UTXO selection and TSS signing
	prelimBal := getAccBal(from)
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
		btcFeeEst, err := cs.estimateFee(int64(len(inputUtxoIds)), utxoSelectionAmount, totalInputAmt)
		if err != nil {
			return err
		}
		sendAmount, err = safeSubtract64(utxoSelectionAmount, btcFeeEst)
		if err != nil || sendAmount <= dustThreshold {
			return ce.NewContractError(ce.ErrBalance, "amount too small to cover fees")
		}
	}

	tx, witnessScripts, btcFee, err := cs.buildSpendTransaction(
		inputUtxos,
		totalInputAmt,
		instructions.To,
		changeAddress,
		sendAmount,
	)
	if err != nil {
		return err
	}

	totalFee, err := safeAdd64(vscFee, btcFee)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error computing total fee")
	}
	if instructions.MaxFee != nil && totalFee > *instructions.MaxFee {
		return ce.NewContractError(
			ce.ErrTransaction,
			"total fee "+strconv.FormatInt(totalFee, 10)+
				" exceeds max_fee "+strconv.FormatInt(*instructions.MaxFee, 10),
		)
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

	// check whether caller (or delegated from) has enough balance to cover transaction
	err = checkAndDeductBalance(env, from, finalAmt)
	if err != nil {
		return err
	}

	// All checks passed — now request TSS signing
	signingData, err := signSpendTransaction(tx, inputUtxos, witnessScripts)
	if err != nil {
		return ce.WrapContractError(ce.ErrTransaction, err, "error signing spend transaction")
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
	sdk.Log(createUnmapLog(tx.TxID(), from, instructions.To, finalAmt, sendAmount))

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

// HandleConfirmSpend confirms a pending spend transaction by verifying its
// Merkle inclusion proof against the stored block headers, then promoting the
// unconfirmed change UTXOs at the specified output indices to the confirmed pool.
//
// This function has no access control by design: it is trustlessly permissionless
// because the caller must supply a valid SPV Merkle proof linking the transaction
// to a block header already accepted by the contract. Without a valid proof the
// call reverts, so no authorization check is needed.
func (cs *ContractState) HandleConfirmSpend(txData *VerificationRequest, indices []uint32) error {
	rawTx, err := hex.DecodeString(txData.RawTxHex)
	if err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "invalid raw tx hex")
	}
	if err := verifyTransaction(txData, rawTx); err != nil {
		return ce.Prepend(err, "error verifying transaction")
	}
	var msgTx wire.MsgTx
	if err := msgTx.Deserialize(bytes.NewReader(rawTx)); err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "could not deserialize transaction")
	}
	txId := msgTx.TxID()

	indexSet := make(map[uint32]struct{}, len(indices))
	for _, idx := range indices {
		indexSet[idx] = struct{}{}
	}

	for i, entry := range cs.UtxoList {
		if entry.Id >= constants.UtxoConfirmedPoolStart {
			continue
		}
		utxo, err := loadUtxo(entry.Id)
		if err != nil {
			return err
		}
		if utxo.TxId != txId {
			continue
		}
		if _, ok := indexSet[utxo.Vout]; !ok {
			continue
		}
		newId, err := cs.allocateConfirmedId()
		if err != nil {
			return err
		}
		saveUtxo(newId, utxo)
		sdk.StateDeleteObject(getUtxoKey(cs.UtxoList[i].Id))
		cs.UtxoList[i].Id = newId
	}

	// Clean up signing data for this tx if present.
	sdk.StateDeleteObject(constants.TxSpendsPrefix + txId)
	for i, val := range cs.TxSpendsList {
		if val == txId {
			cs.TxSpendsList[i] = cs.TxSpendsList[len(cs.TxSpendsList)-1]
			cs.TxSpendsList = cs.TxSpendsList[:len(cs.TxSpendsList)-1]
			break
		}
	}

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

	if sdk.VerifyAddress(instructions.To) == "unknown" {
		return ce.NewContractError(ce.ErrInput, "invalid recipient address \""+instructions.To+"\"")
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

	sdk.Log(createTransferLog(from, instructions.To, amount))

	return nil
}
