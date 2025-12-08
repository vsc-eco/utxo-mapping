package mapping

import (
	"bytes"
	"contract-template/sdk"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func (ms *MappingState) HandleMap(txData *VerificationRequest) error {
	env := sdk.GetEnv()

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
			// proceed if this output has already been observed
			alreadyObserved := sdk.StateGetObject(observedPrefix + utxoKey)
			if *alreadyObserved != "" {
				continue
			}

			utxoInternalId := ms.UtxoLastId
			ms.UtxoLastId++
			// TODO: change since 'confirmed' was removed
			ms.UtxoList = append(ms.UtxoList, packUtxo(utxoInternalId, utxo.Amount, 1))
			utxoJson, err := tinyjson.Marshal(utxo)
			if err != nil {
				sdk.Abort(err.Error())
			}

			sdk.StateSetObject(utxoPrefix+fmt.Sprintf("%d", utxoInternalId), string(utxoJson))

			// set observed
			sdk.StateSetObject(observedPrefix+utxoKey, "1")

			if metadata.Type == MapDeposit {
				// increment balance for recipient account (vsc account not btc account)
				recipientBal, err := getAccBal(metadata.VscAddress)
				if err != nil {
					sdk.Abort(err.Error())
				}
				setAccBal(metadata.VscAddress, recipientBal+utxo.Amount)
			} else if metadata.Type == MapSwap {
				ok := metadata.Instruction.Has(swapAssetOut)
				if !ok {
					sdk.Abort("asset out required to execute a swap")
				}
				assetOut := metadata.Instruction.Get(swapAssetOut)

				instruction := DexInstruction{
					Type:      "swap",
					Version:   "1.0.0",
					AssetIn:   BtcAssetValue,
					AssetOut:  assetOut,
					Recipient: metadata.VscAddress,
				}
				instrJson, err := tinyjson.Marshal(instruction)
				if err != nil {
					sdk.Abort(fmt.Sprintf("error marshalling swap instruction: %s", err.Error()))
				}

				options := sdk.ContractCallOptions{
					Intents: []sdk.Intent{
						{
							Type: "transfer.allow",
							Args: map[string]string{
								"limit": strconv.FormatInt(utxo.Amount, 10),
								"token": "btc",
							},
						},
					},
				}

				// increment the balance of the sender, since that's the only account that can authorize
				// the intents for the swap and is calling the swap
				sender := env.Sender.Address.String()
				senderBal, err := getAccBal(sender)
				if err != nil {
					sdk.Abort(fmt.Sprintf("error getting sender account balance: %s", err.Error()))
				}
				setAccBal(sender, senderBal+utxo.Amount)

				// call swap contract
				sdk.ContractCall("INSERT_ID_HERE", "execute", string(instrJson), &options)
			}

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
