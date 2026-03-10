package mapping

import (
	"btc-mapping-contract/sdk"
	"bytes"
	"encoding/hex"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
)

func isForVscAcc(
	txOut *wire.TxOut,
	addresses map[string]*AddressMetadata,
	network *chaincfg.Params,
) (string, bool, error) {
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, network)
	if err != nil {
		return "", false, ce.WrapContractError(ce.ErrInput, err, "could not extract pkscript address")
	}
	// should always being exactly length 1 for P2SH an P2WSH addresses
	for _, addr := range addrs {
		addressString := addr.EncodeAddress()
		if _, ok := addresses[addressString]; ok {
			return addr.EncodeAddress(), true, nil
		}
	}
	return "", false, nil
}

// gets all outputs pertaining to a vsc address
func (ms *MappingState) indexOutputs(msgTx *wire.MsgTx) ([]Utxo, error) {
	outputsForVsc := make([]Utxo, len(ms.AddressRegistry))
	i := 0

	for index, txOut := range msgTx.TxOut {
		if addr, ok, err := isForVscAcc(txOut, ms.AddressRegistry, ms.NetworkParams); ok {
			if err != nil {
				return nil, ce.WrapContractError(
					ce.ErrInput,
					err,
					"error extracting address from output in bitcoin transaction",
				)
			}

			utxo := Utxo{
				TxId:     msgTx.TxID(),
				Vout:     uint32(index),
				Amount:   txOut.Value,
				PkScript: txOut.PkScript,
				Tag:      ms.AddressRegistry[addr].Tag, // raw bytes, not hex
			}
			outputsForVsc[i] = utxo
			i++
		}
	}

	return outputsForVsc, nil
}

// updateUtxoSpends checks whether txId is a known pending spend transaction.
// If so, it confirms matching unconfirmed UTXOs by transitioning them from the
// unconfirmed pool (IDs 0–63) to the confirmed pool (IDs 64–255), and removes
// the signing data entry.
func (cs *ContractState) updateUtxoSpends(txId string) error {
	utxoSpendJson := sdk.StateGetObject(constants.TxSpendsPrefix + txId)
	if len(*utxoSpendJson) < 1 {
		return nil
	}

	utxoSpendPtr, err := UnmarshalSigningData([]byte(*utxoSpendJson))
	if err != nil {
		return ce.NewContractError(ce.ErrJson, "error unmarshalling utxo spend: "+err.Error())
	}
	utxoSpend := *utxoSpendPtr

	type unconfirmedEntry struct {
		indexInRegistry int
		utxo            *Utxo
	}

	unconfirmedEntries := []unconfirmedEntry{}

	for i, entry := range cs.UtxoList {
		if entry.Id < constants.UtxoConfirmedPoolStart {
			utxo, err := loadUtxo(entry.Id)
			if err != nil {
				return err
			}
			unconfirmedEntries = append(unconfirmedEntries, unconfirmedEntry{indexInRegistry: i, utxo: utxo})
		}
	}

	for _, sigHash := range utxoSpend.UnsignedSigHashes {
		for _, unconfirmed := range unconfirmedEntries {
			if txId == unconfirmed.utxo.TxId && sigHash.Index == unconfirmed.utxo.Vout {
				// Promote to confirmed pool: allocate a new confirmed ID,
				// write data at new key, delete old key, update registry.
				newId, err := cs.allocateConfirmedId()
				if err != nil {
					return err
				}
				saveUtxo(newId, unconfirmed.utxo)
				sdk.StateDeleteObject(getUtxoKey(cs.UtxoList[unconfirmed.indexInRegistry].Id))
				cs.UtxoList[unconfirmed.indexInRegistry].Id = newId
				continue
			}
		}
	}

	sdk.StateDeleteObject(constants.TxSpendsPrefix + txId)
	for i, val := range cs.TxSpendsList {
		if val == txId {
			// swap with the last element and shorten
			cs.TxSpendsList[i] = cs.TxSpendsList[len(cs.TxSpendsList)-1]
			cs.TxSpendsList = cs.TxSpendsList[:len(cs.TxSpendsList)-1]
			break
		}
	}
	return nil
}

func (ms *MappingState) processUtxos(relevantUtxos []Utxo) error {
	totalMapped := int64(0)
	env := sdk.GetEnv()
	routerId := ""

	// create new utxos entries for all of the relevant outputs in the incoming transaction
	for _, utxo := range relevantUtxos {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(utxo.PkScript, ms.NetworkParams)
		if err != nil {
			return ce.WrapContractError("", err)
		}
		if metadata, ok := ms.AddressRegistry[addrs[0].EncodeAddress()]; ok {
			// Create UTXO entry
			observedUtxoKey := getObservedKey(utxo)
			// proceed if this output has already been observed
			alreadyObserved := sdk.StateGetObject(observedUtxoKey)
			if *alreadyObserved != "" {
				continue
			}

			utxoInternalId, err := ms.allocateConfirmedId()
			if err != nil {
				return err
			}
			ms.UtxoList = append(ms.UtxoList, UtxoRegistryEntry{Id: utxoInternalId, Amount: utxo.Amount})
			saveUtxo(utxoInternalId, &utxo)

			// set observed
			sdk.StateSetObject(observedUtxoKey, "1")

			switch metadata.Type {
			case MapDeposit:
				// increment balance for recipient account (vsc account not btc account)
				incAccBalance(metadata.Recipient, utxo.Amount)
				sdk.Log(createDepositLog(Deposit{
					to:     metadata.Recipient,
					from:   []string{},
					amount: utxo.Amount,
				}))
			case MapSwap:
				// get router id and check it only if there is a swap in the tx
				if routerId == "" {
					routerId := sdk.StateGetObject(constants.RouterContractIdKey)
					if *routerId == "" {
						return ce.NewContractError(ce.ErrInitialization, "router contract not initialized")
					}
				}

				ok := metadata.Params.Has(constants.SwapAssetOut)
				if !ok {
					return ce.NewContractError(ce.ErrInput, "asset out required to execute a swap")
				}
				assetOut := metadata.Params.Get(constants.SwapAssetOut)

				instruction := DexInstruction{
					Type:      "swap",
					Version:   "1.0.0",
					AssetIn:   BtcAssetValue,
					AmountIn:  utxo.Amount,
					AssetOut:  assetOut,
					Recipient: metadata.Recipient,
				}
				instrJson, err := tinyjson.Marshal(instruction)
				if err != nil {
					return ce.NewContractError(ce.ErrJson, "error marshalling swap instruction: "+err.Error())
				}

				options := sdk.ContractCallOptions{
					Intents: []sdk.Intent{
						{
							Type: "transfer.allow",
							Args: map[string]string{
								"limit": hex.EncodeToString([]byte{byte(utxo.Amount)}),
								"token": "btc",
							},
						},
					},
				}

				sender := env.Sender.Address.String()
				err = incAccBalance(sender, utxo.Amount)
				if err != nil {
					return ce.NewContractError(ce.ErrStateAccess, "error getting sender account balance: "+err.Error())
				}

				swapResultStr := sdk.ContractCall(routerId, "execute", string(instrJson), &options)
				var swapResult SwapResult
				err = tinyjson.Unmarshal([]byte(*swapResultStr), &swapResult)
				if err != nil {
					return ce.WrapContractError(ce.ErrJson, err)
				}
			default:
				// should never happen
				continue
			}
			// This increments in all cases, since BTC is always mapped onto VSC
			totalMapped, err = safeAdd64(totalMapped, utxo.Amount)
			if err != nil {
				return ce.WrapContractError(ce.ErrArithmetic, err, "error accumulating mapped amount")
			}
		}
	}

	if totalMapped != 0 {
		newActive, err := safeAdd64(ms.Supply.ActiveSupply, totalMapped)
		if err != nil {
			return ce.WrapContractError(ce.ErrArithmetic, err, "error incrementing active supply")
		}
		ms.Supply.ActiveSupply = newActive
		newUser, err := safeAdd64(ms.Supply.UserSupply, totalMapped)
		if err != nil {
			return ce.WrapContractError(ce.ErrArithmetic, err, "error incrementing user supply")
		}
		ms.Supply.UserSupply = newUser
	}

	return nil
}

// HandleMap processes an incoming Bitcoin transaction.
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
	ms.updateUtxoSpends(msgTx.TxID())

	err = ms.processUtxos(relevantOutputs)
	if err != nil {
		return err
	}

	return nil
}
