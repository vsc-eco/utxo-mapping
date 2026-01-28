package mapping

import (
	"btc-mapping-contract/sdk"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func isForVscAcc(
	txOut *wire.TxOut,
	addresses map[string]*AddressMetadata,
	network *chaincfg.Params,
) (string, bool, error) {
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, network)
	if err != nil {
		return "", false, fmt.Errorf("coult not extract pkscript address: %w", err)
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

func (ms *MappingState) indexOutputs(msgTx *wire.MsgTx) ([]Utxo, error) {
	outputsForVsc := make([]Utxo, len(ms.AddressRegistry))
	i := 0

	for index, txOut := range msgTx.TxOut {
		if addr, ok, err := isForVscAcc(txOut, ms.AddressRegistry, ms.NetworkParams); ok {
			if err != nil {
				return nil, err
			}

			utxo := Utxo{
				TxId:     msgTx.TxID(),
				Vout:     uint32(index),
				Amount:   txOut.Value,
				PkScript: txOut.PkScript,
				Tag:      hex.EncodeToString(ms.AddressRegistry[addr].Tag),
			}
			outputsForVsc[i] = utxo
			i++
		}
	}

	return outputsForVsc, nil
}

func (cs *ContractState) updateUtxoSpends(txId string) error {
	utxoSpendJson := sdk.StateGetObject(txSpendsPrefix + txId)
	if len(*utxoSpendJson) < 1 {
		return nil
	}

	var utxoSpend SigningData
	err := tinyjson.Unmarshal([]byte(*utxoSpendJson), &utxoSpend)
	if err != nil {
		return fmt.Errorf("error unmarshalling utxo spend json: %w", err)
	}

	// not the most efficient but there should never be more than a few of these
	type unconfirmedUtxo struct {
		indexInRegistry int
		utxo            *Utxo
	}

	unconfirmedUtxos := []unconfirmedUtxo{}

	for i, utxoBytes := range cs.UtxoList {
		internalId, _, confirmed := unpackUtxo(utxoBytes)
		if confirmed == 0 {
			utxo := Utxo{}
			utxoJson := sdk.StateGetObject(fmt.Sprintf("%s%x", utxoPrefix, internalId))
			err := tinyjson.Unmarshal([]byte(*utxoJson), &utxo)
			if err != nil {
				return err
			}
			unconfirmedUtxos = append(unconfirmedUtxos, unconfirmedUtxo{indexInRegistry: i, utxo: &utxo})
		}
	}

	for _, sigHash := range utxoSpend.UnsignedSigHashes {
		// check all unconfirmed utxos
		for _, unconfirmed := range unconfirmedUtxos {
			if txId == unconfirmed.utxo.TxId && sigHash.Index == unconfirmed.utxo.Vout {
				// set the confirmed byte array to 1
				cs.UtxoList[unconfirmed.indexInRegistry][2] = 1
				continue
			}
		}
	}

	sdk.StateDeleteObject(txSpendsPrefix + txId)
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

// attempts to return funds to the checkAddress, falls back on sending to dex account
// returns the address it returns funds to
func (cs *ContractState) allocateFunds(recipient string, amount int64) error {
	recipientBal, err := getAccBal(recipient)
	if err != nil {
		return err
	}
	setAccBal(recipient, recipientBal+amount)
	return nil
}

// TODO: make last output an actual error object
func (cs *ContractState) determineReturnInfo(metadata *AddressMetadata) (string, NetworkName, string) {
	// fallback is typically the system address, which should never fail to be created
	// if it does, defaults on a "blind faith" send to the sender's destination
	fallBackAddress, _, err := createP2WSHAddressWithBackup(
		cs.PublicKeys.PrimaryPubKey,
		cs.PublicKeys.BackupPubKey,
		nil,
		cs.NetworkParams,
	)
	if err != nil {
		fallBackAddress = metadata.Recipient
	}

	if !metadata.Params.Has(returnAddressKey) {
		return metadata.Recipient, Vsc, "no return address provided, returning to destination VSC account"
	}

	returnAddress := metadata.Params.Get(returnAddressKey)

	var returnNetwork Network

	if !metadata.Params.Has(returnNetworkKey) {
		returnNetwork = cs.NetworkOptions[Vsc]
	} else {
		returnNetwork, err = cs.getNetwork(metadata.Params.Get(returnNetworkKey))
		if err != nil {
			returnNetwork = cs.NetworkOptions[Vsc]
		}
	}

	if returnNetwork.ValidateAddress(returnAddress) {
		return returnAddress, returnNetwork.Name(), ""
	} else {
		// destination network, to be trimmed to VSC or BTC
		destNetName := metadata.OutNetwork
		if metadata.OutNetwork != Vsc && metadata.OutNetwork != Btc {
			destNetName = Vsc
		}
		if cs.NetworkOptions[destNetName].ValidateAddress(returnAddress) {
			return metadata.Recipient, destNetName, fmt.Sprintf(
				"return address '%s' invalid on network '%s', funds returned to transaction destination account on vsc",
				returnAddress,
				returnNetwork.Name(),
			)
		}
		return fallBackAddress, Vsc, fmt.Sprintf(
			"return address '%s' invalid on network '%s' and destination address '%s' invalid on network '%s', funds burned",
			returnAddress,
			returnNetwork.Name(),
			metadata.Recipient,
			destNetName,
		)
	}
}

func (ms *MappingState) processUtxos(relevantUtxos []Utxo) (int64, MappingResults, error) {
	totalMapped := int64(0)
	env := sdk.GetEnv()

	results := make(MappingResults, len(relevantUtxos))
	// create new utxos entries for all of the relevant outputs in the incoming transaction
	for i, utxo := range relevantUtxos {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(utxo.PkScript, ms.NetworkParams)
		if err != nil {
			return 0, nil, err
		}
		if metadata, ok := ms.AddressRegistry[addrs[0].EncodeAddress()]; ok {
			// Create UTXO entry
			observedUtxoKey := fmt.Sprintf("%s:%d", utxo.TxId, utxo.Vout)
			// proceed if this output has already been observed
			// TODO: error or some type of acknowledgement here?
			alreadyObserved := sdk.StateGetObject(observedPrefix + observedUtxoKey)
			if *alreadyObserved != "" {
				continue
			}

			utxoInternalId := ms.UtxoNextId
			ms.UtxoNextId++
			// TODO: change since 'confirmed' was removed
			ms.UtxoList = append(ms.UtxoList, packUtxo(utxoInternalId, utxo.Amount, 1))
			utxoJson, err := tinyjson.Marshal(utxo)
			if err != nil {
				return 0, nil, err
			}

			sdk.StateSetObject(fmt.Sprintf("%s%x", utxoPrefix, utxoInternalId), string(utxoJson))

			// set observed
			sdk.StateSetObject(observedPrefix+observedUtxoKey, "1")

			if metadata.Type == MapDeposit {
				// increment balance for recipient account (vsc account not btc account)
				// alread verified that this addresss is valid on VSC
				ms.allocateFunds(metadata.Recipient, utxo.Amount)
			} else if metadata.Type == MapSwap {
				ok := metadata.Params.Has(swapAssetOut)
				if !ok {
					return 0, nil, fmt.Errorf("asset out required to execute a swap")
				}
				assetOut := metadata.Params.Get(swapAssetOut)

				instruction := DexInstruction{
					Type:      "swap",
					Version:   "1.0.0",
					AssetIn:   BtcAssetValue,
					AssetOut:  assetOut,
					Recipient: metadata.Recipient,
				}
				instrJson, err := tinyjson.Marshal(instruction)
				if err != nil {
					return 0, nil, fmt.Errorf("error marshalling swap instruction: %w", err)
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
					return 0, nil, fmt.Errorf("error getting sender account balance: %w", err)
				}
				setAccBal(sender, senderBal+utxo.Amount)

				// call swap contract
				swapResult := sdk.ContractCall(routerContracId, "execute", string(instrJson), &options)

				// TODO: replace with check for success
				if *swapResult == "" {
					// swap succeeded
					results[i] = &MappingResult{
						Instruction: metadata.Instruction,
					}
					continue
				}
			}

			// TODO: check cases for when this should increment
			totalMapped += utxo.Amount
		}
	}

	if totalMapped != 0 {
		ms.Supply.ActiveSupply += totalMapped
		ms.Supply.UserSupply += totalMapped
	}

	return totalMapped, results, nil
}
