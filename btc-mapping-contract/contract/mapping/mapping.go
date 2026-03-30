package mapping

import (
	"btc-mapping-contract/sdk"
	"strconv"

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
	outputsForVsc := make([]Utxo, 0, len(ms.AddressRegistry))

	for index, txOut := range msgTx.TxOut {
		addr, ok, err := isForVscAcc(txOut, ms.AddressRegistry, ms.NetworkParams)
		if err != nil {
			return nil, ce.WrapContractError(
				ce.ErrInput,
				err,
				"error extracting address from output in bitcoin transaction",
			)
		}
		if ok {
			utxo := Utxo{
				TxId:     msgTx.TxID(),
				Vout:     uint32(index),
				Amount:   txOut.Value,
				PkScript: txOut.PkScript,
				Tag:      ms.AddressRegistry[addr].Tag, // raw bytes, not hex
			}
			outputsForVsc = append(outputsForVsc, utxo)
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
	if utxoSpendJson == nil || len(*utxoSpendJson) < 1 {
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

func (ms *MappingState) processUtxos(relevantUtxos []Utxo, from string) error {
	totalMapped := int64(0)
	env := sdk.GetEnv()
	routerId := ""

	// create new utxos entries for all of the relevant outputs in the incoming transaction
	for _, utxo := range relevantUtxos {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(utxo.PkScript, ms.NetworkParams)
		if err != nil {
			return ce.WrapContractError(ce.ErrInput, err, "error extracting pkscript address")
		}
		if len(addrs) == 0 {
			continue
		}
		if metadata, ok := ms.AddressRegistry[addrs[0].EncodeAddress()]; ok {
			// Create UTXO entry
			observedUtxoKey := getObservedKey(utxo)
			// proceed if this output has already been observed
			alreadyObserved := sdk.StateGetObject(observedUtxoKey)
			if alreadyObserved != nil && *alreadyObserved != "" {
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

			sdk.Log(createMapLog(from, metadata.Recipient, utxo.Amount))
			switch metadata.Type {
			case MapDeposit:
				// increment balance for recipient account (vsc account not btc account)
				// alread verified that this addresss is valid on VSC
				if err := incAccBalance(metadata.Recipient, utxo.Amount); err != nil {
					return ce.Prepend(err, "error crediting deposit balance")
				}
			case MapSwap:

				// get router id and check it only if there is a swap in the tx
				if routerId == "" {
					r := sdk.StateGetObject(constants.RouterContractIdKey)
					if *r == "" {
						return ce.NewContractError(ce.ErrInitialization, "router contract not initialized")
					}
					routerId = *r
				}

				if metadata.Params == nil {
					return ce.NewContractError(ce.ErrInput, "swap instruction missing parameters")
				}
				ok := metadata.Params.Has(constants.SwapAssetOut)
				if !ok {
					return ce.NewContractError(ce.ErrInput, "asset out required to execute a swap")
				}
				assetOut := metadata.Params.Get(constants.SwapAssetOut)

				instruction := DexInstruction{
					Type:             "swap",
					Version:          "1.0.0",
					AssetIn:          BtcAssetValue,
					AmountIn:         strconv.FormatInt(utxo.Amount, 10),
					AssetOut:         assetOut,
					Recipient:        metadata.Recipient,
					DestinationChain: metadata.Params.Get(constants.DestinationChainKey),
				}
				instrJson, err := tinyjson.Marshal(instruction)
				if err != nil {
					return ce.NewContractError(ce.ErrJson, "error marshalling swap instruction: "+err.Error())
				}

				selfAddr := "contract:" + env.ContractId
				err = incAccBalance(selfAddr, utxo.Amount)
				if err != nil {
					return ce.NewContractError(ce.ErrStateAccess, "error getting sender account balance: "+err.Error())
				}

				// Approve the Router to spend the contract's freshly-credited tokens.
				// The Router's preFundAsset uses env.Caller (this contract) as the From,
				// and env.Caller when the Router calls back is "contract:<routerId>".
				routerAddr := "contract:" + routerId
				setAllowance(selfAddr, routerAddr, utxo.Amount)

				swapResultStr := sdk.ContractCall(routerId, "execute", string(instrJson), &sdk.ContractCallOptions{})
				// Clean up any remaining allowance after swap to prevent lingering authorization
				setAllowance(selfAddr, routerAddr, 0)
				var swapResult SwapResult
				err = tinyjson.Unmarshal([]byte(*swapResultStr), &swapResult)
				if err != nil {
					return ce.WrapContractError(ce.ErrJson, err, "error unmarshalling swap result")
				}
				if swapResult.AmountOut == "" || swapResult.AmountOut == "0" {
					return ce.NewContractError(ce.ErrInput, "swap returned zero amount out")
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
