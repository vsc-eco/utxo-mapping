package mapping

import (
	"dash-mapping-contract/sdk"
	"strconv"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"dash-mapping-contract/contract/constants"
	ce "dash-mapping-contract/contract/contracterrors"
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
	// should always be exactly length 1 for P2SH addresses (Dash never
	// activated SegWit, so the deposit-address commitment is always P2SH)
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
			if txOut.Value > constants.MaxUtxoAmount {
				return nil, ce.NewContractError(ce.ErrInput, "utxo amount exceeds maximum ("+
					strconv.FormatInt(txOut.Value, 10)+" > "+
					strconv.FormatInt(constants.MaxUtxoAmount, 10)+")")
			}
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

func (ms *MappingState) processUtxos(relevantUtxos []Utxo, from string, blockHeight uint32) error {
	totalMapped := int64(0)
	env := sdk.GetEnv()
	routerId := ""

	// Load existing observed list for this block height (may already have entries
	// from a prior map call against the same block).
	observedList := loadObservedList(blockHeight)

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
			// Check if this output has already been observed
			entry, err := makeObservedEntry(utxo.TxId, utxo.Vout)
			if err != nil {
				return ce.WrapContractError(ce.ErrInput, err, "error creating observed entry")
			}
			if isObserved(observedList, entry) {
				continue
			}

			utxoInternalId, err := ms.allocateConfirmedId()
			if err != nil {
				return err
			}
			ms.UtxoList = append(ms.UtxoList, UtxoRegistryEntry{Id: utxoInternalId, Amount: utxo.Amount})
			saveUtxo(utxoInternalId, &utxo)

			// Mark observed
			observedList = append(observedList, entry)

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
					AssetIn:          DashAssetValue,
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

				// DX-H6 (propagated from btc-mapping): run the ingress swap
				// in try/catch mode. If the router reverts (slippage, no
				// pool, zero output, abort), the router+DEX state/ledger
				// effects are rolled back to a savepoint and the caller is
				// NOT trapped — so instead of the whole deposit reverting
				// and STRANDING the user's already-irreversible Dash, the
				// refund branch below credits them wrapped DASH and they
				// can withdraw or retry later. The router/DEX keep
				// aborting normally; the mapping contract decides to
				// absorb the failure.
				//
				// Requires consensus version >= 0.2.0. Below it, Try is
				// ignored and a reverting swap traps as before — the
				// legacy strand-on-permanent-failure behaviour, until
				// the network activates the feature.
				res := sdk.TryContractCall(routerId, "execute", string(instrJson), nil)
				// Clean up any remaining allowance after swap to prevent lingering authorization
				setAllowance(selfAddr, routerAddr, 0)

				// Pentest finding BTC-C4 / DX-H6 (propagated from btc-
				// mapping): when the router fails or returns a useless
				// result, previously this branch reverted the entire map →
				// user's Dash sat in the contract vault with no L2 credit
				// until the backup CSV timelock let them reclaim. Now: if
				// the router didn't successfully pull the allowance, the
				// contract's self-credit is transferred to the depositor as
				// wrapped DASH instead.
				//
				// With sdk.TryContractCall the router's effects are rolled
				// back even on success-shaped-but-useless replies (e.g.
				// AmountOut=0), so the post-revert refund is safe — the
				// allowance is back to its pre-call value and only the
				// contract's pre-call incAccBalance remains to settle.
				routerFailed := false
				var swapResult SwapResult
				if !res.Ok {
					routerFailed = true
				} else if res.Result == "" {
					routerFailed = true
				} else if uerr := tinyjson.Unmarshal([]byte(res.Result), &swapResult); uerr != nil {
					routerFailed = true
				} else if swapResult.AmountOut == "" || swapResult.AmountOut == "0" {
					routerFailed = true
				}

				if routerFailed {
					selfBal := getAccBal(selfAddr)
					if selfBal < utxo.Amount {
						return ce.NewContractError(ce.ErrTransaction,
							"swap failed and allowance partially consumed; manual recovery required")
					}
					setAccBal(selfAddr, selfBal-utxo.Amount)
					if err := incAccBalance(metadata.Recipient, utxo.Amount); err != nil {
						return ce.Prepend(err, "dx-h6 refund: error crediting depositor")
					}
					reason := res.Error
					if res.Ok {
						reason = "router returned zero / unparseable result"
					}
					sdk.Log("dx-h6 refund: swap failed (" + reason + "); credited " + metadata.Recipient + " " +
						strconv.FormatInt(utxo.Amount, 10) + " duffs")
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

	// Persist the observed list for this block height
	if len(observedList) > 0 {
		saveObservedList(blockHeight, observedList)
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
