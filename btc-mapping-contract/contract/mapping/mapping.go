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
				// S1.3 C-1: tag the deposit with the generation whose address it hit,
				// so the spend path resolves the correct per-generation witness keys +
				// TSS keyId. Without this, a post-rotation gen-1 deposit recorded as
				// gen-0 would build an unspendable witness while the balance is deducted.
				Generation: ms.AddressRegistry[addr].Generation,
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
func (cs *ContractState) updateUtxoSpends(txId string, blockHeight uint32) error {
	// BRK-1 (methodology M1/M4 S2-1): a MIGRATION sweep — one with a live "ms-" record —
	// must be reconciled ONLY through confirmSpend's settle (index output → successor,
	// delete inputs, debit fee), NEVER stripped here. If the permissionless `map` path
	// stripped its "d-"/TxSpendsList entry, the sweep would vanish from the pending-spend
	// list while still unsettled in "ms-"/MigrationSweeps — losing the BRK-4b pause-exempt
	// on the later confirmSpend AND making a TxSpendsList-keyed monitor read it as
	// reconciled so confirmSpend may never fire → NN#3 rotation freeze (funds-safe,
	// recoverable, but a liveness hazard). Leave the migration sweep fully intact for
	// confirmSpend. (A migration sweep indexes no unconfirmed change, so there is nothing
	// to promote here anyway.)
	if ms := sdk.StateGetObject(constants.MigrationSweepPrefix + txId); ms != nil && *ms != "" {
		return nil
	}

	// Guard 1 (delete-at-confirm unmap): an UNMAP with a live "us-" record must LIKEWISE be
	// reconciled ONLY through confirmSpend's settleUnmap, NEVER stripped here. Its inputs
	// stay registered (and reserved) until settle; if the permissionless `map` path stripped
	// its "d-"/TxSpendsList entry while the inputs remain registered, the tx's txid would
	// leave the authorised set (cs.TxSpendsList) while its inputs are still in the registry —
	// exactly the state HandleReportUnauthorizedSpend trips on (spendsRegistered &&
	// !authorized) → a permissionless false theft-halt of the whole vault (the identical
	// landmine the reverted release-stale-sweep guard armed, council finding A1/F3). Leave the
	// unmap fully intact for confirmSpend; its change is indexed by settleUnmap, not here.
	if us := sdk.StateGetObject(constants.PendingUnmapPrefix + txId); us != nil && *us != "" {
		return nil
	}

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

	promotedVouts := []uint32{}
	for _, sigHash := range utxoSpend.UnsignedSigHashes {
		for _, unconfirmed := range unconfirmedEntries {
			if txId == unconfirmed.utxo.TxId && sigHash.Index == unconfirmed.utxo.Vout {
				// B-1 (council): never re-id a UTXO reserved by an in-flight unmap — its "us-"
				// record references this input by its current id; re-iding it strands that unmap at
				// settle and leaves the promoted id unreserved (double-select). Leave it unconfirmed +
				// reserved; its unmap deletes it at settleUnmap. (Upgrade-path only; a fresh Guard-1
				// deploy holds no unconfirmed UTXOs.)
				if isUtxoReserved(cs.UtxoList[unconfirmed.indexInRegistry].Id) {
					continue
				}
				// Promote to confirmed pool: allocate a new confirmed ID,
				// write data at new key, delete old key, update registry.
				newId, err := cs.allocateConfirmedId()
				if err != nil {
					return err
				}
				saveUtxo(newId, unconfirmed.utxo)
				sdk.StateDeleteObject(getUtxoKey(cs.UtxoList[unconfirmed.indexInRegistry].Id))
				cs.UtxoList[unconfirmed.indexInRegistry].Id = newId
				promotedVouts = append(promotedVouts, unconfirmed.utxo.Vout)
				continue
			}
		}
	}
	// D-1/C-1 (council HIGH): a promoted output belongs to this confirmed tx (txId) at this
	// block; record it observed so topUp cannot double-credit a legacy unconfirmed change
	// promoted on the upgrade path.
	if err := markOutpointsObserved(blockHeight, txId, promotedVouts); err != nil {
		return err
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
