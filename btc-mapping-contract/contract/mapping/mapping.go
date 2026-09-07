package mapping

import (
	"btc-mapping-contract/sdk"
	"net/url"
	"strconv"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
)

// buildSwapInstruction builds the DEX swap instruction for a BTC deposit-swap.
// DX-H5: it forwards the depositor's min_amount_out param so the ingress swap
// honours their slippage bound. The instruction was previously built WITHOUT
// MinAmountOut, so no bound ever reached the router and the swap executed at any
// price (a sandwich could take the whole amount). The router/dex already enforce
// MinAmountOut downstream; the bug was purely that the mapping contract never
// passed it on.
func buildSwapInstruction(params *url.Values, recipient, assetOut string, amount int64) DexInstruction {
	instruction := DexInstruction{
		Type:             "swap",
		Version:          "1.0.0",
		AssetIn:          BtcAssetValue,
		AmountIn:         strconv.FormatInt(amount, 10),
		AssetOut:         assetOut,
		Recipient:        recipient,
		DestinationChain: params.Get(constants.DestinationChainKey),
	}
	if params.Has(constants.MinAmountOutKey) {
		minOut := params.Get(constants.MinAmountOutKey)
		instruction.MinAmountOut = &minOut
	}
	return instruction
}

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
			// V-1 dust-escape prevention (INERT-GATED): once rotation has happened at least
			// once (a superseded generation exists), never credit a sub-MinDepositSats
			// output — it can never be swept economically and, landed on a superseded gen,
			// would permanently deadlock rotation (NN#3). A per-output SKIP, not a tx abort:
			// a tx with one legit + one dust output must still credit the legit one. Gated on
			// hasSupersededGen so a pre-rotation deploy's map behavior is BYTE-IDENTICAL to
			// before this slice (see constants.MinDepositSats doc + BUILD-MAP §4/§7 — this is
			// the one deliberately non-inert-once-rotated behavior change, by design).
			if hasSupersededGen(ms.Vaults) && txOut.Value < constants.MinDepositSats {
				sdk.Log("dust-skip|addr=" + addr + "|sats=" + strconv.FormatInt(txOut.Value, 10))
				continue
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

				instruction := buildSwapInstruction(metadata.Params, metadata.Recipient, assetOut, utxo.Amount)
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

				// DX-H6: run the ingress swap in try/catch mode. If it reverts
				// (slippage / no pool / zero output), the router+DEX state/ledger
				// effects are rolled back to a savepoint and we are NOT trapped — so
				// instead of the whole deposit reverting and STRANDING the user's
				// already-irreversible BTC, we credit them wrapped BTC and they can
				// withdraw or retry later. The router/DEX keep aborting normally; the
				// mapping contract decides to absorb the failure.
				//
				// (Requires consensus version >= 0.2.0. Below it, Try is ignored and a
				// reverting swap traps as before — the legacy strand-on-permanent-
				// failure behaviour, until the network activates the feature.)
				res := sdk.TryContractCall(routerId, "execute", string(instrJson), nil)
				// Clean up any remaining allowance after swap to prevent lingering authorization
				setAllowance(selfAddr, routerAddr, 0)

				// VR2-23: ALL router-failure shapes converge on the SAME refund.
				//
				// A router can fail three ways: it reverts, it returns something
				// unparseable, or it "succeeds" while producing zero output (a drained
				// pool is enough — no malice required). The original BTC-C4 fix
				// refunded the depositor in all three cases; a later refactor to
				// TryContractCall kept only the revert branch, on the stated assumption
				// that zero output would always surface as a revert. That assumption is
				// false, and the repo ships a mock router specifically to prove it.
				//
				// With only the revert branch, a zero-output swap hard-errored and
				// reverted the ENTIRE map call — including registration of the
				// already-SPV-verified L1 deposit. Real Bitcoin that had landed on
				// chain got no credit and no registry entry: stranded.
				//
				// Refunding is safe on the success path too, because the underflow check
				// below only pays out if the contract STILL HOLDS the funds. If the
				// router already pulled them through its allowance, selfBal is short and
				// we fail closed rather than paying twice.
				routerFailure := ""
				if !res.Ok {
					routerFailure = "reverted: " + res.Error
				} else {
					var swapResult SwapResult
					if err := tinyjson.Unmarshal([]byte(res.Result), &swapResult); err != nil {
						routerFailure = "unparseable result"
					} else if swapResult.AmountOut == "" || swapResult.AmountOut == "0" {
						routerFailure = "zero amount out"
					}
				}
				if routerFailure != "" {
					// The BTC drawn for the swap is still credited to the contract
					// account (incAccBalance above ran in THIS frame, not in a
					// rolled-back callee). Move it to the depositor as wrapped BTC.
					selfBal := getAccBal(selfAddr)
					if selfBal < utxo.Amount {
						return ce.NewContractError(ce.ErrStateAccess, "swap refund: contract balance underflow")
					}
					setAccBal(selfAddr, selfBal-utxo.Amount)
					if err := incAccBalance(metadata.Recipient, utxo.Amount); err != nil {
						return ce.Prepend(err, "swap refund: crediting depositor")
					}
					sdk.Log("deposit-swap failed (" + routerFailure + "); refunded depositor wrapped BTC")
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
