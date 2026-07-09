package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"bytes"
	"encoding/hex"
	"strconv"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// fee_reserve.go — operator-funded migration fee reserve top-up.
//
// PROBLEM (council FeeSupply lens, verified at source). FeeSupply is credited ONLY by
// unmap vscFee (handlers.go), and vscFee is hard-coded to 0 (unmapping.go
// VscFeeMinSats/VscFeeRateBps). So FeeSupply is structurally 0, and the migration
// reserve gate (migration.go: FeeSupply < feeNeeded) fails on the FIRST tranche of the
// FIRST rotation → migration can never build → NN#3 permanently wedges rotation with no
// runtime recovery.
//
// WHY NOT DRAW THE FEE FROM THE SWEPT VALUE. map/unmap keep ActiveSupply == UserSupply
// in lock-step (no surplus), so netting the miner fee out of the swept value would push
// ActiveSupply < UserSupply — a fractional vault where the last withdrawer cannot be
// paid. The reserve MUST be funded from a source outside user principal.
//
// FIX (user decision, 2026-07-09): the OPERATOR funds it. HandleTopUpFeeReserve
// SPV-proves a real BTC deposit to the active vault's own address and credits FeeSupply
// by the deposited value, indexing the deposit as a normal confirmed active-gen UTXO so
// conservation is preserved exactly: Σ(UTXO) += value AND FeeSupply += value ⇒
// Σ(UTXO) == ActiveSupply + FeeSupply still holds, and ActiveSupply (== UserSupply) is
// untouched, so users stay fully backed. Over time migration draws FeeSupply DOWN (each
// settle debits btcFee while the swept output is btcFee smaller) and the operator tops it
// back UP — the operator's BTC is what absorbs the rotation's miner fees, never user
// principal. Solvency after a sweep: Σ' = A + (F − btcFee) = A + F' ≥ A == UserSupply
// (F' ≥ 0 by the reserve gate), so the users the vault owes are never diluted.
//
// ★ NEVER-TERMINAL (user requirement, 2026-07-09: "adding more btc should continue the
// migration automatically, never a situation where it can't be continued"). The
// migration fee-shortage abort writes NO state — the reserve gate in HandleMigrateVault
// sits BEFORE signing, the "d-"/"ms-" records, and the status transition, and a returned
// error reverts the whole tx — so a fee-starved migration leaves the retiring gen fully
// intact (same UTXOs, same status). A top-up simply lets the NEXT migrateVault tranche
// re-select the identical inputs and proceed. Migration ALWAYS continues; it can never
// terminally brick on fees. This op is therefore PERMISSIONLESS (a valid SPV proof of a
// real deposit is self-authorising — anyone may fund the reserve to un-wedge a rotation)
// and NOT pause-gated (it moves no funds OUT and can only help; the operator must be able
// to fund even during a pause so migration flows the instant it unpauses).
func (cs *ContractState) HandleTopUpFeeReserve(txData *VerificationRequest) error {
	if txData == nil || txData.RawTxHex == "" {
		return ce.NewContractError(ce.ErrInput, "tx_data.raw_tx_hex required")
	}
	rawTx, err := hex.DecodeString(txData.RawTxHex)
	if err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "invalid raw tx hex")
	}
	if err := verifyTransaction(txData, rawTx); err != nil {
		return ce.Prepend(err, "error verifying fee-reserve deposit")
	}
	var msgTx wire.MsgTx
	if err := msgTx.Deserialize(bytes.NewReader(rawTx)); err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "could not deserialize fee-reserve deposit tx")
	}
	txId := msgTx.TxID()

	// D-1/C-1 (council HIGH): a fee-reserve top-up must be an EXTERNAL deposit, NEVER a
	// vault-authored spend. An unmap change output and a migration sweep output pay the SAME
	// untagged vault address a top-up matches; without this guard anyone could point topUp at an
	// already-broadcast change/sweep tx and double-credit FeeSupply + double-index the outpoint
	// (a phantom UTXO — Σ==Active+Fee stays balanced because both sides inflate, so no assert
	// catches it → masked insolvency / eventual double-spend). This closes the PRE-settle window
	// (L1-confirmed, not-yet-settled): the vault spend still holds a live "us-"/"ms-" record or a
	// TxSpendsList entry. The POST-settle window is closed by the settle paths recording their
	// outputs in the observed list (isObserved, below).
	if v := sdk.StateGetObject(constants.PendingUnmapPrefix + txId); v != nil && *v != "" {
		return ce.NewContractError(ce.ErrInput, "fee-reserve tx is an in-flight unmap, not a deposit")
	}
	if v := sdk.StateGetObject(constants.MigrationSweepPrefix + txId); v != nil && *v != "" {
		return ce.NewContractError(ce.ErrInput, "fee-reserve tx is an in-flight migration sweep, not a deposit")
	}
	for _, pendingId := range cs.TxSpendsList {
		if pendingId == txId {
			return ce.NewContractError(ce.ErrInput, "fee-reserve tx is a pending vault spend, not a deposit")
		}
	}

	// Derive the ACTIVE vault's untagged address — the same P2WSH the unmap change and the
	// migration successor pay. cs.PublicKeys is resolved to the active generation's keys
	// (IntializeContractState), and each matched output is tagged with cs.ActiveGen so it is
	// a normal, spendable active-gen UTXO (fungible backing, swept like any other when the
	// active gen eventually retires). A pre-fold / keyless deploy derives an address nothing
	// pays → the "no matching output" abort below (can't fund a vault that doesn't exist).
	reserveAddr, _, err := createP2WSHAddressWithBackup(
		cs.PublicKeys.Primary, cs.PublicKeys.Backup, nil, cs.NetworkParams,
	)
	if err != nil {
		return ce.WrapContractError(ce.ErrTransaction, err, "error deriving fee-reserve vault address")
	}

	// Dedup via the shared observed list (the exact mechanism the map deposit path uses), so
	// a replay of topUpFeeReserve — or a normal map of the same tx — can never double-credit
	// the same output. Consistent with pruning: once the block header is pruned the deposit
	// can no longer be SPV-verified at all (verifyTransaction above fails first), so a replay
	// outside the retention window is blocked even without the observed entry.
	observedList := loadObservedList(txData.BlockHeight)
	var credited int64
	changed := false
	for index, txOut := range msgTx.TxOut {
		_, addrs, _, aerr := txscript.ExtractPkScriptAddrs(txOut.PkScript, cs.NetworkParams)
		if aerr != nil {
			return ce.WrapContractError(ce.ErrInput, aerr, "error extracting fee-reserve output address")
		}
		if len(addrs) != 1 || addrs[0].EncodeAddress() != reserveAddr {
			continue
		}
		// Cap at the uint48 registry width exactly like the deposit/change/migration paths.
		if txOut.Value > constants.MaxUtxoAmount {
			return ce.NewContractError(ce.ErrInput, "fee-reserve deposit output exceeds maximum utxo amount")
		}
		entry, eerr := makeObservedEntry(txId, uint32(index))
		if eerr != nil {
			return ce.WrapContractError(ce.ErrInput, eerr, "error creating observed entry")
		}
		if isObserved(observedList, entry) {
			continue // already credited by a prior top-up (or map) of this same output
		}
		internalId, ierr := cs.allocateConfirmedId()
		if ierr != nil {
			return ierr
		}
		utxo := &Utxo{
			TxId:       txId,
			Vout:       uint32(index),
			Amount:     txOut.Value,
			PkScript:   txOut.PkScript,
			Tag:        nil, // untagged vault address, exactly like an unmap change output
			Generation: cs.ActiveGen,
		}
		cs.UtxoList = append(cs.UtxoList, UtxoRegistryEntry{Id: internalId, Amount: txOut.Value})
		saveUtxo(internalId, utxo)
		observedList = append(observedList, entry)
		credited, err = safeAdd64(credited, txOut.Value)
		if err != nil {
			return ce.WrapContractError(ce.ErrArithmetic, err, "fee-reserve credit overflow")
		}
		changed = true
	}
	if !changed {
		return ce.NewContractError(ce.ErrInput, "no output pays the active vault fee-reserve address")
	}
	saveObservedList(txData.BlockHeight, observedList)

	// Credit FeeSupply (the ONLY mutation to Supply — ActiveSupply/UserSupply untouched).
	// Σ(UTXO) rose by `credited` above; FeeSupply rises by the same, preserving conservation.
	newFee, err := safeAdd64(cs.Supply.FeeSupply, credited)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "fee supply overflow")
	}
	cs.Supply.FeeSupply = newFee
	sdk.Log("feereserve|topup|txid=" + txId + "|credited=" + strconv.FormatInt(credited, 10) +
		"|feeSupply=" + strconv.FormatInt(newFee, 10))
	return nil
}
