package mapping

import (
	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/sdk"
	"bytes"
	"encoding/hex"
	"slices"
	"strconv"

	"github.com/btcsuite/btcd/wire"

	ce "btc-mapping-contract/contract/contracterrors"
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
	if err := ms.updateUtxoSpends(msgTx.TxID(), txData.BlockHeight); err != nil {
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
	// Guard 1: the destination must differ from the vault change address so settleUnmap can
	// identify the change output(s) unambiguously by address at confirm. A To == changeAddress
	// collision would index the user's own withdrawal output as change (the vault over-
	// collateralises and the user donates the withdrawal) — self-harm, no theft, but cheap to
	// reject outright and it removes the only conservation ambiguity at settle.
	if instructions.To == changeAddress {
		return ce.NewContractError(ce.ErrInput, "destination address must differ from the vault change address")
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

	// All checks passed — now request TSS signing (the node reads only the "d-" record +
	// TxSpendsList entry written below; the "us-" record + reservations are contract-internal,
	// so the node/broadcast side is UNCHANGED — exactly like BRK-1's migration "ms-" record).
	signingData, err := signSpendTransaction(tx, inputUtxos, witnessScripts)
	if err != nil {
		return ce.WrapContractError(ce.ErrTransaction, err, "error signing spend transaction")
	}

	// Guard 1 (delete-at-confirm, BRK-1 mirror for the withdrawal path). DO NOT delete the
	// input UTXOs and DO NOT index the change here. Keep the inputs registered + RESERVE them,
	// store a "us-" pending record, and defer BOTH the input-delete and the (now confirmed)
	// change-index to settleUnmap in HandleConfirmSpend under the tx's SPV proof. This makes a
	// never-confirming unmap fund-safe (inputs stay tracked → recoverable, not stranded on L1)
	// and closes M1.1b FN-3 (a rogue re-sign of a still-registered input is theft-detected).
	// The balance debit + FeeSupply(vscFee) credit STAY at build (below): during the in-flight
	// window Σ(UTXO) is unchanged while Supply is down, so the vault is temporarily OVER-
	// collateralised (safe — never under, no false insolvency), rebalancing exactly at settle.
	txId := tx.TxID()
	signingDataBytes, err := MarshalSigningData(signingData)
	if err != nil {
		return ce.WrapContractError(ce.ErrJson, err, "error marshalling signing data")
	}
	sdk.StateSetObject(constants.TxSpendsPrefix+txId, string(signingDataBytes))
	cs.TxSpendsList = append(cs.TxSpendsList, txId)

	unmapRecord := &PendingUnmap{
		InputIds:      inputUtxoIds,
		ChangeAddress: changeAddress,
		ChangeGen:     cs.ActiveGen,
		BtcFee:        btcFee,             // L7-01: true miner fee this tx pays (re-drive delta basis)
		BuildHeight:   currentLastHeight(), // L7-01: re-drive staleness clock
	}
	sdk.StateSetObject(constants.PendingUnmapPrefix+txId, string(MarshalPendingUnmap(unmapRecord)))
	for _, inputId := range inputUtxoIds {
		reserveUtxo(inputId)
	}
	sdk.Log(createUnmapLog(txId, from, instructions.To, finalAmt, sendAmount))

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

	// BRK-4b (brick council FS-1/V-8): a confirm of an ALREADY-PENDING spend (in
	// the TxSpends registry) is EXEMPT from pause — it only reconciles an
	// already-authorized, already-broadcast spend and moves no new funds; freezing
	// it merely strands an in-flight migration/withdrawal. Any OTHER confirm stays
	// pause-gated.
	// L10-1 (FULL-PRUNED 2026-07-09): O(1) keyed check instead of an O(N) scan of the
	// permissionless-inflatable TxSpendsList — the "d-<txid>" signing-data record is
	// written/deleted in lockstep with the list entry (handlers.go / migration.go add
	// both; settle deletes both), so it IS the pending-spend membership. A flood of
	// pending unmaps can no longer make this pause-exempt check O(N). The "ms-"/"us-"
	// record checks below remain as defense-in-depth (never depend on a single record).
	isPending := false
	if d := sdk.StateGetObject(constants.TxSpendsPrefix + txId); d != nil && *d != "" {
		isPending = true
	}
	// BRK-1 (methodology M1/M4 S2-1, defense-in-depth): a migration sweep is ALSO
	// pause-exempt while its "ms-" record is live. updateUtxoSpends now preserves a
	// migration sweep's TxSpendsList entry (so this is normally already true), but check
	// the "ms-" record directly too — the pause-exempt guarantee for an in-flight sweep
	// must not depend on any single list staying intact.
	if !isPending {
		if ms := sdk.StateGetObject(constants.MigrationSweepPrefix + txId); ms != nil && *ms != "" {
			isPending = true
		}
	}
	// Guard 1 (delete-at-confirm unmap): an in-flight unmap is ALSO pause-exempt while its
	// "us-" record is live. Its txid normally stays in TxSpendsList (so isPending is already
	// true), but check the record directly too — the pause-exempt guarantee for settling an
	// already-broadcast withdrawal must not depend on any single list staying intact.
	if !isPending {
		if us := sdk.StateGetObject(constants.PendingUnmapPrefix + txId); us != nil && *us != "" {
			isPending = true
		}
	}
	if !isPending {
		if p := sdk.StateGetObject(constants.PausedKey); p != nil && *p != "" {
			return ce.NewContractError(ce.ErrTransaction, "contract is paused")
		}
	}

	indexSet := make(map[uint32]struct{}, len(indices))
	for _, idx := range indices {
		indexSet[idx] = struct{}{}
	}

	promotedVouts := []uint32{}
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
		// B-1 (council MED, HIGH ceiling): never re-id a UTXO reserved by an in-flight unmap.
		// The unmap's "us-" record references this input by its CURRENT id; re-iding it here
		// strands that unmap at settle (its recorded id vanishes) AND leaves the promoted id
		// unreserved → a later unmap double-selects the outpoint (debit-without-delivery for an
		// innocent user). Leave it unconfirmed + reserved; its own unmap deletes it at settleUnmap.
		// (Only reachable on the upgrade path — a fresh Guard-1 deploy creates no unconfirmed UTXOs.)
		if isUtxoReserved(cs.UtxoList[i].Id) {
			continue
		}
		newId, err := cs.allocateConfirmedId()
		if err != nil {
			return err
		}
		saveUtxo(newId, utxo)
		sdk.StateDeleteObject(getUtxoKey(cs.UtxoList[i].Id))
		cs.UtxoList[i].Id = newId
		promotedVouts = append(promotedVouts, utxo.Vout)
	}
	// D-1/C-1 (council HIGH): a promoted output belongs to this confirmed tx (txId) at this
	// block; record it observed so topUp cannot double-credit a legacy unconfirmed change
	// promoted on the upgrade path.
	if err := markOutpointsObserved(txData.BlockHeight, txId, promotedVouts); err != nil {
		return err
	}

	// BRK-1 (delete-at-confirm migration settle): if this confirmed tx is a migration
	// sweep (it has an "ms-"+txId record), perform the atomic swap HandleMigrateVault
	// deferred — index the swept output(s) to the successor, delete the swept inputs, and
	// debit the reserved miner fee — under the SPV proof verified above. A normal unmap has
	// no "ms-" record and skips this entirely; a migration sweep indexed NOTHING at build,
	// so the promotion loop above is a no-op for it (they never touch the same UTXOs).
	// A migration sweep is always in the TxSpends registry, so isPending==true above → this
	// settle is pause-EXEMPT (BRK-4b): pausing must not strand an already-broadcast sweep.
	// An unmap ("us-") and a migration sweep ("ms-") never share a txid, so at most one of
	// the two settle paths fires. settledInputs captures the confirmed record's input set —
	// the L7-01 spend-group key used for the group-aware cleanup below.
	var settledInputs []uint16
	if msRaw := sdk.StateGetObject(constants.MigrationSweepPrefix + txId); msRaw != nil && *msRaw != "" {
		rec, err := UnmarshalMigrationSweep([]byte(*msRaw))
		if err != nil {
			return ce.NewContractError(ce.ErrStateAccess, "error decoding migration sweep record: "+err.Error())
		}
		if err := cs.settleMigrationSweep(&msgTx, rec, txData.BlockHeight); err != nil {
			return err
		}
		settledInputs = rec.InputIds
	}

	// Guard 1 (delete-at-confirm unmap settle): if this confirmed tx has a "us-" record,
	// perform the finish HandleUnmap deferred — index the change output(s) as confirmed, delete
	// the swept inputs, clear their reservations — under the SPV proof verified above.
	// Pause-EXEMPT (isPending is true for an in-flight unmap).
	if usRaw := sdk.StateGetObject(constants.PendingUnmapPrefix + txId); usRaw != nil && *usRaw != "" {
		rec, err := UnmarshalPendingUnmap([]byte(*usRaw))
		if err != nil {
			return ce.NewContractError(ce.ErrStateAccess, "error decoding pending unmap record: "+err.Error())
		}
		if err := cs.settleUnmap(&msgTx, rec, txData.BlockHeight); err != nil {
			return err
		}
		settledInputs = rec.InputIds
		// L7-01 unmap re-drive refund (H1/P2): a re-drive CHARGED FeeSupply down to the group's
		// HighestFee (the priciest replacement); refund the difference vs the fee the ACTUALLY-
		// confirmed member paid, so I1 holds whether the priciest replacement or a cheaper member
		// (e.g. the original) confirms. Group-of-one (no re-drive) → no group → no refund
		// (settleUnmap already balances). Only UNMAP re-drives charge at build; this branch runs
		// only for an unmap confirm, so the group is always an unmap group (sweeps reserve+debit).
		if graw := sdk.StateGetObject(spendGroupKey(rec.InputIds)); graw != nil && *graw != "" {
			if g, gerr := UnmarshalSpendGroup([]byte(*graw)); gerr == nil && g.HighestFee > rec.BtcFee {
				refunded, aerr := safeAdd64(cs.Supply.FeeSupply, g.HighestFee-rec.BtcFee)
				if aerr != nil {
					return ce.WrapContractError(ce.ErrArithmetic, aerr, "unmap re-drive fee refund overflow")
				}
				cs.Supply.FeeSupply = refunded
			}
		}
	}

	// L7-01 group-aware cleanup: clear the confirmed member AND every RBF replacement sharing
	// its reserved inputs (the spend group) + the group object, atomically — the H2 guarantee
	// (a dangling sibling would re-arm the NN#3 freeze and be uncleanable). LAZY: with no
	// re-drive the group object is absent → a group-of-one, byte-identical to the pre-L7-01
	// per-txid cleanup. If NO pending record settled (idempotent replay / a confirm of a
	// non-vault-spend tx) there is no group key → clean only this txid's stray signing data.
	if len(settledInputs) > 0 {
		cs.clearSpendGroup(txId, settledInputs)
	} else {
		sdk.StateDeleteObject(constants.TxSpendsPrefix + txId)
		cs.TxSpendsList = removeTxid(cs.TxSpendsList, txId)
	}

	return nil
}

// settleUnmap performs the delete-at-confirm finish for an unmap (Guard 1), called from
// HandleConfirmSpend under the tx's already-verified SPV proof: delete the swept inputs
// (kept registered + reserved since build), index the change output(s) as CONFIRMED, and
// clear the per-input reservations. NO Supply mutation — the balance debit + FeeSupply
// (vscFee) credit already happened at BUILD (HandleUnmap); keeping the inputs registered
// made the vault temporarily OVER-collateralised, and this step rebalances Σ(UTXO) exactly.
// NO fee-equality assert (council F2): a no-change / dust-burn unmap legitimately has a real
// miner fee larger than any recorded estimate, so an equality assert would brick a valid
// withdrawal. Correctness rests on (1) the txid binds this SPV-proven tx to the record
// (HandleConfirmSpend looked up "us-"+txId by the confirmed tx's OWN id), so its outputs are
// exactly the ones we built; (2) the change is identified by the record's ChangeAddress
// (To != ChangeAddress enforced at build), tagged ChangeGen so it stays spendable across a
// rotation, capped at MaxUtxoAmount; (3) fail-closed if any recorded input already left the
// registry (idempotent replay / corrupt state) BEFORE any mutation.
func (cs *ContractState) settleUnmap(msgTx *wire.MsgTx, rec *PendingUnmap, blockHeight uint32) error {
	// Idempotency / corruption guard: every recorded input still registered (fail-closed,
	// before any mutation — never double-settle). Also sum the swept input amounts for the
	// conservation sanity assert below (council B-2: the migration settle twin carries one).
	var inputTotal int64
	for _, id := range rec.InputIds {
		found := false
		for i := range cs.UtxoList {
			if cs.UtxoList[i].Id == id {
				var aerr error
				inputTotal, aerr = safeAdd64(inputTotal, cs.UtxoList[i].Amount)
				if aerr != nil {
					return ce.WrapContractError(ce.ErrArithmetic, aerr, "unmap settle input total overflow")
				}
				found = true
				break
			}
		}
		if !found {
			return ce.NewContractError(ce.ErrStateAccess, "unmap settle input missing from registry")
		}
	}

	// Index the change output(s) (paying ChangeAddress, tagged ChangeGen, capped at
	// MaxUtxoAmount) as CONFIRMED. Reuses indexMigrationOutputs — identical shape (match one
	// vault address, cap, tag a generation); the user destination output (To != ChangeAddress)
	// is skipped, and a no-change unmap yields zero here (valid: everything went to
	// destination + miner fee).
	changeUtxos, err := indexMigrationOutputs(msgTx, rec.ChangeAddress, cs.NetworkParams, rec.ChangeGen)
	if err != nil {
		return err
	}

	// Conservation sanity (council B-2, defense-in-depth like settleMigrationSweep): the change
	// returned to the vault can never exceed the swept inputs — the difference funds the user
	// output + miner fee. Fail-closed on gross corruption. NOT an equality assert: a no-change /
	// dust-burn unmap legitimately pays a miner fee larger than any recorded estimate (council
	// F2), so equality would brick a valid withdrawal.
	var changeTotal int64
	for _, u := range changeUtxos {
		changeTotal, err = safeAdd64(changeTotal, u.Amount)
		if err != nil {
			return ce.WrapContractError(ce.ErrArithmetic, err, "unmap settle change total overflow")
		}
	}
	if changeTotal > inputTotal {
		return ce.NewContractError(ce.ErrTransaction, "unmap settle change exceeds swept inputs")
	}

	observedVouts := make([]uint32, 0, len(changeUtxos))
	for _, u := range changeUtxos {
		newId, aerr := cs.allocateConfirmedId()
		if aerr != nil {
			return aerr
		}
		cs.UtxoList = append(cs.UtxoList, UtxoRegistryEntry{Id: newId, Amount: u.Amount})
		saveUtxo(newId, u)
		observedVouts = append(observedVouts, u.Vout)
	}
	// D-1/C-1 (council HIGH): record the indexed change output(s) in the observed list so a
	// later topUpFeeReserve of the same outpoint cannot double-credit it (the change pays the
	// untagged vault address, byte-identical to a fee-reserve deposit).
	if err := markOutpointsObserved(blockHeight, msgTx.TxID(), observedVouts); err != nil {
		return err
	}

	// Delete the swept inputs + clear their reservations (paired — so a later recycled
	// confirmed id can never inherit a stale reservation).
	for _, id := range rec.InputIds {
		cs.UtxoList = slices.DeleteFunc(cs.UtxoList, func(e UtxoRegistryEntry) bool { return e.Id == id })
		sdk.StateDeleteObject(getUtxoKey(id))
		unreserveUtxo(id)
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
