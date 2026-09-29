package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"encoding/binary"
	"errors"
	"slices"
	"strconv"

	"github.com/btcsuite/btcd/wire"
)

// abandon.go: H-2 (VR2-27), a sweep that can never confirm must not block rotation.
//
// A migration tranche drawn from the legacy unconfirmed pool (the VR2-26 fallback) may
// spend an entry that does not exist on Bitcoin: those entries predate the SPV-indexed
// registry, and the shared testnet vault holds one (u-10). Its sweep is invalid forever,
// its generation never drains, AnyFundedSupersededGen (NN#3) stays true and every later
// createKey is refused. Re-drive cannot help: it rebuilds the same inputs.
//
// Chainflip has the same kind of on-chain UTXO set and two valves for this: a broadcast
// that no authority can land is aborted and taken off the pending set, and UTXOs under a
// key older than the previous one are dropped. THORChain avoids the problem by keeping no
// UTXO list on chain at all. Here:
//   - a legacy tranche spends ONE input (MaxLegacyInputsPerTranche), so an entry that
//     does not exist can only block its own sweep;
//   - once such a sweep has been fee-bumped (re-driven) and still has not confirmed
//     SweepAbandonBlocks after its latest build, anyone may abandon it: its input is
//     written off against the fee reserve (never user principal, like HandleWriteOffDust,
//     VR2-15), its whole spend group leaves the pending set, and the generation can drain;
//   - if a member of the abandoned group confirms after all (the input was real, the
//     sweep only slow), settleAbandonedSweep indexes its output to the successor and
//     returns the written-off value to the reserve, net of the miner fee, exactly the
//     result a normal settle would have had.
// Conservation holds at every step: the write-off lowers Sigma(UTXO) and FeeSupply by the
// same value, and the late settle raises both by the swept output.

// AbandonedSweep is kept per member txid of an abandoned spend group ("sa-"+txid).
type AbandonedSweep struct {
	Sweep      MigrationSweep // that member's own sweep record (its fee, inputs, successor)
	WrittenOff int64          // the input value written off against FeeSupply
	Members    []string       // every member txid of the group
}

// MarshalAbandonedSweep layout: [8] WrittenOff, [2] member count, 64 hex chars per member,
// then the member's MarshalMigrationSweep bytes.
func MarshalAbandonedSweep(a *AbandonedSweep) []byte {
	sweep := MarshalMigrationSweep(&a.Sweep)
	k := len(a.Members)
	buf := make([]byte, 8+2+k*txidHexLen+len(sweep))
	off := 0
	binary.BigEndian.PutUint64(buf[off:], uint64(a.WrittenOff))
	off += 8
	binary.BigEndian.PutUint16(buf[off:], uint16(k))
	off += 2
	for _, m := range a.Members {
		copy(buf[off:off+txidHexLen], m)
		off += txidHexLen
	}
	copy(buf[off:], sweep)
	return buf
}

func UnmarshalAbandonedSweep(data []byte) (*AbandonedSweep, error) {
	if len(data) < 8+2 {
		return nil, errors.New("abandoned sweep record too short")
	}
	a := &AbandonedSweep{}
	off := 0
	a.WrittenOff = int64(binary.BigEndian.Uint64(data[off:]))
	off += 8
	k := int(binary.BigEndian.Uint16(data[off:]))
	off += 2
	if off+k*txidHexLen > len(data) {
		return nil, errors.New("abandoned sweep record truncated (members)")
	}
	a.Members = make([]string, k)
	for i := 0; i < k; i++ {
		a.Members[i] = string(data[off : off+txidHexLen])
		off += txidHexLen
	}
	sweep, err := UnmarshalMigrationSweep(data[off:])
	if err != nil {
		return nil, err
	}
	a.Sweep = *sweep
	return a, nil
}

// HandleAbandonStuckSweep abandons a legacy-input sweep that stayed unconfirmed past
// SweepAbandonBlocks after a re-drive. Permissionless: every condition is on-chain state.
// Refuses, with no state change, anything else.
func (cs *ContractState) HandleAbandonStuckSweep(txId string) (string, error) {
	raw := sdk.StateGetObject(constants.MigrationSweepPrefix + txId)
	if raw == nil || *raw == "" {
		return "", ce.NewContractError(ce.ErrInput, "no in-flight migration sweep for that txid")
	}
	rec, err := UnmarshalMigrationSweep([]byte(*raw))
	if err != nil {
		return "", ce.NewContractError(ce.ErrStateAccess, "error decoding migration sweep record: "+err.Error())
	}

	// Scope: only a sweep of legacy entries, which is one input by construction. A
	// confirmed-pool input was SPV-proven to exist, so its sweep is only ever slow, and
	// re-drive is the tool for that.
	if len(rec.InputIds) == 0 || len(rec.InputIds) > constants.MaxLegacyInputsPerTranche {
		return "", ce.NewContractError(ce.ErrInput, "only a sweep of a single legacy input can be abandoned")
	}
	for _, id := range rec.InputIds {
		if id >= constants.UtxoConfirmedPoolStart {
			return "", ce.NewContractError(ce.ErrInput, "only a sweep of a single legacy input can be abandoned")
		}
	}

	// It must have been fee-bumped at least once, and every member of its spend group must
	// have stayed unconfirmed for SweepAbandonBlocks since it was built.
	gk := spendGroupKey(rec.InputIds)
	graw := sdk.StateGetObject(gk)
	if graw == nil || *graw == "" {
		return "", ce.NewContractError(ce.ErrTransaction, "re-drive the sweep first: only a sweep still unconfirmed after a fee bump can be abandoned")
	}
	group, err := UnmarshalSpendGroup([]byte(*graw))
	if err != nil {
		return "", ce.NewContractError(ce.ErrStateAccess, "corrupt spend-group object: refusing to abandon")
	}
	if len(group.Members) < 2 {
		return "", ce.NewContractError(ce.ErrTransaction, "re-drive the sweep first: only a sweep still unconfirmed after a fee bump can be abandoned")
	}
	members := make([]*MigrationSweep, len(group.Members))
	var latestBuild uint32
	var groupFee int64
	for i, m := range group.Members {
		mraw := sdk.StateGetObject(constants.MigrationSweepPrefix + m)
		if mraw == nil || *mraw == "" {
			return "", ce.NewContractError(ce.ErrStateAccess, "spend group member has no sweep record: refusing to abandon")
		}
		mrec, merr := UnmarshalMigrationSweep([]byte(*mraw))
		if merr != nil {
			return "", ce.NewContractError(ce.ErrStateAccess, "error decoding migration sweep record: "+merr.Error())
		}
		if !slices.Equal(mrec.InputIds, rec.InputIds) {
			return "", ce.NewContractError(ce.ErrStateAccess, "spend group member spends different inputs: refusing to abandon")
		}
		if mrec.BuildHeight > latestBuild {
			latestBuild = mrec.BuildHeight
		}
		if mrec.BtcFee > groupFee {
			groupFee = mrec.BtcFee
		}
		members[i] = mrec
	}
	nowH := currentLastHeight()
	if latestBuild == 0 || nowH < latestBuild || nowH-latestBuild < constants.SweepAbandonBlocks {
		return "", ce.NewContractError(ce.ErrTransaction, "sweep not unconfirmed long enough to abandon")
	}

	// The input is still registered (delete-at-confirm keeps it until a settle).
	var writtenOff int64
	for _, id := range rec.InputIds {
		found := false
		for _, e := range cs.UtxoList {
			if e.Id == id {
				writtenOff, err = safeAdd64(writtenOff, e.Amount)
				if err != nil {
					return "", ce.WrapContractError(ce.ErrArithmetic, err, "abandon input total overflow")
				}
				found = true
				break
			}
		}
		if !found {
			return "", ce.NewContractError(ce.ErrStateAccess, "abandoned sweep input missing from registry")
		}
	}

	// Charged to the fee reserve, never user principal (VR2-15), and only from the surplus
	// over what the OTHER in-flight sweeps have reserved: this group's own reservation is
	// released by the abandon. Reserve-short is a liveness stall cleared by a top-up
	// (permissionless), exactly like HandleWriteOffDust.
	_, pendingFeeSum, err := cs.pendingMigrationState()
	if err != nil {
		return "", err
	}
	othersReserved := pendingFeeSum - groupFee
	if othersReserved < 0 {
		othersReserved = 0
	}
	if cs.Supply.FeeSupply-othersReserved < writtenOff {
		return "", ce.NewContractError(ce.ErrBalance, "insufficient fee reserve to write off the abandoned sweep's input: top up the reserve")
	}

	for _, id := range rec.InputIds {
		cs.UtxoList = slices.DeleteFunc(cs.UtxoList, func(e UtxoRegistryEntry) bool { return e.Id == id })
		sdk.StateDeleteObject(getUtxoKey(id))
	}
	newFee, err := safeSubtract64(cs.Supply.FeeSupply, writtenOff)
	if err != nil {
		return "", ce.WrapContractError(ce.ErrArithmetic, err, "abandon fee reserve debit")
	}
	cs.Supply.FeeSupply = newFee

	for i, m := range group.Members {
		ab := &AbandonedSweep{Sweep: *members[i], WrittenOff: writtenOff, Members: group.Members}
		sdk.StateSetObject(constants.AbandonedSweepPrefix+m, string(MarshalAbandonedSweep(ab)))
	}
	// Takes every member's "ms-"/"d-" records and TxSpends entries and the group object
	// off the pending set, so nodes stop signing and broadcasting it.
	cs.clearSpendGroup(txId, rec.InputIds)

	sdk.Log("sweep-abandon|txid=" + txId + "|input=" + strconv.FormatUint(uint64(rec.InputIds[0]), 10) +
		"|writtenOff=" + strconv.FormatInt(writtenOff, 10) + "|members=" + strconv.Itoa(len(group.Members)) +
		"|feeSupply=" + strconv.FormatInt(newFee, 10))
	return "abandon: txid=" + txId + " writtenOff=" + strconv.FormatInt(writtenOff, 10), nil
}

// settleAbandonedSweep settles a member of an abandoned group that confirmed after all,
// called from HandleConfirmSpend under the tx's SPV proof. The record is keyed by the
// confirmed tx's own id, so its outputs are exactly the ones built. Indexes the swept
// output(s) to the successor and returns them to the reserve: net of the earlier
// write-off that is exactly a normal settle (Sigma(UTXO) and FeeSupply both down by the
// miner fee). Clears every member's record: the others spend the same input, so none of
// them can confirm now.
func (cs *ContractState) settleAbandonedSweep(msgTx *wire.MsgTx, ab *AbandonedSweep, blockHeight uint32) error {
	outUtxos, err := indexMigrationOutputs(msgTx, ab.Sweep.SuccessorAddress, cs.NetworkParams, ab.Sweep.SuccessorGen)
	if err != nil {
		return err
	}
	if len(outUtxos) == 0 {
		return ce.NewContractError(ce.ErrTransaction, "abandoned sweep confirmed with no output to the successor")
	}
	var outputTotal int64
	for _, u := range outUtxos {
		outputTotal, err = safeAdd64(outputTotal, u.Amount)
		if err != nil {
			return ce.WrapContractError(ce.ErrArithmetic, err, "abandoned sweep output total overflow")
		}
	}
	expected, err := safeSubtract64(ab.WrittenOff, ab.Sweep.BtcFee)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "abandoned sweep conservation arithmetic")
	}
	if outputTotal != expected {
		return ce.NewContractError(ce.ErrTransaction, "abandoned sweep conservation mismatch (outputs != written off - fee)")
	}

	observedVouts := make([]uint32, 0, len(outUtxos))
	for _, u := range outUtxos {
		newId, aerr := cs.allocateConfirmedId()
		if aerr != nil {
			return aerr
		}
		cs.UtxoList = append(cs.UtxoList, UtxoRegistryEntry{Id: newId, Amount: u.Amount})
		saveUtxo(newId, u)
		observedVouts = append(observedVouts, u.Vout)
	}
	if err := markOutpointsObserved(blockHeight, msgTx.TxID(), observedVouts); err != nil {
		return err
	}

	newFee, err := safeAdd64(cs.Supply.FeeSupply, outputTotal)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "abandoned sweep fee reserve credit")
	}
	cs.Supply.FeeSupply = newFee
	for _, m := range ab.Members {
		sdk.StateDeleteObject(constants.AbandonedSweepPrefix + m)
	}
	sdk.Log("sweep-abandon|late-settle|txid=" + msgTx.TxID() + "|returned=" + strconv.FormatInt(outputTotal, 10) +
		"|feeSupply=" + strconv.FormatInt(newFee, 10))
	return nil
}
