package mapping

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"

	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// SENDER-REFUND-1 (owner 11-21): a deposit swap that does not complete goes back
// to the address that SENT it, nobody types a refund address, and it never lands
// in a Magi balance. THORChain's bifrost takes the sender as the address of the
// output the deposit's first input spends (utxo client_internal.go getSender).
// This contract cannot read that from the deposit's own proof (the txid leaves
// out the witness, and anyone may submit a map), but it can prove it: the first
// input names the previous transaction by its txid, and an SPV proof of that
// transaction against a stored header gives its outputs, so the sending address
// is read from data the chain commits to. Nothing in it can be chosen by whoever
// submits the proof.
//
// proveSender is permissionless. Before the deposit is mapped it records the
// sender for map (constants.SenderPrefix); after, it sends the deposit's held
// parts (swaps that did not complete without a known sender, instructions the
// contract could not use) home to that address. A map made without it can only
// delay a refund, never redirect one.
//
// Limits: a call is at most 8,192 bytes and a txid commits to the whole
// transaction, so a previous transaction larger than that (an exchange's batched
// withdrawal) cannot be proven, and its block must still be inside the header
// window (MaxBlockRetention). Such deposits stay held for the owner's manual
// refund (releaseHold).

// HandleProveSender proves a deposit's sending address; it returns the address.
func (cs *ContractState) HandleProveSender(p *ProveSenderParams) (string, error) {
	if p == nil || p.Sender == nil {
		return "", ce.NewContractError(ce.ErrInput, "proveSender needs the deposit transaction and a sender proof")
	}
	var depRaw []byte
	var err error
	switch {
	case p.DepositTxHex != "" && p.DepositTxB64 != "":
		return "", ce.NewContractError(ce.ErrInput, "set deposit_tx_hex or deposit_tx_b64, not both")
	case p.DepositTxB64 != "":
		depRaw, err = base64.StdEncoding.DecodeString(p.DepositTxB64)
	default:
		depRaw, err = hex.DecodeString(p.DepositTxHex)
	}
	if err != nil || len(depRaw) == 0 {
		return "", ce.NewContractError(ce.ErrInput, "proveSender: the deposit transaction does not decode")
	}
	var dep wire.MsgTx
	if err := dep.Deserialize(bytes.NewReader(depRaw)); err != nil || len(dep.TxIn) == 0 {
		return "", ce.NewContractError(ce.ErrInput, "proveSender: the deposit transaction does not parse")
	}
	prevRaw, err := p.Sender.rawTx()
	if err != nil {
		return "", ce.WrapContractError(ce.ErrInvalidHex, err, "proveSender: the sender transaction does not decode")
	}
	if err := verifyTransaction(p.Sender, prevRaw); err != nil {
		return "", ce.Prepend(err, "proveSender: the sender transaction is not proven")
	}
	var prev wire.MsgTx
	if err := prev.Deserialize(bytes.NewReader(prevRaw)); err != nil {
		return "", ce.NewContractError(ce.ErrInput, "proveSender: the sender transaction does not parse")
	}
	in := dep.TxIn[0].PreviousOutPoint
	if prev.TxHash() != in.Hash || int(in.Index) >= len(prev.TxOut) {
		return "", ce.NewContractError(ce.ErrInput, "proveSender: that is not the output the deposit's first input spends")
	}
	// An output the vault indexed (a deposit, a change output) is the vault's: a
	// vault transaction that pays a deposit address has no user sender, and a
	// refund there would vanish into the vault.
	if entry, err := makeObservedEntry(prev.TxID(), in.Index); err == nil && isObserved(loadObservedList(p.Sender.BlockHeight), entry) {
		return "", ce.NewContractError(ce.ErrInput, "proveSender: the spent output belongs to the vault")
	}
	class, addrs, _, err := txscript.ExtractPkScriptAddrs(prev.TxOut[in.Index].PkScript, cs.NetworkParams)
	if err != nil || len(addrs) != 1 {
		return "", ce.NewContractError(ce.ErrInput, "proveSender: the spent output has no single address")
	}
	switch class {
	case txscript.PubKeyHashTy, txscript.ScriptHashTy, txscript.WitnessV0PubKeyHashTy,
		txscript.WitnessV0ScriptHashTy, txscript.WitnessV1TaprootTy:
	default:
		return "", ce.NewContractError(ce.ErrInput, "proveSender: the spent output is not a standard address")
	}
	sender := addrs[0].EncodeAddress()

	txid := dep.TxID()
	moved := int64(0)
	for vout := range dep.TxOut {
		op := outpointLabel(txid, uint32(vout))
		pending := getRecordAmount(constants.SenderPendingPrefix + op)
		if pending <= 0 {
			continue
		}
		heldKey := constants.RefundHoldPrefix + op
		amount := getRecordAmount(heldKey)
		if amount > pending {
			amount = pending
		}
		setRecordAmount(constants.SenderPendingPrefix+op, 0)
		if amount <= 0 {
			continue
		}
		bal := getAccBal(constants.RefundHoldAccount)
		if bal < amount {
			return "", ce.NewContractError(ce.ErrStateAccess, "proveSender: hold account below the record for "+op)
		}
		setAccBal(constants.RefundHoldAccount, bal-amount)
		setRecordAmount(heldKey, getRecordAmount(heldKey)-amount)
		if err := holdForAddress(sender, amount); err != nil {
			return "", ce.Prepend(err, "proveSender")
		}
		sdk.Log(refundLog("senderrefund", sender, amount, "sender proven", op))
		moved += amount
	}
	if moved == 0 {
		// Not mapped yet (or nothing of it held): map reads the sender.
		sdk.StateSetObject(constants.SenderPrefix+txid, sender)
	}
	sdk.Log("sender" + constants.LogDelimiter + "tx" + constants.LogKeyDelimiter + txid +
		constants.LogDelimiter + "s" + constants.LogKeyDelimiter + sender)
	return sender, nil
}

// magiNamesBtcAddress reports whether the node gives addr a Magi identity
// (dids.ParseBtcDID / ParseBtcTestnetDID accept P2PKH, P2SH and P2WPKH only).
func magiNamesBtcAddress(addr string, net *chaincfg.Params) bool {
	a, err := btcutil.DecodeAddress(addr, net)
	if err != nil {
		return false
	}
	switch a.(type) {
	case *btcutil.AddressPubKeyHash, *btcutil.AddressScriptHash, *btcutil.AddressWitnessPubKeyHash:
		return true
	}
	return false
}
