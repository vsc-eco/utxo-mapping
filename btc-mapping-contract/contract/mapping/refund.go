package mapping

import (
	"net/url"
	"strconv"
	"strings"

	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

// refund.go: a deposit swap either completes, or goes back to its sender, or is
// held for a manual refund. It is never paid to the swap's recipient (swap_to),
// which may be a third party such as an exchange or a payment processor.
//
// Who the sender is cannot be read from the deposit: the SPV proof covers the
// txid, which excludes the witness that names the sending address, and anyone
// may submit a map. So the sender names its refund target in the instruction
// (refund_to). The instruction is hashed into the deposit address, so the target
// is fixed before any BTC is sent.
//
//   - refund_to=hive:<name>: credited there. A hive: account has free RC.
//   - refund_to=<btc address> (or its did:pkh:bip122 DID): credited to the
//     address's Magi account and recorded as refundable. sendHome, which anyone
//     may call and pay the RC for, returns it to that address on Bitcoin, so a
//     wallet account with no HBD (no RC) is never stuck.
//   - none, or a value the contract cannot use: held (RefundHoldAccount) for a
//     manual refund by the owner (releaseHold).

// parseRefundTo resolves a refund_to value. Anything it cannot use is RefundNone.
func parseRefundTo(raw string, net *chaincfg.Params) (RefundKind, string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return RefundNone, "", ""
	}
	if strings.HasPrefix(raw, "hive:") {
		if sdk.VerifyAddress(raw) == "user:hive" {
			return RefundMagi, raw, ""
		}
		return RefundNone, "", ""
	}
	addrPart := raw
	if strings.HasPrefix(raw, "did:pkh:bip122:") {
		addrPart = raw[strings.LastIndex(raw, ":")+1:]
	}
	addr, err := btcutil.DecodeAddress(addrPart, net)
	if err != nil || !addr.IsForNet(net) {
		return RefundNone, "", ""
	}
	encoded := addr.EncodeAddress()
	return RefundBtc, btcRefundAccount(encoded, net), encoded
}

// btcRefundAccount is the Magi account of a Bitcoin address (its did:pkh DID).
func btcRefundAccount(addr string, net *chaincfg.Params) string {
	if net != nil && net.Name == chaincfg.MainNetParams.Name {
		return constants.BtcDIDMainnetPrefix + addr
	}
	return constants.BtcDIDTestnetPrefix + addr
}

func outpointLabel(txId string, vout uint32) string {
	return txId + ":" + strconv.FormatUint(uint64(vout), 10)
}

func getRecordAmount(key string) int64 {
	v := sdk.StateGetObject(key)
	if v == nil || *v == "" {
		return 0
	}
	n, err := strconv.ParseInt(*v, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func setRecordAmount(key string, amount int64) {
	if amount <= 0 {
		sdk.StateDeleteObject(key)
		return
	}
	sdk.StateSetObject(key, strconv.FormatInt(amount, 10))
}

func refundLog(kind, target string, amount int64, reason, outpoint string) string {
	d, k := constants.LogDelimiter, constants.LogKeyDelimiter
	s := kind
	if target != "" {
		s += d + "t" + k + target
	}
	s += d + "a" + k + strconv.FormatInt(amount, 10) + d + "r" + k + reason + d + "o" + k + outpoint
	return s
}

// refundDepositSwap sends `amount` of a deposit swap that did not complete back
// to its sender, or holds it. The amount must not already be credited anywhere.
func refundDepositSwap(metadata *AddressMetadata, amount int64, reason, outpoint string) error {
	if amount <= 0 {
		return nil
	}
	switch metadata.RefundKind {
	case RefundMagi:
		if err := incAccBalance(metadata.RefundAccount, amount); err != nil {
			return ce.Prepend(err, "swap refund: crediting refund_to")
		}
		sdk.Log(refundLog("swaprefund", metadata.RefundAccount, amount, reason, outpoint))
		return nil
	case RefundBtc:
		// SENDER-REFUND-1: held for the address and sent home from the hold, never
		// credited to the address's own Magi account (owner 11-21).
		if err := holdForAddress(metadata.RefundBtcAddr, amount); err != nil {
			return ce.Prepend(err, "swap refund")
		}
		sdk.Log(refundLog("swaprefund", metadata.RefundAccount, amount, reason, outpoint))
		return nil
	default:
		return holdDeposit(amount, reason, outpoint)
	}
}

// holdDeposit keeps a deposit for a manual refund (releaseHold). Nothing else can
// move RefundHoldAccount: no caller is that account.
func holdDeposit(amount int64, reason, outpoint string) error {
	if amount <= 0 {
		return nil
	}
	if err := incAccBalance(constants.RefundHoldAccount, amount); err != nil {
		return ce.Prepend(err, "hold: crediting the hold account")
	}
	key := constants.RefundHoldPrefix + outpoint
	total, err := safeAdd64(getRecordAmount(key), amount)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "hold: record total")
	}
	setRecordAmount(key, total)
	// Until the owner releases it, proving the deposit's sender (proveSender)
	// sends it home to the sending address.
	setRecordAmount(constants.SenderPendingPrefix+outpoint, total)
	sdk.Log(refundLog("swaphold", "", amount, reason, outpoint))
	return nil
}

// holdForAddress holds amount owed to a Bitcoin address on BtcRefundHoldAccount
// and adds it to the address's refundable total and its held part.
func holdForAddress(addr string, amount int64) error {
	if amount <= 0 {
		return nil
	}
	if err := incAccBalance(constants.BtcRefundHoldAccount, amount); err != nil {
		return ce.Prepend(err, "crediting the refund hold")
	}
	for _, key := range []string{constants.RefundablePrefix + addr, constants.RefundHeldPrefix + addr} {
		total, err := safeAdd64(getRecordAmount(key), amount)
		if err != nil {
			return ce.WrapContractError(ce.ErrArithmetic, err, "refund hold: record total")
		}
		setRecordAmount(key, total)
	}
	return nil
}

// HandleSendHome returns a Bitcoin address's refunded sats to that address on
// Bitcoin. Anyone may call it (the caller pays the RC); the destination is the
// address itself and the amount is at most what was refunded to it, so it cannot
// move anyone's funds anywhere else. The miner fee comes out of the amount.
// Input: the address, bare or as a JSON string (the mapping bot sends JSON).
func (cs *ContractState) HandleSendHome(input string) error {
	raw := strings.TrimSpace(input)
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		raw = raw[1 : len(raw)-1]
	}
	addr, err := btcutil.DecodeAddress(raw, cs.NetworkParams)
	if err != nil || !addr.IsForNet(cs.NetworkParams) {
		return ce.NewContractError(ce.ErrInput, "sendHome needs a Bitcoin address on this network")
	}
	encoded := addr.EncodeAddress()
	key := constants.RefundablePrefix + encoded
	refundable := getRecordAmount(key)
	if refundable <= 0 {
		return ce.NewContractError(ce.ErrInput, "nothing refundable for "+encoded)
	}
	// SENDER-REFUND-1: what is held for the address goes first, from the hold
	// (only up to the address's own held record, so one address can never draw
	// another's); a refund from before it sits on the address's own account.
	heldKey := constants.RefundHeldPrefix + encoded
	held := getRecordAmount(heldKey)
	holder := btcRefundAccount(encoded, cs.NetworkParams)
	if held > 0 {
		holder = constants.BtcRefundHoldAccount
		if held < refundable {
			refundable = held
		}
	}
	bal := getAccBal(holder)
	amount := refundable
	if bal < amount {
		amount = bal
	}
	if amount <= 0 {
		setRecordAmount(key, 0)
		return ce.NewContractError(ce.ErrInput, "the refunded sats have already left "+holder)
	}
	// A held refund that can never be sent (not above the dust limit plus the
	// Magi fee, whatever the miner fee) is fee (THORChain: a refund below its
	// outbound fee is not sent): it leaves the hold for the fee supply instead
	// of sitting there for good. Above that it waits for the miner fee.
	if held > 0 {
		vscFee, ferr := calcVscFee(amount)
		if ferr != nil || amount <= dustThreshold+vscFee {
			setAccBal(holder, bal-amount)
			setRecordAmount(heldKey, held-amount)
			setRecordAmount(key, getRecordAmount(key)-amount)
			newUser, uerr := safeSubtract64(cs.Supply.UserSupply, amount)
			newFee, ferr2 := safeAdd64(cs.Supply.FeeSupply, amount)
			if uerr != nil || ferr2 != nil {
				return ce.NewContractError(ce.ErrArithmetic, "sendHome: booking a dust refund as fee")
			}
			cs.Supply.UserSupply, cs.Supply.FeeSupply = newUser, newFee
			sdk.Log("sendhome" + constants.LogDelimiter + "dust" + constants.LogDelimiter + "t" + constants.LogKeyDelimiter + encoded +
				constants.LogDelimiter + "a" + constants.LogKeyDelimiter + strconv.FormatInt(amount, 10))
			return nil
		}
	}
	instr := &TransferParams{
		Amount:    strconv.FormatInt(amount, 10),
		To:        encoded,
		From:      holder,
		DeductFee: true,
	}
	if err := cs.handleUnmap(instr, true); err != nil {
		return ce.Prepend(err, "sendHome")
	}
	// What left the account is the Magi fee + the amount sent + the true miner fee
	// (ACCT-1). An over-estimated miner fee stays with the owner; it stays
	// refundable too, so it goes home with the address's next refund.
	after := getAccBal(holder)
	debited := bal - after
	if held > 0 {
		// The address's records go down by what left the hold; nothing caps them
		// at the pooled hold's balance (it holds other addresses' refunds too).
		setRecordAmount(heldKey, held-debited)
		setRecordAmount(key, getRecordAmount(key)-debited)
	} else {
		left := refundable - debited
		if left > after {
			left = after
		}
		setRecordAmount(key, left)
	}
	sdk.Log("sendhome" + constants.LogDelimiter + "t" + constants.LogKeyDelimiter + encoded +
		constants.LogDelimiter + "a" + constants.LogKeyDelimiter + strconv.FormatInt(amount, 10))
	return nil
}

// HandleReleaseHold moves a held deposit to the account its owner proves is the
// sender. Owner only. Input: "o=<txid>:<vout>&to=<user address>".
func HandleReleaseHold(input, caller, owner string) error {
	if caller == "" || caller != owner {
		return ce.NewContractError(ce.ErrNoPermission, "releaseHold is for the contract owner")
	}
	params, err := url.ParseQuery(input)
	if err != nil {
		return ce.NewContractError(ce.ErrInput, "releaseHold input: o=<txid>:<vout>&to=<address>")
	}
	outpoint, to := params.Get("o"), params.Get("to")
	if outpoint == "" || !strings.HasPrefix(sdk.VerifyAddress(to), "user:") {
		return ce.NewContractError(ce.ErrInput, "releaseHold needs o=<txid>:<vout> and a user address to=")
	}
	key := constants.RefundHoldPrefix + outpoint
	amount := getRecordAmount(key)
	if amount <= 0 {
		return ce.NewContractError(ce.ErrInput, "no held deposit "+outpoint)
	}
	held := getAccBal(constants.RefundHoldAccount)
	if held < amount {
		return ce.NewContractError(ce.ErrStateAccess, "hold account below the record for "+outpoint)
	}
	setAccBal(constants.RefundHoldAccount, held-amount)
	if err := incAccBalance(to, amount); err != nil {
		return ce.Prepend(err, "releaseHold: crediting the owner")
	}
	setRecordAmount(key, 0)
	setRecordAmount(constants.SenderPendingPrefix+outpoint, 0)
	sdk.Log(refundLog("holdrelease", to, amount, "owner", outpoint))
	return nil
}

// deductOwnRefund debits a sendHome withdrawal from the refunded address's own
// account. Only HandleSendHome reaches it (through handleUnmap's homeRefund).
func deductOwnRefund(account string, amount int64) error {
	bal := getAccBal(account)
	if bal < amount {
		return ce.NewContractError(ce.ErrBalance, "account ["+account+"] balance "+
			strconv.FormatInt(bal, 10)+" insufficient needs "+strconv.FormatInt(amount, 10))
	}
	setAccBal(account, bal-amount)
	return nil
}

// refundWording keeps the human-readable refund log as it was when the deposit
// does go back ("credited N sats to depositor" / "refunded N unspent sats to
// depositor"), and says so when it is held instead.
func refundWording(metadata *AddressMetadata, amount int64, verb, qualifier string) string {
	n := strconv.FormatInt(amount, 10)
	if metadata.RefundKind == RefundNone {
		return "held " + n + " " + qualifier + "sats for a manual refund"
	}
	return verb + " " + n + " " + qualifier + "sats to depositor"
}

// settlesSynchronously: a payout that either happens inside the swap call or
// reverts it (Magi itself, or Hive through the gateway). Any other chain is paid
// by a withdrawal that can fail later, after the swap.
func settlesSynchronously(destinationChain string) bool {
	switch strings.ToUpper(strings.TrimSpace(destinationChain)) {
	case "", "MAGI", "HIVE":
		return true
	}
	return false
}
