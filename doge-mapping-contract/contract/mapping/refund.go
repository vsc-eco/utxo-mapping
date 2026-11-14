package mapping

import (
	"net/url"
	"strconv"
	"strings"

	"doge-mapping-contract/contract/constants"
	ce "doge-mapping-contract/contract/contracterrors"
	"doge-mapping-contract/sdk"
)

// A deposit swap that does not complete goes back to its sender, never to
// swap_to, which may be a third party (an exchange, a payment processor).
//
// Who the sender is cannot be read from the deposit: the SPV proof covers the
// txid, which excludes the witness that names the sending address, and anyone
// may submit a map. So the sender names its refund target in the instruction:
// refund_to=hive:<name>. The instruction is hashed into the deposit address, so
// the target is fixed before any coin is sent. With no usable refund_to the
// deposit is held (RefundHoldAccount) for a manual refund by the owner
// (releaseHold). Ported from btc-mapping-contract (refund.go); this chain takes
// hive: refunds only, as it has no sendHome.

// parseRefundTo is refund_to's hive: account, or "" when it names none.
func parseRefundTo(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "hive:") && sdk.VerifyAddress(raw) == "user:hive" {
		return raw
	}
	return ""
}

// settlesSynchronously reports whether a payout on destinationChain is final
// inside the swap (Magi or Hive). Any other payout settles later, and if it fails
// the router refunds it to the instruction's return_address.
func settlesSynchronously(destinationChain string) bool {
	switch strings.ToUpper(strings.TrimSpace(destinationChain)) {
	case "", "MAGI", "HIVE":
		return true
	}
	return false
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

// refundDepositSwap sends amount of a deposit swap that did not complete back
// to its sender (refund_to), or holds it. The amount must not be credited anywhere.
func refundDepositSwap(metadata *AddressMetadata, amount int64, reason, outpoint string) error {
	if amount <= 0 {
		return nil
	}
	if metadata.RefundAccount != "" {
		if err := incAccBalance(metadata.RefundAccount, amount); err != nil {
			return ce.Prepend(err, "swap refund: crediting refund_to")
		}
		sdk.Log(refundLog("swaprefund", metadata.RefundAccount, amount, reason, outpoint))
		return nil
	}
	return holdDeposit(amount, reason, outpoint)
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
	sdk.Log(refundLog("swaphold", "", amount, reason, outpoint))
	return nil
}

// refundWording describes where a refund went, for the map's log line.
func refundWording(metadata *AddressMetadata, amount int64, verb string) string {
	n := strconv.FormatInt(amount, 10) + " sats"
	if metadata.RefundAccount != "" {
		return verb + " " + n + " to " + metadata.RefundAccount
	}
	return "held " + n + " for a manual refund"
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
		return ce.Prepend(err, "releaseHold: crediting the sender")
	}
	setRecordAmount(key, 0)
	sdk.Log(refundLog("holdrelease", to, amount, "owner", outpoint))
	return nil
}
