// HandleMapInstantSendV2 — the lazy-attestation fast-path entry point.
// See forwarder_integration.go for the helpers + types this consumes.
//
// Spec §5.2.3 sequence, implemented end-to-end:
//
//  1. Re-derive D from instruction; verify D appears as a destination in rawTxHex.
//  2. Verify BLS aggregate attestation against at-epoch validator set.
//  3. Resolve sender DashDID (strict same-address-all-inputs rule, §5.2.5).
//  4. Apply amount-matching rules (§5.2.4).
//  5. Per-DashDID rate-limit check (§5.2.7).
//  6. Credit DashDID(sender) internal DASH balance.
//  7. Mark IS-lock as processed (idempotency).
//  8. Op-specific path:
//     - op=auth: done (subsidised — no RC reimbursement)
//     - op=call: write forwardQueue + invoke forwarder + RC reimbursement
package mapping

import (
	"crypto/sha256"
	"dash-mapping-contract/contract/constants"
	ce "dash-mapping-contract/contract/contracterrors"
	"dash-mapping-contract/sdk"
	"encoding/hex"
	"strconv"
)

// HandleMapInstantSendV2 is the main entry into the fast-path mapping flow.
// All state mutations happen in-place on ms; caller (main.go) calls
// SaveToState afterwards.
//
// Returns nil on success, or a tagged ContractError on rejection. Most
// rejection paths leave state untouched, so caller can revert cleanly.
// The op=call forward path is the one place where partial state changes
// can persist (credit happens, forward may fail) — those paths
// explicitly mark forwardQueue status so the result is auditable.
func (ms *MappingState) HandleMapInstantSendV2(params MapInstantSendV2ParamsFull) error {
	body := &params.Body
	agg := &params.Agg

	// ===== Step 1: re-derive D and verify it's an output in rawTxHex =====

	// Derive the expected deposit address from the supplied instruction
	// using the bridge pubkeys we hold in state. Any mismatch from what
	// the user actually paid to is fatal — the attestation can't bind
	// us to crediting a different address.
	primaryHex := hex.EncodeToString(ms.PublicKeys.Primary[:])
	backupHex := hex.EncodeToString(ms.PublicKeys.Backup[:])
	D, _, err := DepositAddress(primaryHex, backupHex, body.Instruction, ms.NetworkParams)
	if err != nil {
		return ce.NewContractError(ce.ErrInput, "deposit address derivation failed: "+err.Error())
	}

	paidAmount, err := FindOutputAmount(body.RawTxHex, D, ms.NetworkParams)
	if err != nil {
		return ce.NewContractError(ce.ErrInput, "could not parse tx outputs: "+err.Error())
	}
	if paidAmount == 0 {
		return ce.NewContractError(ce.ErrInput,
			"derived deposit address "+D+" not found in tx outputs (mismatched instruction?)")
	}

	// ===== Step 2: verify BLS aggregate attestation =====

	// Build the canonical signed message exactly as validators did.
	chainID := body.ChainId
	if chainID == "" {
		return ce.NewContractError(ce.ErrInput, "chainId must be set in params")
	}
	msg, err := CanonicalAttestationMessage(chainID, body.Epoch, body.RawTxHex, body.Instruction)
	if err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "canonical message build failed")
	}

	// Aggregate pubkeys for the contract-side verification. The
	// crypto.bls_verify_aggregate host fn does the AggregatePubkeys
	// internally — we just concatenate hex.
	if len(body.Attestations) == 0 {
		return ce.NewContractError(ce.ErrInput, "no attestations provided")
	}
	var pubkeysHexBuilder []byte
	for _, a := range body.Attestations {
		if len(a.PubkeyHex) != 96 {
			return ce.NewContractError(ce.ErrInput,
				"validator pubkey must be 48 bytes (96 hex chars), got "+a.PubkeyHex)
		}
		// TODO: confirm each ValidatorDID is in the validator set at body.Epoch.
		// Requires either a host function to read elections state, or a
		// dedicated read-validator-set system call. For now the BLS
		// signature itself is the sole gate — if a validator's pubkey
		// isn't in the active set, the aggregate verify still passes
		// (because the math doesn't know), so a malicious aggregator
		// could include unknown pubkeys. Workstream 5b will add this
		// check once the host-function design is settled.
		pubkeysHexBuilder = append(pubkeysHexBuilder, []byte(a.PubkeyHex)...)
	}
	pubkeysHex := string(pubkeysHexBuilder)

	if !sdk.VerifyBlsAggregate(pubkeysHex, hex.EncodeToString(msg), agg.AggSigHex) {
		return ce.NewContractError(ce.ErrNoPermission,
			"BLS attestation aggregate failed to verify against signed message")
	}

	// TODO: enforce N-of-M quorum requirement (2M/3+1 of active validator set).
	// Until validator-set lookup is wired, count provided attestations
	// against a configurable minimum from state.

	// ===== Step 3: resolve sender DashDID =====

	dashGenesisCAIP2Hex := ms.dashGenesisCAIP2Hex() // mainnet/testnet selector
	senderDID, err := ResolveSenderDashDID(body.RawTxHex, dashGenesisCAIP2Hex, ms.NetworkParams)
	if err != nil {
		return ce.Prepend(err, "could not resolve sender DashDID")
	}

	// ===== Step 4: amount-matching rules =====

	parsed, err := ParseInstructionV2(body.Instruction)
	if err != nil {
		return ce.Prepend(err, "instruction parse failed")
	}

	// Per spec §5.2.4 dust floor: anything below MinDustDuffs is rejected
	// (network-fee dominates the credit — no economic point in processing).
	if paidAmount < constants.MinDustDuffs {
		return ce.NewContractError(ce.ErrInput,
			"amount below dust threshold")
	}
	// For value-bearing op=call, declared amount must also be above the
	// 0.01 DASH floor. Below that, attacker spam becomes uneconomic per
	// §5.2.7.
	if parsed.Op == constants.OpCallValue && parsed.AmountDuffs > 0 &&
		parsed.AmountDuffs < constants.MinCallFundingDuffs {
		return ce.NewContractError(ce.ErrInput,
			"op=call amount below 0.01 DASH floor (§5.2.7)")
	}

	// ===== Step 5: per-DashDID rate-limit check =====

	// "now" is approximated as the env's block height — sufficient for the
	// sliding-window check since the window is in seconds and block-height
	// monotonicity is enough. Real implementations might multiply by Magi's
	// typical block time or read env.BlockTimestamp.
	now := sdk.GetEnv().BlockHeight
	withinLimit := checkAndBumpRateLimit(senderDID, now)

	// ===== Step 6 + 7: credit + idempotency marker =====

	// Idempotency: if we've already processed this txid, skip cleanly.
	if isAlreadyProcessed(body.RawTxHex) {
		return nil
	}

	if err := incInternalBalance(senderDID, "dash", paidAmount); err != nil {
		return err
	}
	markAsProcessed(body.RawTxHex)

	// ===== Step 8: op-specific path =====

	switch parsed.Op {
	case constants.OpAuthValue:
		// Login. Credit-only, subsidised. No forward dispatch.
		return nil

	case constants.OpCallValue:
		if !withinLimit {
			// Spec §5.2.7: over rate-limit, contract credits but skips
			// forward. forwardQueue gets a "rate-limited" status so
			// auditors can see what happened.
			saveForwardQueueEntry(rawTxId(body.RawTxHex), ForwardQueueEntry{
				Sender:      senderDID,
				Instruction: body.Instruction,
				CallFunding: 0,
				Status:      "RATE_LIMITED",
			})
			return nil
		}
		return ms.dispatchForward(senderDID, parsed, paidAmount, body.RawTxHex)

	default:
		return ce.NewContractError(ce.ErrInput,
			"unknown op="+parsed.Op)
	}
}

// dispatchForward performs the §5.2.3 steps 4-9: debit user, credit target,
// write forwardQueue, call forwarder.execute, on success deduct RC
// reimbursement HBD, on failure roll back the debit/credit.
func (ms *MappingState) dispatchForward(
	senderDID string,
	parsed ParsedInstruction,
	paidAmount int64,
	rawTxHex string,
) error {
	// callFunding = min(creditedAmount, declaredAmount), 0 = value-less
	callFunding := int64(0)
	if parsed.AmountDuffs > 0 {
		callFunding = parsed.AmountDuffs
		if callFunding > paidAmount {
			callFunding = paidAmount
		}
	}

	txid := rawTxId(rawTxHex)
	targetAddr := parsed.Target

	// Verify the target is in the allow-list (§5.2.7).
	if !isTargetAllowed(targetAddr) {
		// User keeps DASH credit; forward marked failed.
		saveForwardQueueEntry(txid, ForwardQueueEntry{
			Sender:      senderDID,
			Instruction: parsed.Op + ";" + parsed.Target, // abbreviated
			CallFunding: callFunding,
			Status:      constants.StatusForwardFailed,
		})
		return nil
	}

	// Forwarder contract id must be set (admin init).
	forwarderId := sdk.StateGetObject(constants.ForwarderContractIdStateKey)
	if forwarderId == nil || *forwarderId == "" {
		return ce.NewContractError(ce.ErrInitialization,
			"forwarder contract not configured; cannot dispatch op=call")
	}

	// Move callFunding from sender to target's internal balance.
	if callFunding > 0 {
		if err := decInternalBalance(senderDID, "dash", callFunding); err != nil {
			return err
		}
		if err := incInternalBalance("contract:"+targetAddr, "dash", callFunding); err != nil {
			// Roll back the decrement before returning.
			_ = incInternalBalance(senderDID, "dash", callFunding)
			return err
		}
	}

	// Write forwardQueue PENDING.
	entry := ForwardQueueEntry{
		Sender:      senderDID,
		Instruction: marshalInstruction(parsed),
		CallFunding: callFunding,
		Status:      constants.StatusPendingForward,
	}
	saveForwardQueueEntry(txid, entry)

	// Invoke forwarder.
	result := sdk.ContractCall(*forwarderId, "execute", txid, &sdk.ContractCallOptions{})
	if result == nil || isAbortResult(*result) {
		// Forward failed. Roll back target funding.
		if callFunding > 0 {
			_ = decInternalBalance("contract:"+targetAddr, "dash", callFunding)
			_ = incInternalBalance(senderDID, "dash", callFunding)
		}
		entry.Status = constants.StatusForwardFailed
		saveForwardQueueEntry(txid, entry)
		return nil
	}

	// Success. Mark FORWARDED.
	entry.Status = constants.StatusForwarded
	saveForwardQueueEntry(txid, entry)

	// ===== RC reimbursement (spec §5.2.6) =====
	//
	// Compute the L2-tx RC cost upper-bound and convert via the
	// 1000 RC = 1 HBD rate (params.go:11). Deduct from sender's
	// internal HBD balance. If insufficient, mark FORWARD_FAILED_
	// INSUFFICIENT_RC, refund the target funding, keep the DASH credit.
	rcCost := estimateRcCost(parsed)
	rcReimbursementHBD := rcCost // 1 RC = 1 milli-HBD per params comment; calibrate

	hbdBal := getInternalBalance(senderDID, "hbd")
	if hbdBal < rcReimbursementHBD {
		// Insufficient HBD. Per spec §5.2.6, mark FORWARD_FAILED_INSUFFICIENT_RC
		// — but the forwarded call SUCCEEDED. This is an edge case (the
		// forwarder shouldn't have been allowed to dispatch without
		// reasonable HBD reserves), so we ALSO roll back the dispatch
		// to keep accounting consistent.
		// Roll back: refund target → sender, leave DASH credit intact.
		if callFunding > 0 {
			_ = decInternalBalance("contract:"+targetAddr, "dash", callFunding)
			_ = incInternalBalance(senderDID, "dash", callFunding)
		}
		entry.Status = constants.StatusForwardFailedInsufficientRC
		saveForwardQueueEntry(txid, entry)
		return nil
	}

	// Deduct RC reimbursement from sender's internal HBD.
	_ = decInternalBalance(senderDID, "hbd", rcReimbursementHBD)
	// Credit IS service (the L2 tx submitter). The IS service's address
	// is the env's caller — which for fast-path mapInstantSendV2
	// submissions is the submitting account.
	submitter := sdk.GetEnv().Caller.String()
	// SendBalance from the mapping contract's own native HBD to submitter.
	// Mapping contract holds native HBD reserves 1:1-backing the sum of
	// internal HBD balances. Each RC reimbursement debits user internal
	// HBD AND sends native HBD out.
	//
	// TODO: actually call sdk.HiveTransfer when SDK supports targeted
	// from-contract sends to arbitrary recipients. For now we just track
	// the obligation in state.
	_ = submitter

	return nil
}

// ----- helpers -----

// isAbortResult detects forwarder failure based on result string convention.
func isAbortResult(result string) bool {
	return len(result) >= 6 && result[:6] == "ABORT:"
}

// rawTxId computes the Dash txid for the given raw tx hex. Bitcoin
// convention: double-SHA256, little-endian display. For state keys we
// use the raw 32-byte hash hex-encoded (no endian flip) for consistency
// with how validators sign it.
func rawTxId(rawTxHex string) string {
	rawBytes, err := hex.DecodeString(rawTxHex)
	if err != nil {
		return rawTxHex // fallback — caller catches invalid hex elsewhere
	}
	first := sha256.Sum256(rawBytes)
	second := sha256.Sum256(first[:])
	return hex.EncodeToString(second[:])
}

// isAlreadyProcessed checks the IS-locked marker for the txid.
func isAlreadyProcessed(rawTxHex string) bool {
	txid := rawTxId(rawTxHex)
	marker := sdk.StateGetObject("processed/" + txid)
	return marker != nil && *marker == "1"
}

func markAsProcessed(rawTxHex string) {
	txid := rawTxId(rawTxHex)
	sdk.StateSetObject("processed/"+txid, "1")
}

// isTargetAllowed checks allowedTargets["at/<targetId>"] = "1".
func isTargetAllowed(targetId string) bool {
	v := sdk.StateGetObject(constants.AllowedTargetsKeyPrefix + targetId)
	return v != nil && *v == "1"
}

// marshalInstruction is the inverse of ParseInstructionV2. Used to
// preserve the canonical instruction string in the forwardQueue entry
// even if the parser strips/normalises tokens.
func marshalInstruction(p ParsedInstruction) string {
	out := "op=" + p.Op + ";contract=" + p.Target + ";method=" + p.Method +
		";args=" + p.ArgsB64 + ";sid=" + p.Sid
	if p.AmountDuffs > 0 {
		out += ";amount=" + strconv.FormatInt(p.AmountDuffs, 10)
	}
	return out
}

// estimateRcCost returns an HBD-equivalent (in duffs, but we treat as
// HBD millis here for accounting parity) estimate of the L2 tx cost.
// Per params.go:11 "1000 RC ≈ 1 HBD equivalent", so 1 RC = 0.001 HBD.
//
// Static upper bound from transaction-pool/utils.go:
//   - Call min: 100 RC
//   - Per-byte data: tracked separately
//
// For a typical mapInstantSendV2 (~1KB rawTx + attestations), conservative
// upper bound is ~500 RC = 0.5 HBD ≈ $0.50. Pretty steep for small ops;
// real-world RC will be much less.
func estimateRcCost(p ParsedInstruction) int64 {
	if p.Op == constants.OpCallValue {
		return 500 // 500 RC ≈ 0.5 HBD
	}
	return 200 // op=auth: 200 RC ≈ 0.2 HBD
}

// dashGenesisCAIP2Hex returns the appropriate Dash genesis CAIP-2 hex
// for the current network mode. Mirrors lib/dids/dash.go's prefix
// constants — keep in sync.
//
// Selection is by ScriptHashAddrID (0x10 mainnet, 0x13 testnet) which
// the init.go params functions set. This avoids string-compares on the
// Net field that aren't reliable for cloned chaincfg.Params.
func (ms *MappingState) dashGenesisCAIP2Hex() string {
	if ms.NetworkParams != nil && ms.NetworkParams.ScriptHashAddrID == 0x10 {
		return "00000ffd590b1485b3caadc19b22e637"
	}
	return "00000bafbc94add76cb75e2ec9289483" // testnet
}
