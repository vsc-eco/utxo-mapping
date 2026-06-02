// Package mapping — workstream 5 scaffold for the Dash InstantSend login
// feature's forwarder integration.
//
// This file is the staging area for the new logic that will be wired into
// HandleMapInstantSend in workstream 5. The function signatures, state
// schemas, and step ordering are pinned here so the dash-forwarder-contract
// (workstream 6) has a stable target to integrate against.
//
// Status: scaffold + design — these functions return errors until the team
// completes the live integration. Tests run them with stub state. The
// existing slow-path map() flow is unaffected; this lives alongside it.
//
// Cross-references:
//   - Spec §5.2.2 lazy-attestation auth model
//   - Spec §5.2.3 pay-and-call atomicity sequence
//   - Spec §5.2.6 RC accounting via internal HBD ledger
//   - Spec §5.2.7 rate limits + allow-list governance
//   - dash-forwarder-contract/contract/forwarder/forwarder.go (the contract
//     this dispatches to)
package mapping

import (
	"dash-mapping-contract/contract/constants"
	ce "dash-mapping-contract/contract/contracterrors"
	"strings"
)

// MapInstantSendV2Params is the new payload shape for the lazy-attestation
// fast path. Compare with the original MapInstantSendParams (rawTxHex only)
// — v2 carries the validator attestations bundle and the instruction
// string the user paid for.
//
//tinyjson:json
type MapInstantSendV2Params struct {
	RawTxHex     string                  `json:"rawTxHex"`
	Instruction  string                  `json:"instruction"`
	Epoch        uint64                  `json:"epoch"`
	Attestations []ValidatorAttestation  `json:"attestations"`
}

// ValidatorAttestation is one signed entry from a Magi validator's
// IsLockAttestationResponse (see go-vsc-node modules/islock-attestation).
// The contract verifies these as a BLS aggregate against the validator
// set at the given epoch.
//
//tinyjson:json
type ValidatorAttestation struct {
	// ValidatorDID is a did:key:z... reference to the validator's BLS
	// consensus pubkey. Looked up against the at-epoch validator set
	// stored in vsc-node's elections state.
	ValidatorDID string `json:"validatorDid"`
	// BlsSigHex is the validator's 96-byte BLS12-381 signature over the
	// canonical IS-lock attestation message (lib/dids/dash.go's
	// DashISLockDomainPrefix || chainId || epoch || txid || ...).
	BlsSigHex string `json:"sig"`
}

// HandleMapInstantSendV2 is the WIP replacement for HandleMapInstantSend.
// Implements the §5.2.3 + §5.2.2 sequence:
//
//  1. Re-derive deposit address D from instruction; verify D appears in rawTxHex.
//  2. Verify N-of-M BLS attestations against at-epoch validator set
//     using the new crypto.bls_verify_aggregate host function.
//  3. Resolve sender's DashDID (strict all-inputs-same-address rule, §5.2.5).
//  4. Apply amount rules (§5.2.4).
//  5. Per-DashDID rate-limit check (§5.2.7).
//  6. Credit DashDID(sender) internal balance.
//  7. If op=auth: subsidised — no RC reimbursement, just session-state.
//  8. If op=call: write forwardQueue entry; invoke
//     dash-forwarder-contract.execute(txid); on success deduct RC
//     reimbursement HBD from sender internal ledger; on failure roll
//     back the value movement but keep the credit.
//
// Returns nil on success or a tagged ce.NewContractError on any rejection.
//
// TODO(workstream 5): wire this in. Right now it just returns "not yet
// implemented" so the rest of the contract can build cleanly while the
// integration is in progress.
func (ms *MappingState) HandleMapInstantSendV2(params MapInstantSendV2Params) error {
	// === Step 1: re-derive D, verify it's in rawTxHex ===
	// TODO: call mapping.DepositAddress(primaryPK, backupPK, params.Instruction, networkParams)
	// TODO: parse rawTxHex, extract outputs, check destination matches D

	// === Step 2: verify BLS attestations against at-epoch validator set ===
	// TODO: query Magi state for validator set at params.Epoch
	// TODO: extract pubkeys for each ValidatorDID in attestations
	// TODO: build canonical signed message:
	//   H( "dash-is-lock-v1\0" || chainId || epoch || txid || rawTxHash || instructionHash )
	// TODO: call sdk.CryptoBlsVerifyAggregate(pubkeys, msg, agg_sig) — new host fn from workstream 4a
	// TODO: count distinct attesters; require >= 2M/3 + 1 of active set

	// === Step 3: parse instruction ===
	parsed, err := parseInstructionV2(params.Instruction)
	if err != nil {
		return err
	}

	// === Step 4: resolve DashDID(sender) — strict same-address-all-inputs ===
	// TODO: parse rawTxHex inputs; reject if multi-address; build DashDID

	// === Step 5: amount-matching rules ===
	// TODO: read actual amount paid to D from rawTxHex
	// TODO: enforce MinDustDuffs (auth or value-less call) or MinCallFundingDuffs (value-bearing)

	// === Step 6: rate-limit check ===
	// TODO: read DashDID's window counter; reject (credit only, no forward) if exceeded

	// === Step 7-8: credit + forward ===
	switch parsed.Op {
	case constants.OpAuthValue:
		// Login — subsidised. Just credit. No forward.
		// TODO: incAccBalance(sender DashDID, amount)
		return ce.NewContractError(ce.ErrTransaction, "HandleMapInstantSendV2 op=auth: not yet implemented (workstream 5 in progress)")

	case constants.OpCallValue:
		// Value-bearing or value-less call.
		// TODO: credit DashDID(sender) += actualIS
		// TODO: setIsLockedMarker(txid)
		// TODO: write forwardQueue[txid] = SerializeForwardQueueEntry(...)
		// TODO: call sdk.ContractCall(forwarderId, "execute", txid, opts)
		// TODO: on success: mark FORWARDED; deduct RC reimbursement from
		//       sender's internal HBD balance; SendBalance to L2 tx submitter
		// TODO: on failure: reverse target funding move; mark FORWARD_FAILED
		return ce.NewContractError(ce.ErrTransaction, "HandleMapInstantSendV2 op=call: not yet implemented (workstream 5 in progress)")

	default:
		return ce.NewContractError(ce.ErrInput, "unknown op: "+parsed.Op)
	}
}

// parseInstructionV2 unpacks the canonical instruction string per
// the §5.2.1 grammar. Mirrors dash-forwarder-contract's ParseInstruction
// — these two MUST stay in sync.
//
// Exported here as ParseInstructionV2 once the contract is ready for
// external callers (tests). Until then it's internal-only.
func parseInstructionV2(instruction string) (parsedInstruction, error) {
	var out parsedInstruction
	if instruction == "" {
		return out, ce.NewContractError(ce.ErrInput, "instruction empty")
	}
	fields := strings.Split(instruction, constants.InstructionFieldDelimiter)
	for _, f := range fields {
		idx := strings.Index(f, constants.InstructionKVDelimiter)
		if idx < 0 {
			return out, ce.NewContractError(ce.ErrInput, "instruction field missing delimiter: "+f)
		}
		key := f[:idx]
		val := f[idx+1:]
		switch key {
		case constants.InstructionOpKey:
			out.Op = val
		case constants.InstructionContractKey:
			out.Target = val
		case constants.InstructionMethodKey:
			out.Method = val
		case constants.InstructionArgsKey:
			out.ArgsB64 = val
		case constants.InstructionSidKey:
			out.Sid = val
		case constants.InstructionAmountKey:
			// Inline atoi64 to avoid strconv pulling more into the WASM.
			n, perr := atoi64(val)
			if perr != nil {
				return out, ce.NewContractError(ce.ErrInput, "invalid amount: "+val)
			}
			out.AmountDuffs = n
		}
	}
	if out.Op == "" {
		return out, ce.NewContractError(ce.ErrInput, "instruction missing op=")
	}
	if out.Op == constants.OpCallValue {
		if out.Target == "" || out.Method == "" {
			return out, ce.NewContractError(ce.ErrInput, "op=call requires contract= and method=")
		}
	}
	if out.Sid == "" {
		return out, ce.NewContractError(ce.ErrInput, "instruction missing sid=")
	}
	return out, nil
}

type parsedInstruction struct {
	Op          string
	Target      string
	Method      string
	ArgsB64     string
	Sid         string
	AmountDuffs int64
}

func atoi64(s string) (int64, error) {
	if s == "" {
		return 0, ce.NewContractError(ce.ErrInput, "empty number")
	}
	neg := false
	i := 0
	if s[0] == '-' {
		neg = true
		i = 1
	}
	var n int64
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, ce.NewContractError(ce.ErrInput, "non-digit: "+s)
		}
		n = n*10 + int64(c-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}

// computeAttestationMessageHash builds the canonical IS-lock attestation
// message digest that validators sign. Must match
// go-vsc-node/modules/islock-attestation/attestation.go CanonicalSigningMessage.
//
// Format: H( "dash-is-lock-v1\0" || chainId || epoch_be8 || txid || rawTxHashRaw || instructionHashRaw )
//
// Returns the raw 32-byte SHA-256 digest suitable as input to bls_verify.
//
// TODO(workstream 5): implement using the contract's sha256 helper and
// big-endian encoding. Wire to the bls_verify_aggregate host function
// once the WASM SDK exposes it (workstream 4a — host fn already exists in
// go-vsc-node-develop modules/wasm/sdk/sdk.go).
func computeAttestationMessageHash(chainID, txid, rawTxHashHex, instructionHashHex string, epoch uint64) []byte {
	// TODO: implement
	_ = chainID
	_ = txid
	_ = rawTxHashHex
	_ = instructionHashHex
	_ = epoch
	return nil
}
