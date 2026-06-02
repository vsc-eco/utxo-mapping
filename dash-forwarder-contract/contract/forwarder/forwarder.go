// Package forwarder is the core of the dash-forwarder-contract. It owns
// the execute() logic that the dash-mapping-contract invokes after
// crediting an op=call IS deposit.
//
// Hard invariants enforced here (security-critical):
//
//  1. Only the configured dash-mapping-contract may call execute(). Any
//     other caller is rejected. This is the linchpin of the contract —
//     compromise of this check means anyone could spoof effectiveCaller.
//  2. The forwarder NEVER mutates the mapped-DASH ledger. It only invokes
//     call_as on the target. All ledger changes happen in mapping.
//  3. The forwarder reads forwardQueue from the mapping contract via
//     contracts.read. It trusts whatever mapping wrote there because
//     mapping is the only entity that COULD write it.
package forwarder

import (
	"dash-forwarder-contract/contract/constants"
	ce "dash-forwarder-contract/contract/contracterrors"
	"dash-forwarder-contract/sdk"
	"strings"
)

// ForwardQueueEntry is the state shape dash-mapping-contract writes to
// forwardQueue[txid]. Encoded as a simple delimited string for now —
// the parser handles legacy/tinyjson schema once mapping contract
// formalises it in workstream 5. Format:
//
//	sender|instruction|callFunding|status
//
// (Mapping contract MUST emit this exact format until both sides switch
// together to tinyjson.)
type ForwardQueueEntry struct {
	Sender      string // DashDID — the user the call is "from"
	Instruction string // canonical op=call;... string
	CallFunding int64  // duffs being routed to target (0 for value-less)
	Status      string // one of constants.Status* values
}

// Execute is the contract's only externally-callable action. Logic
// follows spec §5.3 with concrete steps numbered.
func Execute(txid string) error {
	// Step 1: hard-check caller. This is the most security-critical
	// line in this contract.
	mappingId := sdk.StateGetObject(constants.DashMappingContractIdStateKey)
	if mappingId == nil || *mappingId == "" {
		return ce.NewError(ce.ErrInitialization,
			"dash-forwarder-contract not initialised: mapping contract id missing")
	}
	caller := sdk.GetEnv().Caller.String()
	expected := "contract:" + *mappingId
	if caller != expected {
		return ce.NewError(ce.ErrNoPermission,
			"forwarder.execute called by "+caller+", expected "+expected)
	}

	// Step 2: read forwardQueue entry from mapping contract state.
	entryKey := constants.ForwardQueueKeyPrefix + txid
	entryRaw := sdk.ContractStateGet(*mappingId, entryKey)
	if entryRaw == nil || *entryRaw == "" {
		return ce.NewError(ce.ErrStateAccess,
			"forwardQueue[txid] not found in mapping state: "+txid)
	}

	entry, err := parseForwardQueueEntry(*entryRaw)
	if err != nil {
		return ce.NewError(ce.ErrInput,
			"could not parse forwardQueue entry: "+err.Error())
	}

	// Step 3: verify status.
	if entry.Status != constants.StatusPendingForward {
		return ce.NewError(ce.ErrInput,
			"forwardQueue entry status is "+entry.Status+", expected "+constants.StatusPendingForward)
	}

	// Step 4: parse instruction → (target, method, args).
	parsed, err := ParseInstruction(entry.Instruction)
	if err != nil {
		return ce.NewError(ce.ErrInput, "could not parse instruction: "+err.Error())
	}
	if parsed.Op != constants.OpCallValue {
		return ce.NewError(ce.ErrInput,
			"forwarder.execute called for non-call op="+parsed.Op)
	}

	// Step 5: verify target is in mapping's allowedTargets list.
	allowedKey := constants.AllowedTargetsKeyPrefix + parsed.Target
	allowed := sdk.ContractStateGet(*mappingId, allowedKey)
	if allowed == nil || *allowed != "1" {
		return ce.NewError(ce.ErrNoPermission,
			"target "+parsed.Target+" is not in mapping's allowedTargets list")
	}

	// Step 6: invoke call_as. The target sees:
	//   msg.caller          = "contract:<dash-forwarder-contract.id>"
	//   msg.effective_caller = entry.Sender (the DashDID)
	//
	// Per the spec §5.4, effectiveCaller is per-call-frame; if the
	// target makes its own contract calls downstream, the grandchild
	// sees the target as both caller and effectiveCaller. User
	// identity propagates downstream only via explicit args.
	result := sdk.ContractCallAs(parsed.Target, parsed.Method, parsed.ArgsB64, entry.Sender, &sdk.ContractCallOptions{})
	if result == nil {
		return ce.NewError(ce.ErrTransaction,
			"target call returned nil — assumed failed")
	}
	// (SDK ContractCallAs returns the call result string; any contract-
	// level error there is surfaced via the result struct's Ok=false.
	// Workstream 5 will define exactly how mapping interprets the
	// return; for now we just return success on non-nil.)
	return nil
}

// ParsedInstruction is the structured form of an op=call instruction.
type ParsedInstruction struct {
	Op       string // always "call" for forwarder-invoked entries
	Target   string // contract: prefix, e.g. "vsc1DexRouter"
	Method   string
	ArgsB64  string
	Sid      string
	AmountDuffs int64 // 0 for value-less calls
}

// ParseInstruction unpacks the canonical "op=...;contract=...;..." string.
// Exported for the test suite and (eventually) for the mapping contract
// to validate that the instruction it baked into the deposit address
// re-parses cleanly before scheduling a forward.
func ParseInstruction(instruction string) (ParsedInstruction, error) {
	var out ParsedInstruction
	if instruction == "" {
		return out, ce.NewError(ce.ErrInput, "instruction empty")
	}

	fields := strings.Split(instruction, constants.InstructionFieldDelimiter)
	for _, f := range fields {
		idx := strings.Index(f, constants.InstructionKVDelimiter)
		if idx < 0 {
			return out, ce.NewError(ce.ErrInput, "instruction field missing delimiter: "+f)
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
			n, perr := parseInt64(val)
			if perr != nil {
				return out, ce.NewError(ce.ErrInput, "invalid amount: "+val)
			}
			out.AmountDuffs = n
		// Unknown keys are ignored on purpose — forwards-compatible parsing.
		}
	}

	if out.Op == "" {
		return out, ce.NewError(ce.ErrInput, "instruction missing op=")
	}
	if out.Op == constants.OpCallValue {
		if out.Target == "" || out.Method == "" {
			return out, ce.NewError(ce.ErrInput, "op=call requires contract= and method=")
		}
	}
	if out.Sid == "" {
		return out, ce.NewError(ce.ErrInput, "instruction missing sid=")
	}
	return out, nil
}

// parseForwardQueueEntry decodes the pipe-delimited entry. Replace with
// tinyjson when workstream 5 settles on a schema; this string format is
// only for the v1 boostrap.
func parseForwardQueueEntry(raw string) (ForwardQueueEntry, error) {
	parts := strings.SplitN(raw, "|", 4)
	if len(parts) != 4 {
		return ForwardQueueEntry{}, ce.NewError(ce.ErrInput,
			"forwardQueue entry must have 4 fields separated by '|', got "+intToString(len(parts)))
	}
	callFunding, err := parseInt64(parts[2])
	if err != nil {
		return ForwardQueueEntry{}, ce.NewError(ce.ErrInput, "invalid callFunding: "+parts[2])
	}
	return ForwardQueueEntry{
		Sender:      parts[0],
		Instruction: parts[1],
		CallFunding: callFunding,
		Status:      parts[3],
	}, nil
}

// SerializeForwardQueueEntry is the inverse of parseForwardQueueEntry —
// used by tests (and once workstream 5 lands, by the mapping contract).
func SerializeForwardQueueEntry(e ForwardQueueEntry) string {
	return e.Sender + "|" + e.Instruction + "|" + intToString(int(e.CallFunding)) + "|" + e.Status
}

// ===== helpers (no strconv to keep WASM build tight) =====

func parseInt64(s string) (int64, error) {
	if s == "" {
		return 0, ce.NewError(ce.ErrInput, "empty number")
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
			return 0, ce.NewError(ce.ErrInput, "non-digit in number: "+s)
		}
		n = n*10 + int64(c-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}

func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
