// Package constants holds magic strings used by the dash-forwarder-contract.
// Keep these in sync with dash-mapping-contract — drift will break the
// forward flow.
package constants

// DashMappingContractIdStateKey stores the canonical ID of the
// dash-mapping-contract this forwarder trusts as its only valid caller.
// Set at contract deployment via an admin init call. Verified inside
// execute() to gate every invocation.
const DashMappingContractIdStateKey = "mapping"

// ForwardQueueKeyPrefix is the prefix the dash-mapping-contract uses for
// its forward-queue entries: "fq/<txid>" → ForwardQueueEntry serialised.
// We read directly from the mapping contract's state via contracts.read,
// so the prefix MUST match dash-mapping-contract's constant.
//
// In sync with: dash-mapping-contract/contract/constants/constants.go
// (workstream 5 will add this constant there too).
const ForwardQueueKeyPrefix = "fq/"

// AllowedTargetsKeyPrefix is the prefix for the mapping contract's
// allowed-targets list. Lookup pattern: "at/<contract-id>" → "1" if
// allowed, empty otherwise.
const AllowedTargetsKeyPrefix = "at/"

// Instruction grammar tokens. Must match dash-mapping-contract's parser
// (workstream 5 — the parser must produce ForwardQueueEntry values whose
// Instruction field matches this format).
const (
	// e.g. "op=call;contract=vsc1...;method=swap;args=...;sid=ab12;amount=100000000"
	InstructionOpKey       = "op"
	InstructionContractKey = "contract"
	InstructionMethodKey   = "method"
	InstructionArgsKey     = "args"
	InstructionSidKey      = "sid"
	InstructionAmountKey   = "amount"

	OpCallValue = "call"
	OpAuthValue = "auth"

	InstructionFieldDelimiter = ";"
	InstructionKVDelimiter    = "="
)

// ForwardQueueStatus values. Strings rather than ints because state
// reads need to be inspectable.
const (
	StatusPendingForward = "PENDING_FORWARD"
	StatusForwarded      = "FORWARDED"
	StatusForwardFailed  = "FORWARD_FAILED"
)
