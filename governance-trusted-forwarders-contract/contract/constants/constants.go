// Package constants holds the state-key prefixes and protocol constants
// the governance-trusted-forwarders contract uses. The magi execution-
// context reads the ACTIVE list directly (one StateGetObject call), so
// the ActiveListKey value is part of the public protocol surface —
// changing it requires a binary release on the magi side.
package constants

// ActiveListKey is the single state key the contract uses to store the
// active trusted-forwarders list as a pipe-delimited string. Magi's
// execution-context wiring reads this key at tx execution time when
// the consensus version >= TrustedForwardersFromContractVersion.
//
// On-the-wire format: "contract:vsc1...|contract:vsc1...|..." (each
// entry already prefixed with the canonical "contract:" so callers
// can compare against ctx.env.ContractId via "contract:"+ContractId
// without any string surgery on the read side).
//
// Empty value (or missing key) means "no active forwarders" — the
// safe default. The contract must NEVER write an empty entry into
// the list; consumers split on "|" and an empty fragment matching
// "contract:" would silently un-trust callers whose id encodes to
// the empty suffix (none exist today, but the invariant matters).
const ActiveListKey = "active"

// PendingAddListKey stores the pending-add queue as a pipe-delimited
// "<id>;<unlock_height>|<id>;<unlock_height>|..." string.
//
// The two-level delimiter chain (semicolon inside, pipe between) is
// the same one ParseValidatorSetPayload uses. Keep them stable —
// changes break wasm builds older than the release.
const PendingAddListKey = "pending-add"

// PendingRemoveListKey is symmetric — the pending-remove queue.
const PendingRemoveListKey = "pending-remove"

// EntryDelim separates entries in the three pipe-delimited lists.
const EntryDelim = "|"

// FieldDelim separates fields inside a pending-add or pending-remove
// entry (`<id>;<unlock_height>`).
const FieldDelim = ";"

// ContractPrefix is the canonical wrapper for contract ids when they
// appear in the active list. Mirrors ctx.env.ContractId formatting on
// the magi side (`"contract:" + ContractId`) so a direct string
// comparison succeeds without surgery.
const ContractPrefix = "contract:"

// DefaultTimelockBlocks is the proposeForwarder → activateForwarder
// (and symmetric remove) timelock window in L1 Hive blocks. 48h at 3s
// per block ≈ 57600 blocks. Overridable per-network via setTimelock
// once the contract is initialised (governance can shorten on testnet
// for faster iteration, lengthen on mainnet if community decides).
//
// Why 48h and not 7d (the mapping contract's addAllowedTarget timelock):
// trusted-forwarders is a strictly tighter security gate (single
// forwarder can call_as any DID); a 48h window is plenty for community
// review while limiting attacker exposure during the propose → activate
// interval. The mapping's 7d is calibrated for target contracts which
// are weaker-scoped.
const DefaultTimelockBlocks uint64 = 57600

// TimelockKey stores the active timelock window (overridable). Reads
// fall back to DefaultTimelockBlocks if unset.
const TimelockKey = "timelock"

// EmergencyRevokeAllowedKey stores a bool ("1" / "0") gating the
// emergencyRevoke action. Defaults to enabled at deploy; the contract
// owner can set "0" to disable in a future hardening step.
const EmergencyRevokeAllowedKey = "emergency-allowed"

// MaxForwardersHardCap is a defensive upper bound on the active list
// length. Each entry adds an O(active-count) per-tx state-read cost on
// the magi side, so a runaway list could grift block production. 256
// is far above any realistic IS-login / future-forwarder need.
const MaxForwardersHardCap = 256

// MaxIdLength bounds a single contract id string (defensive vs. a
// malformed propose that wastes state-write RC). vsc contract ids are
// ~40 chars; cap generously at 128 to leave room for future address
// schemes without forcing a wasm release.
const MaxIdLength = 128
