package constants

const DirPathDelimiter = "-"

const TssKeyName = "main"
const RouterContractIdKey = "routerid"

// UTXO ID pool layout (uint16 ID, 65536 slots total).
// IDs 0–1023   are the unconfirmed pool (change outputs pending confirmation).
// IDs 1024–65535 are the confirmed pool (active mapped UTXOs ready to spend).
const (
	UtxoUnconfirmedPoolSize = 1024  // number of slots in the unconfirmed pool
	UtxoConfirmedPoolStart  = 1024  // first ID in the confirmed pool
	UtxoMaxId               = 65535 // max uint16
)

// MaxUtxoAmount is the maximum satoshi value for a single UTXO in the registry.
// 6 bytes (48 bits) supports up to ~2.81M BTC — far beyond any realistic deposit.
const MaxUtxoAmount int64 = (1 << 48) - 1

const BalancePrefix = "a" + DirPathDelimiter

// ObservedBlockPrefix stores the list of observed txid:vout pairs for a given
// block height. Key: "o-<height>", Value: packed 34-byte entries (32-byte txid
// + 2-byte vout BE). Pruned alongside block headers during addBlocks.
const ObservedBlockPrefix = "o" + DirPathDelimiter
const UtxoPrefix = "u" + DirPathDelimiter
const UtxoRegistryKey = "r"
const UtxoLastIdKey = "i"
const TxSpendsRegistryKey = "p"
const TxSpendsPrefix = "d" + DirPathDelimiter
const SupplyKey = "s"

const LastHeightKey = "h"
const SeedHeightKey = "sh"
const PruneFloorKey = "pf" // lowest unpruned block height, updated during pruning

// BTC-C3 (propagated): per-Hive-block withdrawal rate limit. The
// accumulator tracks total duffs deducted by HandleUnmap within a
// single Hive L1 block; when MaxUnmapPerBlock is positive,
// HandleUnmap rejects any unmap that would push the accumulator
// above the cap. Default 1 DASH per Hive block; operators can tune
// via setMaxUnmapPerBlock. Setting 0 disables the limit.
const DefaultMaxUnmapPerBlock int64 = 100_000_000 // 1 DASH in duffs
const MaxUnmapPerBlockKey = "muxb"

// BlockUnmapAccKey stores the per-block unmap accumulator: 16 bytes
// = uint64 BE Hive block height || uint64 BE accumulated duffs.
const BlockUnmapAccKey = "buac"

// Instruction URL search param keys
const (
	DepositToKey        = "deposit_to"
	SwapAssetOut        = "swap_asset_out"
	SwapNetworkOut      = "swap_network_out"
	SwapToKey           = "swap_to"
	DestinationChainKey = "destination_chain"
	ReturnAddressKey    = "return_address"
	ReturnNetworkKey    = "return_network"
)

// Address Creation
const BackupCSVBlocks = 17280 // ~1 month (Dash ~2.5 min blocks)
const TestnetBackupCSVBlocks = 2

// Logs
const (
	LogDelimiter      = "|"
	LogKeyDelimiter   = "="
	LogArrayDelimiter = ","
)

const AllowancePrefix = "q" + DirPathDelimiter

const PausedKey = "paused"     // "1" when contract is paused, absent/empty when active
const MigrateVersionKey = "mv" // current migration version (decimal string)

// LatestMigrateVersion is the newest migration version. Set this in init/seed
// so freshly deployed contracts skip all migrations.
const LatestMigrateVersion = "1"

// Old format constants (pre-migration)
const (
	OldUtxoConfirmedPoolStart = 64
)

const OracleAddress = "did:vsc:oracle:dash"
const PrimaryPublicKeyStateKey = "pubkey"
const BackupPublicKeyStateKey = "backupkey"

const BlockPrefix = "b" + DirPathDelimiter

// MaxBaseFeeRate caps the base fee rate at 500 duffs/vbyte.
// Pentest finding BTC-C6 (propagated from btc-mapping-contract): the
// previous 1000 sat/vbyte ceiling only protected against int overflow
// — within that range a misbehaving or compromised oracle can drive
// fees to griefing levels. 500 duffs/vbyte still admits genuine
// extreme-market spikes while halving the oracle's griefing range.
// Dash duffs are 1 satoshi-equivalent per the same 8-decimal model,
// so the absolute economic impact is comparable to BTC. Rates above
// this are clamped during fee calculation; rates below 1 are clamped
// up to 1.
const MaxBaseFeeRate int64 = 500

// MaxBlockRetention is the number of recent block headers to keep.
// Older headers are pruned during addBlocks to prevent unbounded state growth.
// keep a week worth of headers to allow addresses to be registered after the fact
const MaxBlockRetention = 1080

// MaxPrunePerCall limits how many old headers are deleted in a single
// addBlocks invocation to keep gas usage predictable.
const MaxPrunePerCall = 50

const (
	Testnet string = "testnet"
	Mainnet string = "mainnet"
	Regtest string = "regtest"
)

func IsTestnet(networkName string) bool {
	return networkName == Testnet || networkName == Regtest
}

// ---------------------------------------------------------------------------
// Dash InstantSend login feature (workstream 5)
//
// Per spec §5.2.3, the dash-mapping-contract gains a forwardQueue state map
// and an allowedTargets registry to support the trusted-forwarder pattern.
// These constants are the keys; the actual state mutations + new
// mapInstantSend action are added in mapping/op_call.go (TODO).
//
// The dash-forwarder-contract (workstream 6) reads forwardQueue[txid] via
// contracts.read using exactly these prefixes — keep them in sync.
// ---------------------------------------------------------------------------

// ForwardQueueKeyPrefix: forwardQueue["fq/<txid>"] holds the pending /
// in-flight / done forward record. Value format is v1 pipe-delimited:
//
//	sender|instruction|callFunding|status
//
// (Will switch to tinyjson once the schema settles.)
const ForwardQueueKeyPrefix = "fq" + DirPathDelimiter

// AllowedTargetsKeyPrefix: allowedTargets["at/<contract-id>"] = "1" if
// the contract may be invoked via the forwarder. Empty / missing = not
// allowed. Per spec §5.2.7, the v1 list contains exactly one entry (the
// magi-dex router); additions go through governance with a 7-day timelock.
const AllowedTargetsKeyPrefix = "at" + DirPathDelimiter

// ForwarderContractIdStateKey holds the canonical
// dash-forwarder-contract id this mapping trusts. Set once at deploy via
// an admin action, then immutable. Required before any op=call IS
// payments will be accepted.
const ForwarderContractIdStateKey = "forwarder"

// ForwardQueue status values. Plain strings rather than ints for
// debuggability — operators inspecting state can read these directly.
const (
	StatusPendingForward = "PENDING_FORWARD"
	StatusForwarded      = "FORWARDED"
	StatusForwardFailed  = "FORWARD_FAILED"
	// StatusForwardFailedInsufficientRC: forwarder call succeeded but the
	// post-call RC reimbursement step couldn't extract enough HBD. See
	// spec §5.2.3 step 9. Credit is preserved; user keeps their DASH.
	StatusForwardFailedInsufficientRC = "FORWARD_FAILED_INSUFFICIENT_RC"
)

// Op grammar tokens used by mapInstantSend's instruction parser. Must
// match dash-forwarder-contract/contract/constants — drift breaks the
// per-op-unique-address property of the system.
const (
	InstructionOpKey       = "op"
	InstructionContractKey = "contract"
	InstructionMethodKey   = "method"
	InstructionArgsKey     = "args"
	InstructionSidKey      = "sid"
	InstructionAmountKey   = "amount"

	OpAuthValue = "auth"
	OpCallValue = "call"

	InstructionFieldDelimiter = ";"
	InstructionKVDelimiter    = "="
)

// MinDustDuffs / MinCallFundingDuffs are the per-op amount floors. Spec
// §5.2.7. MinCallFundingDuffs applies only to value-bearing op=call
// (amount > 0); value-less calls fall under MinDustDuffs.
const (
	MinDustDuffs        int64 = 10_000    // 0.0001 DASH
	MinCallFundingDuffs int64 = 1_000_000 // 0.01 DASH
)

// PerDashDIDRateLimitWindow and PerDashDIDRateLimitMax bound spam per
// authenticated user identity. Spec §5.2.7 — over the limit, the
// contract still credits the IS deposit (no fund loss) but skips the
// forward dispatch. Defends against the economically-asymmetric
// RC-exhaustion DoS analysed in §8.3.
const (
	PerDashDIDRateLimitWindowSec int64 = 600 // 10 min
	PerDashDIDRateLimitMax       int   = 30  // 30 ops / 10 min
)

// ForwardQueuePruneAgeBlocks: terminal-state entries older than this
// are eligible for pruning. ~3 days at Hive's 3-second block time.
// PENDING_FORWARD entries are never auto-pruned (in-flight work).
const ForwardQueuePruneAgeBlocks uint64 = 86_400
