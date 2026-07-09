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

// PendingUnmapPrefix keys the per-unmap record (Guard 1 delete-at-confirm for the
// withdrawal path — the BRK-1 mirror). Key: "us-"+txId. HandleUnmap writes it at BUILD
// (deferring the settle); the swept inputs stay registered and the change stays UN-indexed
// until HandleConfirmSpend's settleUnmap consumes+deletes this record and performs the
// atomic finish (index the change output, delete the swept inputs, clear reservations)
// under the tx's SPV proof. The balance debit + FeeSupply(vscFee) credit already happened
// at build. Record layout in utils.go (Marshal/UnmarshalPendingUnmap).
const PendingUnmapPrefix = "us" + DirPathDelimiter

// ReservedUtxoPrefix marks a CONFIRMED UTXO that is committed to an in-flight spend and so
// must not be re-selected until it settles. Key: "ru-"+decimal(id), value "1". Set at unmap
// BUILD (per input), checked per selection candidate by BOTH getInputUtxoIds (unmap→unmap)
// and getMigrationInputs (an unmap's active-gen input whose gen retired mid-flight →
// unmap→migration), deleted at settleUnmap paired with the UTXO delete (so a recycled
// confirmed id never inherits a stale reservation). A per-UTXO marker — NOT a scanned list —
// so the migration path stays O(tranche candidates): an unprivileged unmap flood can never
// gas-DoS rotation (preserves the BRK-1 council A-1 bounded-scan property).
const ReservedUtxoPrefix = "ru" + DirPathDelimiter

// MigrationSweepPrefix keys the per-sweep migration record (BRK-1 delete-at-confirm).
// Key: "ms-"+txId. HandleMigrateVault writes it at BUILD (deferring the settle); a
// migration sweep touches NEITHER the UTXO set nor supply until HandleConfirmSpend
// consumes+deletes this record and performs the atomic swap (index the swept output,
// delete the swept inputs, debit the reserved miner fee) under the sweep's SPV proof.
const MigrationSweepPrefix = "ms" + DirPathDelimiter

// MigrationSweepRegistryKey holds the packed list of pending migration-sweep txids
// (32 bytes/entry, same encoding as TxSpendsRegistryKey). It is the DEDICATED index of
// in-flight "ms-" records, written ONLY by the owner-only migrateVault path and cleared
// at confirm. pendingMigrationState iterates THIS list (bounded by the number of
// concurrent draining sweeps — a handful) instead of the general TxSpendsRegistry (which
// an unprivileged unmap flood can inflate without bound), so migrateVault's exclusion +
// fee-reserve scan can never be gas-DoS'd into freezing rotation (BRK-1 council A-1).
const MigrationSweepRegistryKey = "msl"

// Vault registry (S1 dual-generation vault state model — see S1-DESIGN.md).
// Append-only list of key generations; a new generation appends a PENDING entry
// and existing entries only status-transition (pubkeys NEVER mutated → preserves
// the mainnet key-immutability property). The SDK has no prefix-scan, so this
// mirrors the r/i packed-blob-plus-counter idiom: one blob holds the whole list.
const VaultRegistryKey = "v"    // packed VaultEntrySize-byte entries (whole list)
const VaultNextGenKey = "vn"    // 4-byte BE: next generation number to mint
const VaultActiveGenKey = "va"  // 4-byte BE: generation currently receiving new deposits

// VaultPurgeGraceBlocks (S5) is the BTC-block grace an emptied (INACTIVE) generation
// must wait, measured from its InactiveHeight, before it may transition INACTIVE→PURGED.
// It is the "grace ≥ max BTC reorg depth" safety leg (S5 gate leg (c) / G14): a deep
// reorg could re-introduce a swept UTXO, so purging (which retires the address out of
// the deposit-matchable set) must wait long enough that any such reorg — and any
// still-in-flight late deposit — is first observed and credited (reverting the gen to
// DRAINING). 144 blocks (~24h) is far beyond any reorg Bitcoin mainnet has ever seen
// (deepest ever a handful of blocks) yet keeps a retired key from lingering more than a
// day past emptiness. Measured in the same BTC-height units as the vault height fields.
// NOTE: this alone is NOT sufficient to DESTROY keys — key destruction (S5.1) additionally
// requires the independent zero-balance attestation (leg (d)); purge only STOPS matching.
const VaultPurgeGraceBlocks = 144

const LastHeightKey = "h"
const SeedHeightKey = "sh"
const PruneFloorKey = "pf" // lowest unpruned block height, updated during pruning

// Instruction URL search param keys
const (
	DepositToKey        = "deposit_to"
	SwapAssetOut        = "swap_asset_out"
	SwapToKey           = "swap_to"
	DestinationChainKey = "destination_chain"
)

// Address Creation
const BackupCSVBlocks = 4320 // ~1 month
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

// BtcTheftHaltKey (M1.1b) is the DETERMINISTIC BTC-keysign theft-halt flag: "1" once
// reportUnauthorizedSpend has SPV-proven an unauthorised spend of a registered vault UTXO,
// absent otherwise. Set by the permissionless auto-trip, cleared only by an owner
// (clearTheftHalt) after the theft is resolved. The node's TSS solvency gate reads this
// (alongside the M1.1a governance vsc.tss_halt) and freezes BTC keysign while it is set —
// the THORChain SlashVault "detect-and-halt-on-unauthorised-outbound" pattern, made
// deterministic here by Magi's SPV proof (a single honest report suffices; no 2/3 vote).
const BtcTheftHaltKey = "th"

// LatestMigrateVersion is the newest migration version. Set this in init/seed
// so freshly deployed contracts skip all migrations.
const LatestMigrateVersion = "2"

// Old format constants (pre-migration)
const (
	OldUtxoConfirmedPoolStart = 64
)

const OracleAddress = "did:vsc:oracle:btc"
const PrimaryPublicKeyStateKey = "pubkey"
const BackupPublicKeyStateKey = "backupkey"

const BlockPrefix = "b" + DirPathDelimiter

// MaxBaseFeeRate caps the base fee rate at 1000 sats/vbyte.
// Any rate above this is clamped during fee calculation to prevent
// overflow or unreasonable withdrawal fees from a misconfigured oracle.
const MaxBaseFeeRate int64 = 1000

// MaxMigrationInputs bounds the number of UTXOs a single migration sweep tranche
// consumes (S2). Each input needs its own TSS signature and adds ~150 vB; an
// unbounded sweep-all of a large retiring vault would blow the TSS-signing budget
// and exceed Bitcoin standardness (~100kvB), so the sweep can never be built or
// relayed (the C-F brick). A retiring vault with more UTXOs than this is drained in
// successive tranches. Conservative — the live vault holds only a handful of UTXOs.
const MaxMigrationInputs = 100

// MigrationCanaryValue (THORChain-derived, migration §5c) caps the value of a gen's FIRST
// migration tranche — the "canary." When a newly-RETIRING gen is first swept, only up to this
// much value moves; that tranche must CONFIRM (BRK-1 delete-at-confirm keeps its inputs
// registered until then, and getMigrationInputs excludes in-flight inputs from the next
// tranche) BEFORE the bulk (the larger DRAINING tranches, capped at MaxUtxoAmount) proceeds.
// This bounds the exposure of the first move to a new/unproven successor vault and mirrors
// THORChain's "small-first-then-ramp" churn migration — defense-in-depth on top of BRK-2
// (which already proves the new key can SIGN before activation). 1,000,000 sats = 0.01 BTC:
// a real test amount, small vs any funded vault. Governance-TUNABLE; set to MaxUtxoAmount to
// disable the canary (first tranche then uses the normal cap). The new vault only RECEIVES
// the canary — proving the new vault's own SPEND path end-to-end (the stronger variant) is a
// tracked follow-up (needs a test-spend to avoid coupling migration liveness to unmap flow).
const MigrationCanaryValue int64 = 1_000_000

// MaxBlockRetention is the number of recent block headers to keep.
// Older headers are pruned during addBlocks to prevent unbounded state growth.
//
// Must be >= the CSV backup timelock (BackupCSVBlocks = 4320 ≈ 1 month on
// mainnet) + a reorg-depth margin. A CSV backup recovery becomes spendable on L1
// only after the timelock, and a pending migration sweep may not confirm for a
// while (a pause/suspend can outlast the window); if headers referenced by such
// a spend are pruned first, the contract can no longer SPV-verify the
// confirmation/recovery and the accounting cannot reconcile it (brick council
// FS-1/FS-2/FS-4/FS-5 H-3 — a recoverable freeze that would otherwise degrade
// past the primary path). 4608 = 4320 (mainnet CSV) + 288 (~2-day reorg margin);
// on testnet (CSV=2) this is harmless headroom. Header storage ≈ 4608*80 B ≈ 369 KB.
const MaxBlockRetention = 4608

// MaxPrunePerCall limits how many old headers are deleted in a single
// addBlocks invocation to keep gas usage predictable.
const MaxPrunePerCall = 50

const (
	Testnet3 string = "testnet3"
	Testnet4 string = "testnet4"
	Mainnet  string = "mainnet"
	Regtest  string = "regtest"
)

func IsTestnet(networkName string) bool {
	return networkName == Testnet3 || networkName == Testnet4 || networkName == Regtest
}
