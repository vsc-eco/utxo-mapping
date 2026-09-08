package constants

const DirPathDelimiter = "-"

const TssKeyName = "main"
const RouterContractIdKey = "routerid"

// RbfSequence is the nSequence set on EVERY input of every vault spend (unmap +
// migration sweep). 0xfffffffd (a) signals BIP-125 opt-in Replace-By-Fee so a stuck
// never-confirming spend can be reliably fee-bumped (the L7-01 re-drive) rather than
// wedging rotation forever, and (b) has bit 31 set, so BIP-68 relative-locktime is
// DISABLED — it never interacts with the vault's OP_CSV backup branch (a separate
// spend path / separate tx), exactly the value Bitcoin Core's wallet uses. The
// signed BIP143 sighash commits to this value; the node's output-scoping gate
// recomputes the sighash from the transmitted tx bytes, so it reads this nSequence
// rather than assuming a default — the node side is unchanged.
const RbfSequence uint32 = 0xfffffffd

// L7-01 re-drive tuning (spec v2 D3/RBF-1).
//
// RedriveStaleBlocks: minimum L1 blocks since a spend's BuildHeight before it may be
// re-driven — long enough that we never race a tx about to confirm (the oracle submits
// headers at ~2 confirmations). Staleness is hygiene, NOT safety: identical inputs ⇒
// Bitcoin confirms ≤1 of {original, replacements}, and a late replacement over an
// already-confirmed original is simply network-rejected. Set > the accepted reorg depth.
//
// RedriveIncRelayFeeRate: the BIP-125 rule-4 incremental relay fee (sat/vByte) the
// replacement must pay ABOVE the stuck original — so minBump = RedriveIncRelayFeeRate *
// vSize. 2 (> the 1 sat/vByte default) gives margin so the replacement reliably relays.
const (
	RedriveStaleBlocks     uint32 = 12
	RedriveIncRelayFeeRate int64  = 2
)

// MaxSpendGroupMembers caps the members of an L7-01 spend group (original + RBF
// replacements). Re-drives are owner-gated and each bump raises the fee ≥ 2 sat/vByte
// under a totalInputs/2 ceiling, so an honest operator needs only a handful before a
// stuck tx confirms — 64 is far above any real need. The cap prevents a rogue-owner
// re-drive storm from (a) overflowing the uint16 member-count length prefix past 65535
// (cold-scan B1 → a decode failure that could dangle siblings) or (b) growing
// clearSpendGroup's O(members) settle cost into an RC-limit brick (B2).
const MaxSpendGroupMembers = 64

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

// MinDepositSats (V-1 dust-escape prevention) is the minimum satoshi value a single
// output must carry to be credited by `map` (mapping.go indexOutputs). A deposit below
// this floor can never be economically swept off a superseded generation and, once
// registered, would permanently deadlock rotation (NN#3 / AnyFundedSupersededGen never
// sees that generation empty) — so it is simply never credited (option (a) claw-back:
// claw-back-by-never-crediting; see dust_writeoff.go). Fixed sat value, deliberately NOT
// derived from the oracle's live BaseFeeRate (a fee-rate-scaled floor would let a
// high/rogue oracle rate inflate the "dust" ceiling).
//
// Sweepability derivation at the FIXED protocol-minimum rate (1 sat/vbyte, the floor of
// clampedFeeRate): a 1-input sweep is ~144 vbyte ⇒ ~144 sat fee at rate 1, so
// 1000 − 144 = 856 > dustThreshold (546) — a single deposit at this floor is always
// sweepable with margin at ANY fee rate ≥ 1. 1000 sats is a clean round value matching
// THORChain's DustThreshold (~$0.60 at typical BTC prices).
const MinDepositSats int64 = 1000

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

// SpendGroupPrefix ("g-"+<minInputId>) keys the L7-01 re-drive SPEND GROUP: the set of
// txids that all spend the IDENTICAL reserved input set (an original stuck spend + its
// RBF fee-bumped replacements). Keyed by the minimum input id in the set — deterministic,
// stable across the group (every member reuses the identical inputs), and unique (a UTXO is
// reserved by at most one live spend). Written lazily (only once a spend is first re-driven);
// absent ⇒ a group-of-one. On settle of ANY member, the whole member list is cleared
// atomically so a dangling record can never re-arm the NN#3 freeze (spec v2 D1-B / H2).
const SpendGroupPrefix = "g" + DirPathDelimiter

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
const VaultRegistryKey = "v"   // packed VaultEntrySize-byte entries (whole list)
const VaultNextGenKey = "vn"   // 4-byte BE: next generation number to mint
const VaultActiveGenKey = "va" // 4-byte BE: generation currently receiving new deposits

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
// PendingSpendFloorKey caches the lowest BuildHeight among live pending spends
// (migration sweeps and unmaps), or is absent when there are none.
//
// VR2-03: header pruning must not delete a header a pending spend still needs to
// settle. Deriving that floor by scanning every live record would put an O(N) read
// on the addBlocks path — which runs on every block — so it is maintained
// incrementally instead: set when a spend is recorded, recomputed only when a
// spend group clears. Pruning then reads one key.
const PendingSpendFloorKey = "psf"

// MaxConcurrentPendingSpends caps how many spend records may be live at once.
//
// This is what makes the retention clamp safe to have. Unmap is permissionless —
// rate-limited by satoshis per block, with no cap on COUNT or duration — so
// without a bound an attacker could hold open an unbounded number of
// never-confirming unmaps, each pinning header retention at its own build height
// and growing contract state without limit. It also bounds the recompute that
// runs when a spend group clears.
const MaxConcurrentPendingSpends = 256

// MaxRetentionWithPendingSpend is the absolute floor on header pruning, even
// while a pending spend is holding retention open.
//
// A stopgap, and it should be read as one: it converts an unbounded retention pin
// into a bounded one, and converts a CERTAIN permanent stranding at
// MaxBlockRetention into a possible one at twice that. It does not make a spend
// that outlives it recoverable — that needs the VR2-01 reconcile, which does not
// exist yet. Operators should be alerted well before a live spend's build height
// approaches this.
const MaxRetentionWithPendingSpend = 2 * MaxBlockRetention

const PruneFloorKey = "pf" // lowest unpruned block height, updated during pruning

// BTC-C3: per-Hive-block withdrawal rate limit. The accumulator tracks
// total sats deducted by HandleUnmap within a single Hive L1 block;
// when MaxUnmapPerBlock is positive, HandleUnmap rejects any unmap
// that would push the accumulator above the cap. The accumulator
// resets on each new Hive block (=3s tick).
//
// Default 1 BTC / Hive block = 1200 BTC/hour upper bound on a
// TSS-quorum-compromise drain. Operators can tune via the
// setMaxUnmapPerBlock admin handler; setting it to 0 disables the
// limit (legacy behaviour).
const DefaultMaxUnmapPerBlock int64 = 100_000_000 // 1 BTC in sats
const MaxUnmapPerBlockKey = "muxb"

// BlockUnmapAccKey stores the per-block unmap accumulator: 16 bytes
// = uint64 BE Hive block height || uint64 BE accumulated sats.
const BlockUnmapAccKey = "buac"

// Instruction URL search param keys
const (
	DepositToKey        = "deposit_to"
	SwapAssetOut        = "swap_asset_out"
	SwapToKey           = "swap_to"
	DestinationChainKey = "destination_chain"
	// MinAmountOutKey lets a deposit-swap instruction carry a slippage bound
	// (DX-H5). It is baked into the deposit address (part of the hashed
	// instruction), so the depositor commits to a minimum output up front.
	MinAmountOutKey = "min_amount_out"
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

// VaultOperatorKey stores an OPTIONAL second authorized DID (typically the
// mapping-bot's did:pkh identity) that may call the four OPERATIONAL vault ops
// — migrateVault, retireVault, writeOffDust, redriveSpend — alongside the owner.
// It grants NO governance power (pause/router/key registration stay owner-only).
// Absent/empty ⇒ only the owner may drive the rotation (the pre-operator default).
const VaultOperatorKey = "vaultop"

const BlockPrefix = "b" + DirPathDelimiter

// MaxBaseFeeRate caps the base fee rate at 500 sats/vbyte.
// Pentest finding BTC-C6: the previous 1000 sat/vbyte ceiling
// only protected against int overflow — within that range a
// misbehaving or compromised oracle can drive a typical
// ~200-vbyte withdrawal fee to ~$200, which is griefing. BTC
// mainnet historical peaks (2017 bull run, 2023 inscription
// mania) topped out near 500–750 sat/vbyte for short windows,
// so 500 covers genuine extreme markets while halving the
// oracle's griefing range. Any rate above this is clamped
// during fee calculation; rates below 1 are clamped up to 1.
const MaxBaseFeeRate int64 = 500

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
// MinConfirmationDepth is how far an L1 event's block must be buried under the
// contract's own chain tip before the contract acts on it as final: crediting a
// deposit (VR2-07) or settling a spend (VR2-06).
//
// Without it a deposit is creditable the instant its header lands, which is only
// the oracle's own relay threshold — 2 confirmations on mainnet. A 2-block
// Bitcoin reorg is routine, and the contract can only follow reorgs 2 deep
// (HandleReplaceBlocks is hard-capped at 2 on mainnet), so a deposit orphaned by
// one keeps its L2 credit while the backing coins cease to exist: an
// un-reconcilable inflation of user supply against a vault that never received
// them.
//
// This stacks on the oracle's threshold rather than replacing it, so mainnet
// requires roughly 6 real confirmations end to end — the conventional Bitcoin
// settlement bar.
//
// Deliberately FLAT, not scaled by deposit value. Value-scaling is defeated by
// splitting one deposit across sub-threshold outputs: indexOutputs makes one UTXO
// per output with no aggregation, so there is nothing to accumulate against
// without a new per-address rolling window. A flat floor cannot be split around.
//
// It must stay strictly below RedriveStaleBlocks. A settle waiting for depth keeps
// its spend record live, so if the redrive window opened first an operator could
// RBF a transaction that is already mined — producing a replacement that can never
// confirm, because Bitcoin has already spent its inputs.
//
// Regtest deliberately enforces a NON-ZERO depth. Setting it to zero there would
// leave the entire test suite running with the gate inert — testnet unable to
// prove what mainnet enforces, which is exactly the shape of finding VR2-20.
func MinConfirmationDepth(networkMode string) uint32 {
	switch networkMode {
	case Testnet3, Testnet4:
		return 2
	case Regtest:
		return 2
	default: // mainnet
		return 4
	}
}

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
