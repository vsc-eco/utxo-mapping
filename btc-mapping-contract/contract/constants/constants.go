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

// LatestMigrateVersion is the newest migration version. Set this in init/seed
// so freshly deployed contracts skip all migrations.
const LatestMigrateVersion = "1"

// Old format constants (pre-migration)
const (
	OldUtxoConfirmedPoolStart = 64
)

const OracleAddress = "did:vsc:oracle:btc"
const PrimaryPublicKeyStateKey = "pubkey"
const BackupPublicKeyStateKey = "backupkey"

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

// MaxBlockRetention is the number of recent block headers to keep.
// Older headers are pruned during addBlocks to prevent unbounded state growth.
// keep a week worth of headers to allow addresses to be registered after the fact
const MaxBlockRetention = 1080

// MaxPrunePerCall limits how many old headers are deleted in a single
// addBlocks invocation to keep gas usage predictable.
const MaxPrunePerCall = 50

const (
	Testnet3 string = "testnet3"
	Testnet4 string = "testnet4"
	Mainnet  string = "mainnet"
	Regtest  string = "regtest"
)

// IsTestnet is TRUE only for real testnet builds (testnet3 OR testnet4).
// Regtest is NOT a testnet — it's the throwaway harness used by devnet
// runs + `make dev` builds.
//
// Audit R16-SEC-sec3-sibling-utxo-contracts-unfixed (mirror of the
// dash-mapping-contract SEC-3 R15 fix): the old IsTestnet collapsed
// testnet3, testnet4, and regtest into one gate. Every admin-bypass
// branch (pubkey overwrite, router overwrite) became active for the
// regtest dev build too — a dev.wasm accidentally tagged for mainnet
// (or promoted out of the dev cycle) had all governance timelocks +
// overwrite refusals disabled.
//
// Split into three predicates with explicit intent; callsites in
// main.go + blocklist.go pick the tightest gate.
func IsTestnet(networkName string) bool {
	return networkName == Testnet3 || networkName == Testnet4
}

// IsRegtest is TRUE only for the regtest harness. Used by code paths
// that are test-only (overwrites that the real testnet flow should
// exercise via the same once-and-immutable model as mainnet).
func IsRegtest(networkName string) bool {
	return networkName == Regtest
}

// IsTestnetOrRegtest is the old IsTestnet behaviour — TRUE for any
// non-mainnet build. Use when the gated behaviour is admin-trusted in
// BOTH real testnet and the regtest harness (owner-as-oracle, seedBlocks
// idempotency).
func IsTestnetOrRegtest(networkName string) bool {
	return networkName == Testnet3 || networkName == Testnet4 || networkName == Regtest
}
