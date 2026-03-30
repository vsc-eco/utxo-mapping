package constants

const DirPathDelimiter = "-"

const TssKeyName = "main"
const RouterContractIdKey = "routerid"

// UTXO ID pool layout (single-byte ID, 256 slots total).
// IDs 0–63  are the unconfirmed pool (change outputs pending confirmation).
// IDs 64–255 are the confirmed pool   (active mapped UTXOs ready to spend).
const (
	UtxoUnconfirmedPoolSize = 64 // number of slots in the unconfirmed pool
	UtxoConfirmedPoolStart  = 64 // first ID in the confirmed pool
)

const BalancePrefix = "a" + DirPathDelimiter
const ObservedPrefix = "o" + DirPathDelimiter
const UtxoPrefix = "u" + DirPathDelimiter
const UtxoRegistryKey = "r"
const UtxoLastIdKey = "i"
const TxSpendsRegistryKey = "p"
const TxSpendsPrefix = "d" + DirPathDelimiter
const SupplyKey = "s"

const LastHeightKey = "h"
const SeedHeightKey = "sh"
const PruneFloorKey = "pf" // lowest unpruned block height, updated during pruning

// Instruction URL search param keys
const (
	DepositToKey     = "deposit_to"
	SwapAssetOut     = "swap_asset_out"
	SwapNetworkOut   = "swap_network_out"
	SwapToKey           = "swap_to"
	DestinationChainKey = "destination_chain"
	ReturnAddressKey    = "return_address"
	ReturnNetworkKey    = "return_network"
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

const OracleAddress = "did:vsc:oracle:btc"
const PrimaryPublicKeyStateKey = "pubkey"
const BackupPublicKeyStateKey = "backupkey"

const BlockPrefix = "b" + DirPathDelimiter

// MaxBlockRetention is the number of recent block headers to keep.
// Older headers are pruned during addBlocks to prevent unbounded state growth.
// 101 confirmations exceeds Thorchain's 100-confirmation security threshold.
const MaxBlockRetention = 101

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
