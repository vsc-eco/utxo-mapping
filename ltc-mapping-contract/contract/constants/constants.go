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

// Instruction URL search param keys
const (
	DepositToKey     = "deposit_to"
	SwapAssetOut     = "swap_asset_out"
	SwapNetworkOut   = "swap_network_out"
	SwapToKey        = "swap_to"
	ReturnAddressKey = "return_address"
	ReturnNetworkKey = "return_network"
)

// Address Creation
const BackupCSVBlocks = 17280 // ~1 month (2.5 min blocks)
const TestnetBackupCSVBlocks = 2

// Logs
const (
	LogDelimiter      = "|"
	LogKeyDelimiter   = "="
	LogArrayDelimiter = ","
)

const AllowancePrefix = "q" + DirPathDelimiter

const OracleAddress = "did:vsc:oracle:ltc"
const PrimaryPublicKeyStateKey = "pubkey"
const BackupPublicKeyStateKey = "backupkey"

const BlockPrefix = "b" + DirPathDelimiter

const (
	Testnet string = "testnet"
	Mainnet string = "mainnet"
)

func IsTestnet(networkName string) bool {
	return networkName == Testnet
}
