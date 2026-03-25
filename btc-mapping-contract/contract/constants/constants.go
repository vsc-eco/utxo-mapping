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

// BlockHeaderModulus is the number of state slots for recent headers (b/0 … b/99).
// Each slot stores height (4-byte LE) + 80-byte header; key is height % modulus.
// Proofs need the header at a specific height within the last ~100 blocks of the tip.
const BlockHeaderModulus = 100

const (
	Testnet3 string = "testnet3"
	Testnet4 string = "testnet4"
	Mainnet  string = "mainnet"
	Regtest  string = "regtest"
)

func IsTestnet(networkName string) bool {
	return networkName == Testnet3 || networkName == Testnet4 || networkName == Regtest
}
