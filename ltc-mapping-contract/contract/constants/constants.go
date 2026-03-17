package constants

const DirPathDelimiter = "/"

const TssKeyName = "main"
const RouterContractIdKey = "routerid"

const OracleAddress = "did:vsc:oracle:ltc"
const PrimaryPublicKeyStateKey = "pubkey"
const BackupPublicKeyStateKey = "backupkey"

const BlockPrefix = "block" + DirPathDelimiter

const BalancePrefix = "bal" + DirPathDelimiter
const ObservedPrefix = "otx" + DirPathDelimiter
const UtxoPrefix = "utxo" + DirPathDelimiter
const UtxoRegistryKey = "utxor"
const UtxoLastIdKey = "utxoid"
const TxSpendsRegistryKey = "txspdr"
const TxSpendsPrefix = "txspd" + DirPathDelimiter
const SupplyKey = "sply"

const AllowancePrefix = "q" + DirPathDelimiter

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

const (
	Testnet string = "testnet"
	Mainnet string = "mainnet"
)

func IsTestnet(networkName string) bool {
	return networkName == Testnet
}
