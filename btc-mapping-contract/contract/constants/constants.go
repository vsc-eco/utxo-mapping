package constants

const DirPathDelimiter = "/"

const TssKeyName = "main"
const RouterContractIdKey = "routerid"

// UTXO ID pool layout (single-byte ID, 256 slots total).
// IDs 0–63  are the unconfirmed pool (change outputs pending confirmation).
// IDs 64–255 are the confirmed pool   (active mapped UTXOs ready to spend).
const (
	UtxoUnconfirmedPoolSize = 64  // number of slots in the unconfirmed pool
	UtxoConfirmedPoolStart  = 64  // first ID in the confirmed pool
)

const BalancePrefix = "bal" + DirPathDelimiter
const ObservedPrefix = "otx" + DirPathDelimiter
const UtxoPrefix = "utxo" + DirPathDelimiter
const UtxoRegistryKey = "utxor"
const UtxoLastIdKey = "utxoid"
const TxSpendsRegistryKey = "txspdr"
const TxSpendsPrefix = "txspd" + DirPathDelimiter
const SupplyKey = "sply"

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

// Logs
const (
	LogDelimiter      = "|"
	LogKeyDelimiter   = "="
	LogArrayDelimiter = ","
)

const (
	IntentTransferType      = "transfer.allow"
	IntentContractIdKey     = "contract_id"
	IntentLimitKey          = "limit"
	IntentTokenKey          = "token"
	IntentExpenditurePrefix = "total" + DirPathDelimiter
)

const OracleAddress = "did:vsc:oracle:btc"
const PrimaryPublicKeyStateKey = "pubkey"
const BackupPublicKeyStateKey = "backupkey"

const BlockPrefix = "block" + DirPathDelimiter

const (
	Testnet3 string = "testnet3"
	Testnet4 string = "testnet4"
	Mainnet  string = "mainnet"
	Regtest  string = "regtest"
)

func IsTestnet(networkName string) bool {
	return networkName == Testnet3 || networkName == Testnet4 || networkName == Regtest
}
