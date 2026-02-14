package mapping

import (
	"net/url"

	"github.com/btcsuite/btcd/chaincfg"
)

const balancePrefix = "bal/"
const observedPrefix = "observed_txs/"
const utxoPrefix = "utxos/"
const utxoRegistryKey = "utxo_registry"
const utxoLastIdKey = "utxo_id"
const txSpendsRegistryKey = "tx_spend_registry"
const txSpendsPrefix = "tx-spend/"
const supplyKey = "supply"

const TssKeyName string = "main"

// Instruction URL search param keys
const (
	depositKey       = "deposit_to"
	swapAssetOut     = "swap_asset_out"
	swapNetworkOut   = "swap_network_out"
	swapRecipientKey = "swap_to"
	returnAddressKey = "return_address"
	returnNetworkKey = "return_network"
)

// Address Creation
const backupCSVBlocks = 4320 // ~1 month

// contract IDs
const routerContractId = "INSERT_ROUTER_ID_HERE"

// Logs
const (
	logDelimiter      = "|"
	logKeyDelimiter   = "="
	logArrayDelimiter = ","
)

const (
	intentTransferType     = "transfer.allow"
	intentContractTokenKey = "contract_token"
	intentAmountKey        = "amount"
	intentLimitPrefix      = "limit/"
)

//tinyjson:json
type MappingParams struct {
	TxData *VerificationRequest
	// strings should be valid URL search params, to be decoded later
	Instructions []string
}

type Deposit struct {
	to     string
	from   []string
	amount int64
}

//tinyjson:json
type VerificationRequest struct {
	BlockHeight    uint32
	RawTxHex       string
	MerkleProofHex string // array of byte arrays, each of which is guaranteed 32 bytes
	TxIndex        uint32 // position of the tx in the block
}

//tinyjson:json
type AccountInfo struct {
	ModifiedAt uint64 // hive block height
	Address    string // Caip10address (bitcoin address they can recieve funds at)
}

// address should be Magi for internal transfers and BTC for unmaps
//
//tinyjson:json
type SendParams struct {
	Amount  int64
	Address string
}

//tinyjson:json
type Utxo struct {
	TxId     string // tx containing the output
	Vout     uint32 // defined as uint32 in btcd library
	Amount   int64
	PkScript []byte
	Tag      string // tag used to create the address
}

//tinyjson:json
type UtxoRegistry [][3]int64

//tinyjson:json
type TxSpendsRegistry []string

//tinyjson:json
type SigningData struct {
	Tx                string
	UnsignedSigHashes []UnsignedSigHash
}

type UnsignedSigHash struct {
	Index         uint32
	SigHash       string
	WitnessScript string
}

type MappingType string

const (
	MapDeposit MappingType = "deposit"
	MapSwap    MappingType = "swap"
)

type NetworkName string

const (
	Testnet3 string = "testnet3"
	Testnet4 string = "testnet4"
	Mainnet  string = "mainnet"
)

type AddressMetadata struct {
	Instruction string
	Params      *url.Values // instruction that is hashed to the tag used to create the address
	Recipient   string
	OutNetwork  NetworkName
	Tag         []byte // tag (hashed instruction) used to create the address
	Type        MappingType
}

//tinyjson:json
type SystemSupply struct {
	ActiveSupply int64
	UserSupply   int64
	FeeSupply    int64
	BaseFeeRate  int64 // sats per byte
}

type ContractState struct {
	UtxoList       UtxoRegistry
	UtxoNextId     uint32
	TxSpendsList   TxSpendsRegistry
	Supply         SystemSupply
	PublicKeys     *PublicKeys
	NetworkParams  *chaincfg.Params
	NetworkOptions map[NetworkName]Network
}

type MappingState struct {
	ContractState
	AddressRegistry map[string]*AddressMetadata // map of btc addresses to the tags they were created with
}

// DEX Instruction Schema
//
//tinyjson:json
type DexInstruction struct {
	Type          string            `json:"type"`
	Version       string            `json:"version"`
	AssetIn       string            `json:"asset_in"`
	AssetOut      string            `json:"asset_out"`
	Recipient     string            `json:"recipient"`
	SlippageBps   *int              `json:"slippage_bps,omitempty"`
	MinAmountOut  *int64            `json:"min_amount_out,omitempty"`
	Beneficiary   *string           `json:"beneficiary,omitempty"`
	RefBps        *int              `json:"ref_bps,omitempty"`
	ReturnAddress *ReturnAddress    `json:"return_address,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	AmountIn      int64             `json:"amount_in"`
}

//tinyjson:json
type PoolInfo struct {
	Asset0   string `json:"asset0"`
	Asset1   string `json:"asset1"`
	Reserve0 uint64 `json:"reserve0"`
	Reserve1 uint64 `json:"reserve1"`
	Fee      uint64 `json:"fee"`
	TotalLp  uint64 `json:"total_lp"`
}

//tinyjson:json
type SwapResult struct {
	AmountOut uint64   `json:"amount_out"`
	PoolState PoolInfo `json:"pool_state"` // Current pool state after swap
}

type ReturnAddress struct {
	Chain   string `json:"chain"`
	Address string `json:"address"`
}

const BtcAssetValue string = "BTC"

//tinyjson:json
type PublicKeys struct {
	PrimaryPubKey string `json:"primary_public_key,omitempty"`
	BackupPubKey  string `json:"backup_public_key,omitempty"`
}
