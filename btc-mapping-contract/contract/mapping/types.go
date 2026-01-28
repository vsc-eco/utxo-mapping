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
const depositKey = "deposit_to"
const swapAssetOut = "swap_asset_out"
const swapNetworkOut = "swap_network_out"
const swapRecipientKey = "swap_to"
const returnAddressKey = "return_address"
const returnNetworkKey = "return_network"

// Address Creation
const backupCSVBlocks = 4320 // ~1 month

// contract IDs
const routerContracId = "INSERT_ROUTER_ID_HERE"

//tinyjson:json
type MappingParams struct {
	TxData *VerificationRequest
	// strings should be valid URL search params, to be decoded later
	Instructions []string
}

//tinyjson:json
type MappingResults []*MappingResult

//tinyjson:json
type MappingResult struct {
	Instruction    string      `json:"instruction"`
	DepositAddress string      `json:"deposit_address,omitempty"`
	Depositnetwork NetworkName `json:"deposit_network,omitempty"`
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
