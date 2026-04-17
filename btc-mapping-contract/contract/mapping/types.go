package mapping

import (
	"net/url"

	"github.com/btcsuite/btcd/chaincfg"
)

//tinyjson:json
type MapParams struct {
	TxData *VerificationRequest `json:"tx_data"`
	// strings should be valid URL search params, to be decoded later
	Instructions []string `json:"instructions"`
}

//tinyjson:json
type VerificationRequest struct {
	BlockHeight    uint32 `json:"block_height"`
	RawTxHex       string `json:"raw_tx_hex"`
	MerkleProofHex string `json:"merkle_proof_hex"` // array of byte arrays, each of which is guaranteed 32 bytes
	TxIndex        uint32 `json:"tx_index"`         // position of the tx in the block
}

type Deposit struct {
	to     string
	from   string
	amount int64
}

//tinyjson:json
type AccountInfo struct {
	ModifiedAt uint64 // hive block height
	Address    string // Caip10address (bitcoin address they can recieve funds at)
}

// address should be Magi for internal transfers and BTC for unmaps
//
//tinyjson:json
type TransferParams struct {
	Amount    string `json:"amount"`
	To        string `json:"to"`
	From      string `json:"from,omitempty"`
	DeductFee bool   `json:"deduct_fee,omitempty"`
	MaxFee    *int64 `json:"max_fee,omitempty"`
}

// Utxo stores full UTXO data indexed by a single-byte pool ID.
// Serialised to binary (not JSON) via MarshalUtxo/UnmarshalUtxo.
// Tag is raw bytes (SHA-256 of the instruction string), not hex.
type Utxo struct {
	TxId     string // display-hex txid (64 chars)
	Vout     uint32
	Amount   int64
	PkScript []byte
	Tag      []byte // raw tag bytes (32 bytes for deposits, empty for change)
}

// UtxoRegistryEntry holds a uint16 pool ID and a 6-byte amount for one UTXO.
//
// Binary layout of the registry ("r" state key): each entry is 8 bytes.
//   - Bytes 0–1: ID (uint16 BE; 0–1023 = unconfirmed, 1024–65535 = confirmed)
//   - Bytes 2–7: Amount in satoshis (uint48 BE, max ~2.81M BTC)
type UtxoRegistryEntry struct {
	Id     uint16 // 0-1023 = unconfirmed, 1024-65535 = confirmed
	Amount int64
}

// UtxoRegistry is the in-memory UTXO list, serialised as packed binary.
type UtxoRegistry []UtxoRegistryEntry

// TxSpendsRegistry is the in-memory list of pending spend-tx IDs (display hex).
// Serialised as packed binary: 32 raw bytes per entry.
type TxSpendsRegistry []string

type MappingType string

const (
	MapDeposit MappingType = "deposit"
	MapSwap    MappingType = "swap"
)

type NetworkName string

type AddressMetadata struct {
	Instruction string
	Params      *url.Values // instruction that is hashed to the tag used to create the address
	Recipient   string
	OutNetwork  NetworkName
	Tag         []byte // tag (hashed instruction) used to create the address
	Type        MappingType
}

// SystemSupply tracks protocol-wide BTC accounting.
// Serialised as 32 raw bytes: four int64 values in little-endian order.
//
// Binary layout ("sply" state key):
//   - Bytes  0– 7: ActiveSupply
//   - Bytes  8–15: UserSupply
//   - Bytes 16–23: FeeSupply
//   - Bytes 24–31: BaseFeeRate (sats per byte)
type SystemSupply struct {
	ActiveSupply int64
	UserSupply   int64
	FeeSupply    int64
	BaseFeeRate  int64 // sats per byte
}

// ContractState is the top-level in-memory state loaded at the start of each
// contract action and saved at the end.
//
// ConfirmedNextId and UnconfirmedNextId are stored together as 4 bytes at "i":
// two uint16 BE values [confirmedNext, unconfirmedNext].
type ContractState struct {
	UtxoList          UtxoRegistry
	ConfirmedNextId   uint16 // next candidate in the confirmed pool   (1024–65535, wraps)
	UnconfirmedNextId uint16 // next candidate in the unconfirmed pool (0–1023,    wraps)
	TxSpendsList      TxSpendsRegistry
	Supply            SystemSupply
	PublicKeys        PublicKeys
	NetworkParams     *chaincfg.Params
}

type MappingState struct {
	ContractState
	AddressRegistry map[string]*AddressMetadata // map of btc addresses to the tags they were created with
}

// DEX Instruction Schema
//
//tinyjson:json
type DexInstruction struct {
	Type             string            `json:"type"`
	Version          string            `json:"version"`
	AssetIn          string            `json:"asset_in"`
	AssetOut         string            `json:"asset_out"`
	Recipient        string            `json:"recipient"`
	MinAmountOut     *string           `json:"min_amount_out,omitempty"`
	Beneficiary      *string           `json:"beneficiary,omitempty"`
	RefBps           *uint64           `json:"ref_bps,omitempty"`
	ReturnAddress    *ReturnAddress    `json:"return_address,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	AmountIn         string            `json:"amount_in"`
	DestinationChain string            `json:"destination_chain,omitempty"`
}

//tinyjson:json
type PoolInfo struct {
	Asset0   string `json:"asset0"`
	Asset1   string `json:"asset1"`
	Reserve0 string `json:"reserve0"`
	Reserve1 string `json:"reserve1"`
	Fee      uint64 `json:"fee"`
	TotalLp  string `json:"total_lp"`
}

//tinyjson:json
type SwapResult struct {
	AmountOut string   `json:"amount_out"`
	PoolState PoolInfo `json:"pool_state"` // Current pool state after swap
}

type ReturnAddress struct {
	Chain   string `json:"chain"`
	Address string `json:"address"`
}

const BtcAssetValue string = "BTC"

//tinyjson:json
type RegisterKeyParams struct {
	PrimaryPubKey string `json:"primary_public_key,omitempty"`
	BackupPubKey  string `json:"backup_public_key,omitempty"`
}

// CompressedPubKey is a 33-byte SEC1 compressed secp256k1 public key.
type CompressedPubKey [33]byte

type PublicKeys struct {
	Primary CompressedPubKey
	Backup  CompressedPubKey
}

//tinyjson:json
type RouterContract struct {
	ContractId string `json:"router_contract"`
}

//tinyjson:json
type AllowanceParams struct {
	Spender string `json:"spender"`
	Amount  string `json:"amount"`
}

//tinyjson:json
type ConfirmSpendParams struct {
	TxData  *VerificationRequest `json:"tx_data"`
	Indices []uint32             `json:"indices"`
}

// MapPageParams is the on-wire shape for a single page of a paginated `map`
// submission. `Payload` is the JSON-encoded MapParams bytes for that page.
//
// The ParentId MUST equal `hex(sha256(full-payload))` computed by the relay
// before chunking. The contract verifies this hash on reassembly to prevent
// tampering across pages.
//
//tinyjson:json
type MapPageParams struct {
	ParentId   string `json:"parent_id"`
	PageIdx    uint32 `json:"page_idx"`
	TotalPages uint32 `json:"total_pages"`
	Payload    string `json:"payload"`
}

// ConfirmSpendPageParams mirrors MapPageParams but for paginated
// `confirmSpend` submissions.
//
//tinyjson:json
type ConfirmSpendPageParams struct {
	ParentId   string `json:"parent_id"`
	PageIdx    uint32 `json:"page_idx"`
	TotalPages uint32 `json:"total_pages"`
	Payload    string `json:"payload"`
}

