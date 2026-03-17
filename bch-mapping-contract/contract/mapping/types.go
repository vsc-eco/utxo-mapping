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
	Amount string `json:"amount"`
	To     string `json:"to"`
	From   string `json:"from,omitempty"`
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

// UtxoRegistryEntry holds the single-byte pool ID and the amount for one UTXO.
//
// Binary layout of the registry ("utxor" state key): each entry is 9 bytes.
//   - Byte 0:   ID (0–63 = unconfirmed pool, 64–255 = confirmed pool)
//   - Bytes 1–8: Amount in satoshis (int64, little-endian)
type UtxoRegistryEntry struct {
	Id     uint8 // 0-63 = unconfirmed, 64-255 = confirmed
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
// ConfirmedNextId and UnconfirmedNextId replace the old single uint32 counter.
// They are stored together as 2 bytes at "utxoid": [confirmed, unconfirmed].
type ContractState struct {
	UtxoList          UtxoRegistry
	ConfirmedNextId   uint8 // next candidate in the confirmed pool   (64–255, wraps)
	UnconfirmedNextId uint8 // next candidate in the unconfirmed pool (0–63,  wraps)
	TxSpendsList      TxSpendsRegistry
	Supply            SystemSupply
	PublicKeys        PublicKeys
	NetworkParams     *chaincfg.Params
	NetworkOptions    map[NetworkName]Network
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
	AmountIn      string            `json:"amount_in"`
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

const BchAssetValue string = "BCH"

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
	TxId string `json:"tx_id"`
}
