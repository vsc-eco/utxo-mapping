package mapping

import (
	"net/url"

	"github.com/btcsuite/btcd/chaincfg"
)

const balancePrefix = "bal"
const observedPrefix = "observed_txs"
const utxoPrefix = "utxos"
const utxoRegistryKey = "utxo_registry"
const utxoLastIdKey = "utxo_last_id"
const txSpendsRegistryKey = "tx_spend_registry"
const txSpendsPrefix = "tx_spend"
const supplyKey = "supply"

const TssKeyName string = "main"

//tinyjson:json
type MappingInputData struct {
	TxData *VerificationRequest
	// strings should be valid URL search params, to be decoded later
	Instructions []string
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

//tinyjson:json
type UnmappingInputData struct {
	Amount              int64
	RecipientBtcAddress string
}

//tinyjson:json
type TransferInputData struct {
	Amount              int64
	RecipientVscAddress string
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
type UtxoRegistry [][3][]byte

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

type AddressMetadata struct {
	Instruction *url.Values // instruction that is hashed to the tag used to create the address
	VscAddress  string
	Tag         []byte // tag (hashed instruction) used to create the address
	Type        MappingType
}

//tinyjson:json
type AccountBalanceMap map[string]int64

//tinyjson:json
type SystemSupply struct {
	ActiveSupply int64
	UserSupply   int64
	FeeSupply    int64
	BaseFeeRate  int64 // sats per byte
}

type ContractState struct {
	UtxoList      UtxoRegistry
	UtxoLastId    uint32
	TxSpendsList  TxSpendsRegistry
	Supply        SystemSupply
	PublicKey     string
	NetworkParams *chaincfg.Params
}

type MappingState struct {
	ContractState
	AddressRegistry map[string]*AddressMetadata // map of btc addresses to the tags they were created with
}
