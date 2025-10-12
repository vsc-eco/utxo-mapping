package mapping

import "github.com/btcsuite/btcd/chaincfg"

const balanceKey = "account_balances"
const obserbedKey = "observed_txs"
const utxoKey = "utxos"
const txSpendsKey = "tx_spends"
const supplyKey = "system_supply"

const depositKey = "deposit_to"

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
	TxId      string // tx containing the output
	Vout      uint32 // defined as uint32 in btcd library
	Amount    int64
	PkScript  []byte
	Tag       string // tag used to create the address
	Confirmed bool
}

//tinyjson:json
type HeaderMap map[uint32][]byte

type SigningData struct {
	Tx                string
	UnsignedSigHashes []UnsignedSigHash
}

type UnsignedSigHash struct {
	Index         uint32
	SigHash       string
	WitnessScript string
}

type AddressMetadata struct {
	Instruction string // instruction that is hashed to the tag used to create the address
	VscAddress  string
	Tag         []byte // tag (hashed instruction) used to create the address
}

//tinyjson:json
type AccountBalanceMap map[string]int64

//tinyjson:json
type ObservedTxList map[string]bool

//tinyjson:json
type UtxoMap map[string]*Utxo

// txs that have been built and stored (for the mapping bot to see and sign)
//
//tinyjson:json
type TxSpends map[string]*SigningData

//tinyjson:json
type SystemSupply struct {
	ActiveSupply int64
	UserSupply   int64
	FeeSupply    int64
	BaseFeeRate  int64 // sats per byte
}

type BasicState struct {
	Balances AccountBalanceMap // map of vsc addresses to the btc balance they hold
}

type ContractState struct {
	BasicState
	Utxos         UtxoMap
	TxSpends      TxSpends
	Supply        SystemSupply
	PublicKey     string
	NetworkParams *chaincfg.Params
}

type MappingState struct {
	ContractState
	ObservedTxs     ObservedTxList
	AddressRegistry map[string]*AddressMetadata // map of btc addresses to the tags they were created with
}
