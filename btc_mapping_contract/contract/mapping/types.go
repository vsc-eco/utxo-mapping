package mapping

import (
	"github.com/btcsuite/btcd/wire"
)

const BALANCEKEY = "account_balances"
const OBSERVEDKEY = "observes_txs"
const UTXOKEY = "utxos"

//tinyjson:json
type MappingInputData struct {
	TxData *VerificationRequest
	// strings should be valid URL search params, to be decoded later
	RawInstructions []string
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
	amount              int64
	recipientBtcAddress string
}

//tinyjson:json
type Utxo struct {
	TxId      string // tx containing the output
	Vout      uint32 // defined as uint32 in btcd library
	Amount    int64
	PkScript  []byte
	Confirmed bool
}

//tinyjson:json
type HeaderMap map[uint32][]byte

type SigningData struct {
	Tx                 *wire.MsgTx
	UnsignedSignHashes []UnsignedSigHash
}

type UnsignedSigHash struct {
	Index         uint32
	SigHash       []byte
	WitnessScript []byte
	Amount        int64
}

type AddressMetadata struct {
	Tag        string
	VscAddress string
}

//tinyjson:json
type AccountBalanceMap map[string]int64

//tinyjson:json
type ObservedTxList map[string]bool

//tinyjson:json
type UtxoMap map[string]Utxo

type ContractState struct {
	// change this
	AddressRegistry    map[string]*AddressMetadata // map of addresses to the tags they were created with
	Balances           AccountBalanceMap           // map of vsc addresses to the btc balance they hold
	ObservedTxs        ObservedTxList
	Utxos              UtxoMap
	PossibleRecipients map[string]bool
	ActiveSupply       int64
	UserSupply         int64
	FeeSupply          int64
	BaseFeeRate        int64 // sats per byte
	PublicKey          string
}
