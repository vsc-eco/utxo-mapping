package mapping

import (
	"github.com/btcsuite/btcd/wire"
)

type AccountInfo struct {
	modifiedAt uint64 // hive block height
	address    string // Caip10address (bitcoin address they can recieve funds at)
}

type Utxo struct {
	txId      string // tx containing the output
	vout      uint32
	amount    int64
	pkScript  []byte
	confirmed bool
}

type SigningData struct {
	Tx                 *wire.MsgTx
	UnsignedSignHashes []UnsignedSigHash
}

type UnsignedSigHash struct {
	index         int
	sigHash       []byte
	witnessScript []byte
	amount        int64
}

type MappingInstrutions struct {
	rawInstructions *[]string
	addresses       map[string]bool
}

type ContractState struct {
	// change this
	accountRegistry  map[string]AccountInfo // map[blockchainId]AccountInfo maps vsc did to account info
	addressTagLookup map[string]string      // map of addresses to the tags they were created with
	balances         map[string]uint64
	observedTxs      map[string]bool
	utxos            map[string]Utxo
	instructions     *MappingInstrutions
	activeSupply     uint64
	baseFeeRate      int64 // sats per byte
	publicKey        string
}
