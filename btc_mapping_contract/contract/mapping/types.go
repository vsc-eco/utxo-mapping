package mapping

import "github.com/holiman/uint256"

type AccountInfo struct {
	modifiedAt uint64 // hive block height
	address    string // Caip10address (bitcoin address they can recieve funds at)
}

type Utxo struct {
	txID    string // tx containing the output
	index   uint32
	address string
	amount  uint256.Int
}

type TxOutput struct {
	index   uint32
	address string
	amount  uint256.Int
}

type SignedUtxo struct {
	utxo      Utxo
	signature string
}

type MappingContract struct {
	// change this
	accountRegistry map[string]AccountInfo // map[blockchainId]AccountInfo maps vsc did to account info
	balances        map[string]uint256.Int
	observedTxs     map[string]bool
	utxos           map[string]Utxo
	utxoSpends      map[string]SignedUtxo
	instructions    map[string]string // map of addresses (created from instructions) to the original raw instruction
	activeSupply    uint256.Int
	baseFee         uint64
	publicKey       string
}
