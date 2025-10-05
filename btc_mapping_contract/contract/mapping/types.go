package mapping

import (
	"contract-template/contract/utils"

	"github.com/holiman/uint256"
)

type accountInfo struct {
	modifiedAt uint64 // hive block height
	address    string // Caip10address (bitcoin address they can recieve funds at)
}

type utxo utils.Utxo

type SignedUtxo struct {
	utxo      utxo
	signature string
}

type instrutions struct {
	rawInstructions *[]string
	addressType     utils.AddressType
	addresses       map[string]bool
}

type MappingContract struct {
	// change this
	accountRegistry map[string]accountInfo // map[blockchainId]AccountInfo maps vsc did to account info
	balances        map[string]uint256.Int
	observedTxs     map[string]bool
	utxos           map[string]utxo
	utxoSpends      map[string]SignedUtxo
	instructions    instrutions // map of addresses (created from instructions) to the original raw instruction
	activeSupply    uint256.Int
	baseFee         uint64
	publicKey       string
}
