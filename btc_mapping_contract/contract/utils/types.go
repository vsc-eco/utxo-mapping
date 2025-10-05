package utils

import "github.com/holiman/uint256"

type Utxo struct {
	TxID    string // tx containing the output
	Vout    uint32
	Address string
	Amount  uint256.Int
}
