package mapping

import "github.com/holiman/uint256"

func NewMappingContract(publicKey string) *MappingContract {
	return &MappingContract{
		accountRegistry: make(map[string]AccountInfo),
		balances:        make(map[string]uint256.Int),
		observedTxs:     make(map[string]bool),
		utxos:           make(map[string]Utxo),
		utxoSpends:      make(map[string]SignedUtxo),
		instructions:    make(map[string]string),
		activeSupply:    *uint256.NewInt(0),
		baseFee:         0,
		publicKey:       publicKey,
	}
}
