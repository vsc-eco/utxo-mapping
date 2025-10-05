package mapping

import (
	"contract-template/contract/utils"

	"github.com/holiman/uint256"
)

func NewMappingContract(publicKey string) *MappingContract {
	return &MappingContract{
		accountRegistry: make(map[string]accountInfo),
		balances:        make(map[string]uint256.Int),
		observedTxs:     make(map[string]bool),
		utxos:           make(map[string]utxo),
		utxoSpends:      make(map[string]SignedUtxo),
		activeSupply:    *uint256.NewInt(0),
		baseFee:         0,
		publicKey:       publicKey,
	}
}

func (mc *MappingContract) setInstructions(rawInstrucions *string) {
	// TODO: parse from the raw instructions once format is established
	instrutionsArray := []string{}

	mc.instructions = instrutions{
		rawInstructions: &instrutionsArray,
		addressType:     utils.P2WSH,
		addresses:       make(map[string]bool),
	}
}
