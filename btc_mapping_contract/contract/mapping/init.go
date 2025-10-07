package mapping

func NewContractState(publicKey string) *ContractState {
	return &ContractState{
		accountRegistry: make(map[string]AccountInfo),
		balances:        make(map[string]uint64),
		observedTxs:     make(map[string]bool),
		utxos:           make(map[string]Utxo),
		activeSupply:    0,
		baseFeeRate:     1,
		publicKey:       publicKey,
	}
}

func (cs *ContractState) setInstructions(rawInstrucions *string) {
	// TODO: parse from the raw instructions once format is established
	instrutionsArray := []string{}

	cs.instructions = &MappingInstrutions{
		rawInstructions: &instrutionsArray,
		addresses:       make(map[string]bool),
	}
}
