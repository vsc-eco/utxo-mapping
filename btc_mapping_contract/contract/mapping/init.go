package mapping

func NewContractState(publicKey string) *ContractState {
	return &ContractState{
		accountRegistry:  make(map[string]*AccountInfo),
		addressTagLookup: make(map[string]string),
		balances:         make(map[string]int64),
		observedTxs:      make(map[string]bool),
		utxos:            make(map[string]Utxo),
		activeSupply:     0,
		baseFeeRate:      1,
		publicKey:        publicKey,
	}
}

func NewTestValuesState(publicKey string) *ContractState {
	accountRegistry := map[string]*AccountInfo{
		"hive:milo-hpr": &AccountInfo{
			address: "tb1q7eag20gm5vu6rguwc4hhq8d2jmpude8dhk9z3f0ztrw95nexdnfsppgh6h",
		},
	}
	addressTagLookup := map[string]string{
		"tb1q7eag20gm5vu6rguwc4hhq8d2jmpude8dhk9z3f0ztrw95nexdnfsppgh6h": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
	}
	instructions := MappingInstrutions{
		addresses: map[string]bool{"tb1q7eag20gm5vu6rguwc4hhq8d2jmpude8dhk9z3f0ztrw95nexdnfsppgh6h": true},
	}
	return &ContractState{
		accountRegistry:  accountRegistry,
		addressTagLookup: addressTagLookup,
		balances:         make(map[string]int64),
		observedTxs:      make(map[string]bool),
		utxos:            make(map[string]Utxo),
		activeSupply:     0,
		baseFeeRate:      1,
		publicKey:        publicKey,
		instructions:     &instructions,
	}
}

func NewTestUnmapValuesState(publicKey string) *ContractState {
	accountRegistry := map[string]*AccountInfo{
		"hive:milo-hpr": &AccountInfo{
			address: "tb1q7eag20gm5vu6rguwc4hhq8d2jmpude8dhk9z3f0ztrw95nexdnfsppgh6h",
		},
	}
	addressTagLookup := map[string]string{
		"tb1q7eag20gm5vu6rguwc4hhq8d2jmpude8dhk9z3f0ztrw95nexdnfsppgh6h": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
	}
	balances := map[string]int64{
		"hive:milo-hpr": 119579,
	}
	observedTxs := map[string]bool{
		"5b6808faf6b7bdc53d705efb6b493dadf1f858de47fba0fbdd454772f0f56a0a:0": true,
	}
	utxos := map[string]Utxo{
		"5b6808faf6b7bdc53d705efb6b493dadf1f858de47fba0fbdd454772f0f56a0a:0": Utxo{
			txId:      "5b6808faf6b7bdc53d705efb6b493dadf1f858de47fba0fbdd454772f0f56a0a",
			vout:      0,
			amount:    119579,
			pkScript:  []byte{0, 32, 246, 122, 133, 61, 27, 163, 57, 161, 163, 142, 197, 111, 112, 29, 170, 150, 195, 198, 228, 237, 189, 138, 40, 165, 226, 88, 220, 90, 79, 38, 108, 211},
			confirmed: true,
		},
	}
	return &ContractState{
		accountRegistry:  accountRegistry,
		addressTagLookup: addressTagLookup,
		balances:         balances,
		observedTxs:      observedTxs,
		utxos:            utxos,
		instructions:     &MappingInstrutions{},
		activeSupply:     119579,
		baseFeeRate:      1,
		publicKey:        publicKey,
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
