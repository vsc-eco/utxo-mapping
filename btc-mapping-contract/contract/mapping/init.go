package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"crypto/sha256"
	"net/url"

	"github.com/btcsuite/btcd/chaincfg"
)

func IntializeContractState(publicKeys *PublicKeys, networkMode string) (*ContractState, error) {
	var networkParams *chaincfg.Params
	switch networkMode {
	case constants.Testnet3:
		networkParams = &chaincfg.TestNet3Params
	case constants.Testnet4:
		networkParams = &chaincfg.TestNet4Params
	case constants.Regtest:
		networkParams = &chaincfg.RegressionNetParams
	default:
		networkParams = &chaincfg.MainNetParams
	}

	// Load UTXO registry (binary: 9 bytes/entry)
	var utxos UtxoRegistry
	utxoState := sdk.StateGetObject(constants.UtxoRegistryKey)
	if len(*utxoState) > 0 {
		var err error
		utxos, err = UnmarshalUtxoRegistry([]byte(*utxoState))
		if err != nil {
			return nil, ce.NewContractError(ce.ErrStateAccess, "error decoding utxo registry: "+err.Error())
		}
	}

	// Load UTXO pool counters (2 bytes: [confirmedNext, unconfirmedNext])
	confirmedNextId := uint8(constants.UtxoConfirmedPoolStart)
	unconfirmedNextId := uint8(0)
	counterState := sdk.StateGetObject(constants.UtxoLastIdKey)
	if len(*counterState) == 2 {
		confirmedNextId = (*counterState)[0]
		unconfirmedNextId = (*counterState)[1]
	}

	// Load TX spends registry (binary: 32 bytes/entry)
	var txSpends TxSpendsRegistry
	txSpendsState := sdk.StateGetObject(constants.TxSpendsRegistryKey)
	if len(*txSpendsState) > 0 {
		var err error
		txSpends, err = UnmarshalTxSpendsRegistry([]byte(*txSpendsState))
		if err != nil {
			return nil, ce.NewContractError(ce.ErrStateAccess, "error decoding txspends registry: "+err.Error())
		}
	}

	// Load supply (binary: 32 bytes)
	var supply SystemSupply
	supplyState := sdk.StateGetObject(constants.SupplyKey)
	if len(*supplyState) > 0 {
		s, err := UnmarshalSupply([]byte(*supplyState))
		if err != nil {
			return nil, ce.NewContractError(ce.ErrStateAccess, "error decoding supply: "+err.Error())
		}
		supply = *s
	}

	return &ContractState{
		UtxoList:          utxos,
		ConfirmedNextId:   confirmedNextId,
		UnconfirmedNextId: unconfirmedNextId,
		TxSpendsList:      txSpends,
		Supply:            supply,
		PublicKeys:        publicKeys,
		NetworkParams:     networkParams,
		NetworkOptions:    initNetworkLookup(networkParams),
	}, nil
}

func InitializeMappingState(publicKeys *PublicKeys, networkMode string, instructions ...string) (*MappingState, error) {
	contractState, err := IntializeContractState(publicKeys, networkMode)
	if err != nil {
		return nil, err
	}

	var registry map[string]*AddressMetadata
	if len(instructions) > 0 {
		var err error
		registry, err = contractState.parseInstructions(publicKeys, instructions, contractState.NetworkParams)
		if err != nil {
			return nil, ce.WrapContractError(ce.ErrStateAccess, err, "error unmarshalling address registry")
		}
	}

	return &MappingState{
		ContractState:   *contractState,
		AddressRegistry: registry,
	}, err
}

func (cs *ContractState) parseInstructions(
	publicKeys *PublicKeys,
	instrs []string,
	networkParams *chaincfg.Params,
) (map[string]*AddressMetadata, error) {
	parsedInstructions := make([]url.Values, len(instrs))
	registry := make(map[string]*AddressMetadata, len(instrs))
	for i, instr := range instrs {
		params, err := url.ParseQuery(instr)
		parsedInstructions[i] = params
		if err != nil {
			return nil, err
		}

		// validates all destination addresses as vaild on their network
		// assumes VSC as the network for deposits and unspecified swaps
		var recipient string
		var mappingType MappingType
		if params.Has(constants.DepositToKey) {
			recipient = params.Get(constants.DepositToKey)
			if !cs.NetworkOptions[Vsc].ValidateAddress(recipient) {
				return nil, ce.NewContractError(
					ce.ErrInput,
					"address \""+recipient+"\" invalid on network \""+string(Vsc)+"\"",
					"bad instruction \""+instr+"\"",
				)
			}
			mappingType = MapDeposit
		} else if params.Has(constants.SwapToKey) {
			recipient = params.Get(constants.SwapToKey)
			recipientNetwork, err := cs.getNetwork(params.Get(constants.SwapNetworkOut))
			if err != nil {
				recipientNetwork = cs.NetworkOptions[Vsc]
			}
			mappingType = MapSwap
			if !recipientNetwork.ValidateAddress(recipient) {
				return nil, ce.NewContractError(
					ce.ErrInput,
					"address \""+recipient+"\" invalid on network \""+string(recipientNetwork.Name())+"\"",
					"bad instruction \""+instr+"\"",
				)
			}
		}
		if recipient != "" {
			hasher := sha256.New()
			hasher.Write([]byte(instr))
			hashBytes := hasher.Sum(nil)
			address, _, err := createP2WSHAddressWithBackup(
				publicKeys.PrimaryPubKey,
				publicKeys.BackupPubKey,
				hashBytes,
				networkParams,
			)
			if err != nil {
				return nil, err
			}
			registry[address] = &AddressMetadata{
				Instruction: instr,
				Recipient:   recipient,
				Params:      &params,
				Tag:         hashBytes,
				Type:        mappingType,
			}
		}
		// should error for unsupported instruction?
	}
	return registry, nil
}

func (cs *ContractState) SaveToState() error {
	// UTXO registry (binary)
	sdk.StateSetObject(constants.UtxoRegistryKey, string(MarshalUtxoRegistry(cs.UtxoList)))

	// UTXO pool counters (2 bytes: [confirmedNext, unconfirmedNext])
	sdk.StateSetObject(constants.UtxoLastIdKey, string([]byte{cs.ConfirmedNextId, cs.UnconfirmedNextId}))

	// TX spends registry (binary)
	sdk.StateSetObject(constants.TxSpendsRegistryKey, string(MarshalTxSpendsRegistry(cs.TxSpendsList)))

	// Supply (binary)
	sdk.StateSetObject(constants.SupplyKey, string(MarshalSupply(&cs.Supply)))

	return nil
}

func (ms *MappingState) SaveToState() error {
	return ms.ContractState.SaveToState()
}

func SupplyFromState() (*SystemSupply, error) {
	supplyState := sdk.StateGetObject(constants.SupplyKey)
	if len(*supplyState) == 0 {
		return &SystemSupply{}, nil
	}
	s, err := UnmarshalSupply([]byte(*supplyState))
	if err != nil {
		return nil, ce.NewContractError(ce.ErrStateAccess, "error decoding supply: "+err.Error())
	}
	return s, nil
}

func SaveSupplyToState(supply *SystemSupply) error {
	sdk.StateSetObject(constants.SupplyKey, string(MarshalSupply(supply)))
	return nil
}
