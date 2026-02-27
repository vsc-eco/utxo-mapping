package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"crypto/sha256"
	"net/url"
	"strconv"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/chaincfg"
)

func IntializeContractState(publicKeys *PublicKeys, networkMode string) (*ContractState, error) {
	var networkParams *chaincfg.Params
	switch networkMode {
	case constants.Testnet3:
		networkParams = &chaincfg.TestNet3Params
	case constants.Testnet4:
		networkParams = &chaincfg.TestNet4Params
	default:
		networkParams = &chaincfg.MainNetParams
	}

	var utxos UtxoRegistry
	utxoState := sdk.StateGetObject(UtxoRegistryKey)
	if len(*utxoState) > 0 {
		err := tinyjson.Unmarshal([]byte(*utxoState), &utxos)
		if err != nil {
			return nil, ce.NewContractError(ce.ErrJson, "error unmarshaling utxo registry: "+err.Error())
		}
	}

	lastUtxoIdHex := sdk.StateGetObject(UtxoLastIdKey)
	lastUtxoId, err := strconv.ParseUint(*lastUtxoIdHex, 16, 32)
	if err != nil {
		if *lastUtxoIdHex == "" {
			lastUtxoId = 0
		} else {
			return nil, ce.NewContractError(ce.ErrStateAccess, "error fetching last utxo internal id: "+err.Error())
		}
	}

	var txSpends TxSpendsRegistry
	txSpendsState := sdk.StateGetObject(TxSpendsRegistryKey)
	if len(*txSpendsState) > 0 {
		err := tinyjson.Unmarshal([]byte(*txSpendsState), &txSpends)
		if err != nil {
			return nil, ce.NewContractError(ce.ErrStateAccess, "error unmarshaling txspends registry: "+err.Error())
		}
	}

	var supply SystemSupply
	supplyState := sdk.StateGetObject(SupplyKey)
	if len(*supplyState) > 0 {
		err := tinyjson.Unmarshal([]byte(*supplyState), &supply)
		if err != nil {
			return nil, ce.NewContractError(ce.ErrStateAccess, "error unmarshalling supply: "+err.Error())
		}
	}

	return &ContractState{
		UtxoList:       utxos,
		UtxoNextId:     uint32(lastUtxoId),
		Supply:         supply,
		PublicKeys:     publicKeys,
		NetworkParams:  networkParams,
		NetworkOptions: initNetworkLookup(networkParams),
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
		if params.Has(depositKey) {
			recipient = params.Get(depositKey)
			if !cs.NetworkOptions[Vsc].ValidateAddress(recipient) {
				return nil, ce.NewContractError(
					ce.ErrInput,
					"address \""+recipient+"\" invalid on network \""+string(Vsc)+"\"",
					"bad instruction \""+instr+"\"",
				)
			}
			mappingType = MapDeposit
		} else if params.Has(swapRecipientKey) {
			recipient = params.Get(swapRecipientKey)
			recipientNetwork, err := cs.getNetwork(params.Get(swapNetworkOut))
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
	}
	return registry, nil
}

func (cs *ContractState) SaveToState() error {
	utxosJson, err := tinyjson.Marshal(cs.UtxoList)
	if err != nil {
		return ce.NewContractError(ce.ErrJson, "error marshaling utxo listings: "+err.Error())
	}
	sdk.StateSetObject(UtxoRegistryKey, string(utxosJson))

	sdk.StateSetObject(UtxoLastIdKey, strconv.FormatUint(uint64(cs.UtxoNextId), 16))

	txSpendsJson, err := tinyjson.Marshal(cs.TxSpendsList)
	if err != nil {
		return ce.NewContractError(ce.ErrJson, "error marshaling tx spends: "+err.Error())
	}
	sdk.StateSetObject(TxSpendsRegistryKey, string(txSpendsJson))

	supplyJson, err := tinyjson.Marshal(cs.Supply)
	if err != nil {
		return ce.NewContractError(ce.ErrJson, "error marshaling supply: "+err.Error())
	}
	sdk.StateSetObject(SupplyKey, string(supplyJson))

	return nil
}

func (ms *MappingState) SaveToState() error {
	err := ms.ContractState.SaveToState()
	if err != nil {
		return err
	}
	return nil
}

func SupplyFromState() (*SystemSupply, error) {
	var supply SystemSupply
	supplyState := sdk.StateGetObject(SupplyKey)
	if len(*supplyState) > 0 {
		err := tinyjson.Unmarshal([]byte(*supplyState), &supply)
		if err != nil {
			return nil, ce.NewContractError(ce.ErrStateAccess, "error unmarshalling supply: "+err.Error())
		}
	}

	return &supply, nil
}

func SaveSupplyToState(supply *SystemSupply) error {
	supplyJson, err := tinyjson.Marshal(supply)
	if err != nil {
		return err
	}
	sdk.StateSetObject(SupplyKey, string(supplyJson))

	return nil
}
