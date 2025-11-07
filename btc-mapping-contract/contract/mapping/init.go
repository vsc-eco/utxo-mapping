package mapping

import (
	"contract-template/sdk"
	"crypto/sha256"
	"fmt"
	"net/url"
	"strconv"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/chaincfg"
)

func IntializeContractState(publicKey string, networkMode string) (*ContractState, error) {
	var networkParams *chaincfg.Params
	if networkMode == "testnet" {
		networkParams = &chaincfg.TestNet3Params
	} else {
		networkParams = &chaincfg.MainNetParams
	}

	var utxos UtxoRegistry
	utxoState := sdk.StateGetObject(utxoRegistryKey)
	if len(*utxoState) > 0 {
		err := tinyjson.Unmarshal([]byte(*utxoState), &utxos)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling utxo registry: %w", err)
		}
	}

	lastUtxoIdHex := sdk.StateGetObject(utxoLastIdKey)
	lastUtxoId, err := strconv.ParseInt(*lastUtxoIdHex, 16, 32)
	if err != nil {
		if *lastUtxoIdHex == "" {
			lastUtxoId = 0
		} else {
			return nil, fmt.Errorf("error fetching last utxo internal id: %w", err)
		}
	}

	var utxoSpends TxSpends
	utxoSpendsState := sdk.StateGetObject(txSpendsKey)
	if len(*utxoSpendsState) > 0 {
		err := tinyjson.Unmarshal([]byte(*utxoSpendsState), &utxoSpends)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling utxo spends: %w", err)
		}
	}

	var supply SystemSupply
	supplyState := sdk.StateGetObject(supplyKey)
	if len(*supplyState) > 0 {
		err := tinyjson.Unmarshal([]byte(*supplyState), &supply)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling supply: %w", err)
		}
	}

	return &ContractState{
		UtxoList:      utxos,
		UtxoLastId:    uint32(lastUtxoId),
		TxSpends:      utxoSpends,
		Supply:        supply,
		PublicKey:     publicKey,
		NetworkParams: networkParams,
	}, nil
}

func InitializeMappingState(publicKey string, networkMode string, instructions ...string) (*MappingState, error) {
	contractState, err := IntializeContractState(publicKey, networkMode)
	if err != nil {
		return nil, err
	}

	var registry map[string]*AddressMetadata
	if len(instructions) > 0 {
		var err error
		registry, err = parseInstructions(publicKey, instructions, contractState.NetworkParams)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling address registry: %w", err)
		}
	}

	return &MappingState{
		ContractState:   *contractState,
		AddressRegistry: registry,
	}, err
}

func parseInstructions(
	publicKey string,
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
		if params.Has(depositKey) {
			hasher := sha256.New()
			hasher.Write([]byte(instr))
			hashBytes := hasher.Sum(nil)
			address, _, err := createP2WSHAddress(publicKey, hashBytes, networkParams)
			if err != nil {
				return nil, err
			}
			registry[address] = &AddressMetadata{
				VscAddress:  params.Get(depositKey),
				Instruction: instr,
				Tag:         hashBytes,
			}
		}
	}
	return registry, nil
}

func (cs *ContractState) SaveToState() error {
	utxosJson, err := tinyjson.Marshal(cs.UtxoList)
	if err != nil {
		return err
	}
	sdk.StateSetObject(utxoRegistryKey, string(utxosJson))

	sdk.StateSetObject(utxoLastIdKey, fmt.Sprintf("%x", cs.UtxoLastId))

	utxoSpendsJson, err := tinyjson.Marshal(cs.TxSpends)
	if err != nil {
		return err
	}
	sdk.StateSetObject(txSpendsKey, string(utxoSpendsJson))

	supplyJson, err := tinyjson.Marshal(cs.Supply)
	if err != nil {
		return err
	}
	sdk.StateSetObject(supplyKey, string(supplyJson))

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
	supplyState := sdk.StateGetObject(supplyKey)
	if len(*supplyState) > 0 {
		err := tinyjson.Unmarshal([]byte(*supplyState), &supply)
		if err != nil {
			return nil, err
		}
	}

	return &supply, nil
}

func SaveSupplyToState(supply *SystemSupply) error {
	supplyJson, err := tinyjson.Marshal(supply)
	if err != nil {
		return err
	}
	sdk.StateSetObject(supplyKey, string(supplyJson))

	return nil
}
