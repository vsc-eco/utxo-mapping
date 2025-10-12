package mapping

import (
	"contract-template/sdk"
	"crypto/sha256"
	"net/url"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/chaincfg"
)

func IntializeContractState(publicKey string) (*ContractState, error) {
	networkParams := &chaincfg.MainNetParams

	var balances AccountBalanceMap
	balanceState := sdk.StateGetObject(balanceKey)
	err := tinyjson.Unmarshal([]byte(*balanceState), &balances)
	if err != nil {
		return nil, err
	}

	var utxos UtxoMap
	utxoState := sdk.StateGetObject(utxoKey)
	err = tinyjson.Unmarshal([]byte(*utxoState), &utxos)
	if err != nil {
		return nil, err
	}

	var utxoSpends TxSpends
	utxoSpendsState := sdk.StateGetObject(txSpendsKey)
	err = tinyjson.Unmarshal([]byte(*utxoSpendsState), &utxoSpends)
	if err != nil {
		return nil, err
	}

	var supply SystemSupply
	supplyState := sdk.StateGetObject(supplyKey)
	err = tinyjson.Unmarshal([]byte(*supplyState), &supply)
	if err != nil {
		return nil, err
	}

	return &ContractState{
		BasicState: BasicState{
			Balances: balances,
		},
		Utxos:         utxos,
		TxSpends:      utxoSpends,
		Supply:        supply,
		PublicKey:     publicKey,
		NetworkParams: networkParams,
	}, nil
}

func InitializeMappingState(publicKey string, instructions ...string) (*MappingState, error) {
	contractState, err := IntializeContractState(publicKey)
	if err != nil {
		return nil, err
	}

	var registry map[string]*AddressMetadata
	if len(instructions) > 0 {
		var err error
		registry, err = parseInstructions(publicKey, instructions, contractState.NetworkParams)
		if err != nil {
			return nil, err
		}
	}

	var observedTxs ObservedTxList
	obserbedTxsState := sdk.StateGetObject(obserbedKey)
	err = tinyjson.Unmarshal([]byte(*obserbedTxsState), &observedTxs)
	if err != nil {
		return nil, err
	}

	return &MappingState{
		ContractState:   *contractState,
		ObservedTxs:     observedTxs,
		AddressRegistry: registry,
	}, err
}

func GetBalanceMap() (AccountBalanceMap, error) {
	var balances AccountBalanceMap
	balanceState := sdk.StateGetObject(balanceKey)
	err := tinyjson.Unmarshal([]byte(*balanceState), &balances)
	if err != nil {
		return nil, err
	}
	return balances, nil
}

func SaveBalanceMap(balances AccountBalanceMap) error {
	balancesJson, err := tinyjson.Marshal(balances)
	if err != nil {
		return err
	}
	sdk.StateSetObject(balanceKey, string(balancesJson))
	return nil
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
	balancesJson, err := tinyjson.Marshal(cs.Balances)
	if err != nil {
		return err
	}
	sdk.StateSetObject(balanceKey, string(balancesJson))

	utxosJson, err := tinyjson.Marshal(cs.Utxos)
	if err != nil {
		return err
	}
	sdk.StateSetObject(utxoKey, string(utxosJson))

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
	obseredTxsJson, err := tinyjson.Marshal(ms.ObservedTxs)
	if err != nil {
		return err
	}
	sdk.StateSetObject(obserbedKey, string(obseredTxsJson))

	err = ms.ContractState.SaveToState()
	if err != nil {
		return err
	}
	return nil
}
