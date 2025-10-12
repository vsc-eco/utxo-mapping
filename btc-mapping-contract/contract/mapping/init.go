package mapping

import (
	"contract-template/sdk"
	"crypto/sha256"
	"net/url"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/chaincfg"
)

func IntializeContractState(publicKey string, instructions ...string) (*ContractState, error) {
	networkParams := &chaincfg.MainNetParams

	var registry map[string]*AddressMetadata
	if len(instructions) > 0 {
		var err error
		registry, err = parseInstructions(publicKey, instructions, networkParams)
		if err != nil {
			return nil, err
		}
	}

	var balances AccountBalanceMap
	balanceState := sdk.StateGetObject(balanceKey)
	err := tinyjson.Unmarshal([]byte(*balanceState), &balances)
	if err != nil {
		return nil, err
	}

	var observedTxs ObservedTxList
	obserbedTxsState := sdk.StateGetObject(obserbedKey)
	err = tinyjson.Unmarshal([]byte(*obserbedTxsState), &observedTxs)
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
		AddressRegistry: registry,
		Balances:        balances,
		ObservedTxs:     observedTxs,
		Utxos:           utxos,
		TxSpends:        utxoSpends,
		Supply:          supply,
		PublicKey:       publicKey,
		NetworkParams:   networkParams,
	}, nil
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

	obseredTxsJson, err := tinyjson.Marshal(cs.ObservedTxs)
	if err != nil {
		return err
	}
	sdk.StateSetObject(obserbedKey, string(obseredTxsJson))

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
