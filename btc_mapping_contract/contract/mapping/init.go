package mapping

import (
	"contract-template/sdk"
	"crypto/sha256"
	"encoding/hex"
	"net/url"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/chaincfg"
)

func IntializeContractState(publicKey string, instructions ...string) (*ContractState, error) {
	var registry map[string]*AddressMetadata
	if len(instructions) > 0 {
		var err error
		registry, err = parseInstructions(publicKey, instructions)
		if err != nil {
			return nil, err
		}
	}
	var balances AccountBalanceMap
	balanceState := sdk.StateGetObject(BALANCEKEY)
	err := tinyjson.Unmarshal([]byte(*balanceState), &balances)
	if err != nil {
		return nil, err
	}
	var observedTxs ObservedTxList
	obserbedTxsState := sdk.StateGetObject(OBSERVEDKEY)
	err = tinyjson.Unmarshal([]byte(*obserbedTxsState), &observedTxs)
	if err != nil {
		return nil, err
	}
	var utxos UtxoMap
	utxoState := sdk.StateGetObject(UTXOKEY)
	err = tinyjson.Unmarshal([]byte(*utxoState), &utxos)
	if err != nil {
		return nil, err
	}

	return &ContractState{
		AddressRegistry: registry,
		Balances:        balances,
		ObservedTxs:     observedTxs,
		Utxos:           utxos,
		ActiveSupply:    0,
		BaseFeeRate:     1,
		PublicKey:       publicKey,
	}, nil
}

const DEPOSITKEY = "deposit_to"

func parseInstructions(publicKey string, instrs []string) (map[string]*AddressMetadata, error) {
	parsedInstructions := make([]url.Values, len(instrs))
	registry := make(map[string]*AddressMetadata, len(instrs))
	for i, instr := range instrs {
		params, err := url.ParseQuery(instr)
		parsedInstructions[i] = params
		if err != nil {
			return nil, err
		}
		if params.Has(DEPOSITKEY) {
			hasher := sha256.New()
			hasher.Write([]byte(instr))
			hashBytes := hasher.Sum(nil)
			tag := hex.EncodeToString(hashBytes)
			address, _, err := createP2WSHAddress(publicKey, tag, &chaincfg.TestNet3Params)
			if err != nil {
				return nil, err
			}
			registry[address] = &AddressMetadata{
				VscAddress: params.Get(DEPOSITKEY),
				Tag:        instr,
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
	sdk.StateSetObject(BALANCEKEY, string(balancesJson))

	obseredTxsJson, err := tinyjson.Marshal(cs.ObservedTxs)
	if err != nil {
		return err
	}
	sdk.StateSetObject(OBSERVEDKEY, string(obseredTxsJson))

	utxosJson, err := tinyjson.Marshal(cs.Utxos)
	if err != nil {
		return err
	}
	sdk.StateSetObject(UTXOKEY, string(utxosJson))

	return nil
}
