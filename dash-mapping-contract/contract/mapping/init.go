package mapping

import (
	"dash-mapping-contract/contract/constants"
	ce "dash-mapping-contract/contract/contracterrors"
	"dash-mapping-contract/sdk"
	"crypto/sha256"
	"encoding/binary"
	"net/url"
	"strings"

	"github.com/btcsuite/btcd/chaincfg"
)

// Dash-specific network params for address validation. Dash uses different
// address version bytes than Bitcoin. Bech32HRPSegwit is set for internal
// P2WSH tracking only (Dash has no native segwit).
func dashTestNetParams() *chaincfg.Params {
	p := chaincfg.TestNet3Params
	p.PubKeyHashAddrID = 0x8c // 'y' prefix
	p.ScriptHashAddrID = 0x13 // '8'/'9' prefix
	p.Bech32HRPSegwit = "tdash"
	return &p
}

func dashMainNetParams() *chaincfg.Params {
	p := chaincfg.MainNetParams
	p.PubKeyHashAddrID = 0x4c // 'X' prefix
	p.ScriptHashAddrID = 0x10 // '7' prefix
	p.Bech32HRPSegwit = "dash"
	return &p
}

func IntializeContractState(publicKeys PublicKeys, networkMode string) (*ContractState, error) {
	var networkParams *chaincfg.Params
	switch networkMode {
	case constants.Testnet:
		networkParams = dashTestNetParams()
	case constants.Regtest:
		networkParams = &chaincfg.RegressionNetParams
	default:
		networkParams = dashMainNetParams()
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

	// Load UTXO pool counters (4 bytes: two uint16 BE [confirmedNext, unconfirmedNext])
	confirmedNextId := uint16(constants.UtxoConfirmedPoolStart)
	unconfirmedNextId := uint16(0)
	counterState := sdk.StateGetObject(constants.UtxoLastIdKey)
	if len(*counterState) == 4 {
		counterBytes := []byte(*counterState)
		confirmedNextId = binary.BigEndian.Uint16(counterBytes[0:])
		unconfirmedNextId = binary.BigEndian.Uint16(counterBytes[2:])
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
	}, nil
}

func InitializeMappingState(
	publicKeys PublicKeys,
	networkMode string,
	instructions ...string,
) (*MappingState, error) {
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
	publicKeys PublicKeys,
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
			if sdk.VerifyAddress(recipient) == string(sdk.AddressDomainUnknown) {
				return nil, ce.NewContractError(
					ce.ErrInput,
					"address \""+recipient+"\" invalid on magi",
					"bad instruction \""+instr+"\"",
				)
			}
			mappingType = MapDeposit
		} else if params.Has(constants.SwapToKey) {
			recipient = params.Get(constants.SwapToKey)
			recipientNetwork := params.Get(constants.SwapNetworkOut)
			if recipientNetwork == "dash" {
				return nil, ce.NewContractError(ce.ErrInput, "output network cannot be dash")
			}
			mappingType = MapSwap
			if !strings.HasPrefix(sdk.VerifyAddress(recipient), "user:") {
				return nil, ce.NewContractError(
					ce.ErrInput,
					"address \""+recipient+"\" is not a user address",
					"bad instruction \""+instr+"\"",
				)
			}
		}
		if recipient != "" {
			hasher := sha256.New()
			hasher.Write([]byte(instr))
			hashBytes := hasher.Sum(nil)
			address, _, err := createP2WSHAddressWithBackup(
				publicKeys.Primary,
				publicKeys.Backup,
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

	// UTXO pool counters (4 bytes: two uint16 BE [confirmedNext, unconfirmedNext])
	var counterBuf [4]byte
	binary.BigEndian.PutUint16(counterBuf[0:], cs.ConfirmedNextId)
	binary.BigEndian.PutUint16(counterBuf[2:], cs.UnconfirmedNextId)
	sdk.StateSetObject(constants.UtxoLastIdKey, string(counterBuf[:]))

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
