package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"crypto/sha256"
	"encoding/binary"
	"net/url"
	"strings"

	"github.com/btcsuite/btcd/chaincfg"
)

func IntializeContractState(publicKeys PublicKeys, networkMode string) (*ContractState, error) {
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

	// Load vault registry (S1 dual-generation vault list — VaultEntrySize bytes/entry).
	// Empty on any contract not yet folded (S1.1); tolerant of absent keys.
	var vaults VaultRegistry
	vaultState := sdk.StateGetObject(constants.VaultRegistryKey)
	if len(*vaultState) > 0 {
		var err error
		vaults, err = UnmarshalVaultRegistry([]byte(*vaultState))
		if err != nil {
			return nil, ce.NewContractError(ce.ErrStateAccess, "error decoding vault registry: "+err.Error())
		}
	}
	// Load vault generation counters (4 bytes BE each; absent → 0).
	var nextGen, activeGen uint32
	if s := sdk.StateGetObject(constants.VaultNextGenKey); len(*s) == 4 {
		nextGen = binary.BigEndian.Uint32([]byte(*s))
	}
	if s := sdk.StateGetObject(constants.VaultActiveGenKey); len(*s) == 4 {
		activeGen = binary.BigEndian.Uint32([]byte(*s))
	}

	cs := &ContractState{
		UtxoList:          utxos,
		ConfirmedNextId:   confirmedNextId,
		UnconfirmedNextId: unconfirmedNextId,
		TxSpendsList:      txSpends,
		Supply:            supply,
		PublicKeys:        publicKeys,
		NetworkParams:     networkParams,
		Vaults:            vaults,
		NextGen:           nextGen,
		ActiveGen:         activeGen,
	}
	// S1.2: the ACTIVE generation's keys are the source of truth for deposit/change
	// address derivation. Resolve cs.PublicKeys from the vault list. FAIL-SAFE: if the
	// vault list is empty (pre-fold / fresh deploy) keep the legacy single-slot keys
	// (the passed publicKeys). While only gen-0 exists, the active vault's keys ==
	// the legacy keys (the fold copied them), so this is byte-identical to today.
	//
	// S1.3: match by Generation AND Status==Active. The counter alone is not enough
	// once the lifecycle can create a PENDING gen-0 (a fresh-deploy genesis mint sits
	// at Generation 0 == the default ActiveGen 0 with ZERO keys until it activates) —
	// matching it would resolve to a zero key. Requiring Active leaves cs.PublicKeys
	// on the legacy fallback until a real activation lands. Byte-identical for every
	// existing deploy: the post-fold gen-0 is already Active.
	for i := range cs.Vaults {
		if cs.Vaults[i].Generation == cs.ActiveGen && cs.Vaults[i].Status == VaultStatusActive {
			cs.PublicKeys = PublicKeys{Primary: cs.Vaults[i].Primary, Backup: cs.Vaults[i].Backup}
			break
		}
	}
	return cs, nil
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
		// S1.2: derive deposit addresses from the resolved ACTIVE-generation keys
		// (contractState.PublicKeys), not the raw passed-in legacy pair. (S1.4 will
		// extend this to match ALL non-purged generations' addresses for NR-4.)
		registry, err = contractState.parseInstructions(contractState.PublicKeys, instructions, contractState.NetworkParams)
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
			destinationChain := params.Get(constants.DestinationChainKey)
			if strings.ToLower(destinationChain) == "btc" {
				return nil, ce.NewContractError(ce.ErrInput, "output network cannot be btc")
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

	// Vault registry + generation counters (S1 dual-generation vault list, binary).
	sdk.StateSetObject(constants.VaultRegistryKey, string(MarshalVaultRegistry(cs.Vaults)))
	var nextGenBuf, activeGenBuf [4]byte
	binary.BigEndian.PutUint32(nextGenBuf[:], cs.NextGen)
	binary.BigEndian.PutUint32(activeGenBuf[:], cs.ActiveGen)
	sdk.StateSetObject(constants.VaultNextGenKey, string(nextGenBuf[:]))
	sdk.StateSetObject(constants.VaultActiveGenKey, string(activeGenBuf[:]))

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
