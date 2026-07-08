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
		// S1.4: parseInstructions derives a deposit address for EVERY fund-holding
		// generation (active + retiring + draining) from the resolved vault list,
		// each tagged with its own generation, so a late deposit to a superseded
		// generation's address still credits (NR-4). Pre-fold/fresh deploys fall
		// back to the single resolved active/legacy key pair (byte-identical).
		registry, err = contractState.parseInstructions(instructions, contractState.NetworkParams)
		if err != nil {
			return nil, ce.WrapContractError(ce.ErrStateAccess, err, "error unmarshalling address registry")
		}
	}

	return &MappingState{
		ContractState:   *contractState,
		AddressRegistry: registry,
	}, err
}

// depositVaultKeys is one generation's deposit-address key material (S1.4).
type depositVaultKeys struct {
	generation uint32
	primary    CompressedPubKey
	backup     CompressedPubKey
}

// depositAddressGenerations returns the key material of every generation whose
// deposit address must be matched (S1.4 dual-generation crediting): all
// fund-holding generations (active + retiring + draining, isFundHoldingStatus)
// that carry a real primary key — with the ACTIVE generation FIRST, so it wins
// any address collision (collisions are precluded by the R6 pubkey-uniqueness
// rule, but ordering makes the tie-break deterministic regardless).
//
// New deposits are directed to the active gen's address (the address the
// router/UI hands out), but every superseded gen's address stays matchable
// until that gen is PURGED (S5) — that is what lets a late deposit to a
// retiring vault credit instead of being lost (NR-4 / C-2).
//
// FAIL-SAFE: on an empty vault list (pre-fold) or one with no fund-holding,
// keyed generation (a fresh deploy whose genesis gen is still PENDING with zero
// keys), it returns the single resolved active/legacy key pair tagged
// cs.ActiveGen — byte-identical to the pre-S1.4 single-address behaviour, so an
// unfolded or freshly deployed contract derives exactly the addresses it did
// before. Deterministic: iterates the vault slice in index order (no map range).
func (cs *ContractState) depositAddressGenerations() []depositVaultKeys {
	out := make([]depositVaultKeys, 0, len(cs.Vaults)+1)
	// Active generation first (collision precedence).
	for i := range cs.Vaults {
		v := &cs.Vaults[i]
		if v.Generation == cs.ActiveGen && isFundHoldingStatus(v.Status) && !isZeroKey(v.Primary) {
			out = append(out, depositVaultKeys{v.Generation, v.Primary, v.Backup})
			break
		}
	}
	// Then every OTHER fund-holding generation (retiring / draining / a non-active
	// gen that still holds funds), in vault-list order.
	for i := range cs.Vaults {
		v := &cs.Vaults[i]
		if v.Generation != cs.ActiveGen && isFundHoldingStatus(v.Status) && !isZeroKey(v.Primary) {
			out = append(out, depositVaultKeys{v.Generation, v.Primary, v.Backup})
		}
	}
	if len(out) == 0 {
		// Pre-fold / fresh-deploy fallback: the single resolved key pair (cs.PublicKeys
		// was resolved to the active vault or the legacy slots in IntializeContractState).
		out = append(out, depositVaultKeys{cs.ActiveGen, cs.PublicKeys.Primary, cs.PublicKeys.Backup})
	}
	return out
}

func (cs *ContractState) parseInstructions(
	instrs []string,
	networkParams *chaincfg.Params,
) (map[string]*AddressMetadata, error) {
	// S1.4: derive a deposit address for EVERY fund-holding generation, each tagged
	// with its own generation, so a late deposit to a superseded (retiring/draining)
	// generation's address still credits and is tagged with THAT generation (NR-4 /
	// C-2). When only gen-0 exists this yields exactly one address == the pre-S1.4
	// behaviour (inert-by-construction).
	genKeys := cs.depositAddressGenerations()
	registry := make(map[string]*AddressMetadata, len(instrs)*len(genKeys))
	for _, instr := range instrs {
		params, err := url.ParseQuery(instr)
		if err != nil {
			return nil, err
		}

		// Validate the destination once per instruction (generation-independent);
		// assumes VSC as the network for deposits and unspecified swaps.
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
		if recipient == "" {
			// should error for unsupported instruction?
			continue
		}

		hasher := sha256.New()
		hasher.Write([]byte(instr))
		hashBytes := hasher.Sum(nil)
		// One *url.Values per instruction, shared (read-only) by that instruction's
		// per-generation entries. params is freshly declared each iteration, so &params
		// is a distinct pointer per instruction (no loop-var aliasing across instrs).
		for gi := range genKeys {
			gk := &genKeys[gi]
			address, _, err := createP2WSHAddressWithBackup(
				gk.primary,
				gk.backup,
				hashBytes,
				networkParams,
			)
			if err != nil {
				return nil, err
			}
			// Active-first ordering already claimed this address on the (R6-precluded)
			// chance two generations derive the same one — keep the active gen's entry.
			if _, exists := registry[address]; exists {
				continue
			}
			registry[address] = &AddressMetadata{
				Instruction: instr,
				Recipient:   recipient,
				Params:      &params,
				Tag:         hashBytes,
				Type:        mappingType,
				// S1.3 C-1 / S1.4 NR-4: tag with the generation whose keys derived THIS
				// address, so the spend path resolves the correct per-generation witness
				// keys + TSS keyId after a rotation.
				Generation: gk.generation,
			}
		}
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
