package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"encoding/binary"
)

// vault_lifecycle.go — S1.3 generation lifecycle state machine.
//
// A vault generation moves Pending -> Active -> Retiring (S1 owns these three;
// S2/S5 own Retiring -> Draining -> Inactive -> Purged). The key ceremony drives
// the first three transitions:
//
//   createKey            -> MintNextGeneration      (append a Pending successor)
//   registerPublicKey    -> RegisterVaultKeys       (fill its keys; genesis activates)
//   activateKey          -> ActivatePendingGeneration (cut over; predecessor retires)
//   discardPendingKey    -> DiscardPendingGeneration (drop a stalled keygen)
//
// NEVER-BRICK INVARIANTS enforced here:
//   - The active vault ALWAYS keeps its keys and funds until it is fund-gated out
//     in S5. Rotation moves it to RETIRING (still fully spendable), never purges it.
//   - Every guard failure aborts the whole tx (no partial state), so the live vault
//     keeps signing through any failed ceremony.
//   - Generation numbers are monotonic; a discarded/stalled generation number is
//     never reused, so a partially-completed keygen can never collide with a later
//     one.

// LoadVaultState reads ONLY the S1 dual-generation state — the append-only vault
// list plus the next/active generation counters — decoupled from the heavy
// IntializeContractState. The key ceremony uses this so a key op never reads or
// re-marshals UTXOs / supply / balances (minimal blast radius).
func LoadVaultState() (VaultRegistry, uint32, uint32, error) {
	var vaults VaultRegistry
	vaultState := sdk.StateGetObject(constants.VaultRegistryKey)
	if len(*vaultState) > 0 {
		v, err := UnmarshalVaultRegistry([]byte(*vaultState))
		if err != nil {
			return nil, 0, 0, ce.NewContractError(ce.ErrStateAccess, "error decoding vault registry: "+err.Error())
		}
		vaults = v
	}
	var nextGen, activeGen uint32
	if s := sdk.StateGetObject(constants.VaultNextGenKey); len(*s) == 4 {
		nextGen = binary.BigEndian.Uint32([]byte(*s))
	}
	if s := sdk.StateGetObject(constants.VaultActiveGenKey); len(*s) == 4 {
		activeGen = binary.BigEndian.Uint32([]byte(*s))
	}
	return vaults, nextGen, activeGen, nil
}

// SaveVaultState persists ONLY the vault list + generation counters. Mirrors the
// migrate fold's direct writes, keeping the key ceremony's write blast-radius to
// exactly the three vault keys (never touches UTXO/supply/txspends registries).
func SaveVaultState(vaults VaultRegistry, nextGen, activeGen uint32) {
	sdk.StateSetObject(constants.VaultRegistryKey, string(MarshalVaultRegistry(vaults)))
	var nextGenBuf, activeGenBuf [4]byte
	binary.BigEndian.PutUint32(nextGenBuf[:], nextGen)
	binary.BigEndian.PutUint32(activeGenBuf[:], activeGen)
	sdk.StateSetObject(constants.VaultNextGenKey, string(nextGenBuf[:]))
	sdk.StateSetObject(constants.VaultActiveGenKey, string(activeGenBuf[:]))
}

// firstVaultWithStatus returns the index of the first vault with the given status,
// or -1 if none. Status transitions maintain at most one Pending and exactly one
// Active vault, so "first" is unambiguous in practice; callers that require the
// count assert it separately.
func firstVaultWithStatus(vaults VaultRegistry, status VaultStatus) int {
	for i := range vaults {
		if vaults[i].Status == status {
			return i
		}
	}
	return -1
}

func countVaultsWithStatus(vaults VaultRegistry, status VaultStatus) int {
	n := 0
	for i := range vaults {
		if vaults[i].Status == status {
			n++
		}
	}
	return n
}

// MintNextGeneration appends a new PENDING vault — the successor whose TSS key the
// caller must then request — and returns its generation number + keyId. Genesis
// (empty vault list, e.g. a fresh deploy whose migrate fold found no legacy key)
// mints generation 0; otherwise it mints the next generation counter, bound to the
// current active generation as its predecessor (NN#12 lineage). It NEVER activates
// (a pending vault holds no funds and receives no deposits) and NEVER mutates the
// active generation, so the live vault keeps signing throughout keygen.
//
// Guards (never-brick):
//   - at most ONE keygen in flight: refuse if any PENDING vault already exists
//     (clear a stalled one with DiscardPendingGeneration, then re-mint);
//   - rotation requires EXACTLY ONE active vault to descend from.
func MintNextGeneration(height uint32) (uint32, string, error) {
	vaults, nextGen, activeGen, err := LoadVaultState()
	if err != nil {
		return 0, "", err
	}

	if firstVaultWithStatus(vaults, VaultStatusPending) >= 0 {
		return 0, "", ce.NewContractError(ce.ErrTransaction,
			"a key generation is already in flight (a pending vault exists); discard or activate it before minting another")
	}

	var gen, predecessor uint32
	if len(vaults) == 0 {
		// GENESIS: no vault exists. Mint gen-0 with no ancestor.
		gen = 0
		predecessor = 0
	} else {
		// ROTATION: exactly one active vault must exist to bind lineage to.
		if countVaultsWithStatus(vaults, VaultStatusActive) != 1 {
			return 0, "", ce.NewContractError(ce.ErrTransaction,
				"cannot mint a successor: expected exactly one active vault to rotate from")
		}
		gen = nextGen
		predecessor = activeGen
	}

	vaults = append(vaults, Vault{
		Generation:    gen,
		Status:        VaultStatusPending,
		Predecessor:   predecessor,
		CreatedHeight: height,
	})
	// Monotonic: never let nextGen regress. (Genesis mints gen-0 while nextGen is
	// already 0 -> becomes 1; a rotation mints nextGen -> becomes nextGen+1.)
	if gen >= nextGen {
		nextGen = gen + 1
	}
	// activeGen is deliberately unchanged — the live vault keeps receiving deposits.
	SaveVaultState(vaults, nextGen, activeGen)
	return gen, VaultKeyId(gen), nil
}

// RegisterVaultKeys routes freshly-registered TSS pubkeys into the pending vault
// (whichever key(s) are provided; nil = not provided, to support split
// primary/backup registration). For the GENESIS generation (gen-0, no predecessor,
// no other active vault) it activates immediately once BOTH keys are set — there is
// no predecessor to retire and no funds to sweep. Returns the target generation and
// whether a pending vault was found; if none is found (an existing gen-0 already
// active from the fold, or every generation already activated) it is a no-op and
// the caller keeps only the legacy flat-key path.
func RegisterVaultKeys(primary, backup *CompressedPubKey, height uint32) (uint32, bool, error) {
	vaults, nextGen, activeGen, err := LoadVaultState()
	if err != nil {
		return 0, false, err
	}
	pendingIdx := firstVaultWithStatus(vaults, VaultStatusPending)
	if pendingIdx < 0 {
		return 0, false, nil
	}
	if primary != nil {
		vaults[pendingIdx].Primary = *primary
	}
	if backup != nil {
		vaults[pendingIdx].Backup = *backup
	}
	targetGen := vaults[pendingIdx].Generation

	// Genesis auto-activate: gen-0, both keys now real, and no other active vault.
	if targetGen == 0 &&
		!isZeroKey(vaults[pendingIdx].Primary) && !isZeroKey(vaults[pendingIdx].Backup) &&
		countVaultsWithStatus(vaults, VaultStatusActive) == 0 {
		vaults[pendingIdx].Status = VaultStatusActive
		vaults[pendingIdx].ActivatedHeight = height
		activeGen = 0
	}
	SaveVaultState(vaults, nextGen, activeGen)
	return targetGen, true, nil
}

// ActivatePendingGeneration promotes the (keygen-complete) pending vault to ACTIVE
// and retires the current active vault. The retired vault goes to RETIRING — it
// KEEPS its keys and its funds and can still be swept; it is NEVER purged here
// (purge is fund-gated in S5). This is the safe cutover: new deposits flow to the
// new generation while the old one drains.
//
// Guards (never-brick):
//   - a pending vault must exist and have BOTH real pubkeys (keygen complete);
//   - the active-vault counter must agree with the Active-status vault (no
//     corrupted-counter cutover);
//   - LINEAGE (NN#12): the pending vault's predecessor MUST equal the current
//     active generation — a rogue pending vault that does not descend from the true
//     active gen cannot be activated;
//   - post-condition: EXACTLY ONE active vault afterward, and it is the new gen.
//
// Any guard failure returns an error; the main.go wrapper aborts the tx, so no
// state changes and the live vault keeps working. Returns (activatedGen,
// retiredGen, hadPredecessor).
func ActivatePendingGeneration(height uint32) (uint32, uint32, bool, error) {
	vaults, nextGen, activeGen, err := LoadVaultState()
	if err != nil {
		return 0, 0, false, err
	}
	pendingIdx := firstVaultWithStatus(vaults, VaultStatusPending)
	if pendingIdx < 0 {
		return 0, 0, false, ce.NewContractError(ce.ErrTransaction, "no pending vault to activate")
	}
	if isZeroKey(vaults[pendingIdx].Primary) || isZeroKey(vaults[pendingIdx].Backup) {
		return 0, 0, false, ce.NewContractError(ce.ErrTransaction,
			"pending vault has no registered keys yet (keygen incomplete) — cannot activate")
	}
	newGen := vaults[pendingIdx].Generation

	oldActiveIdx := firstVaultWithStatus(vaults, VaultStatusActive)
	hadPredecessor := oldActiveIdx >= 0
	var retiredGen uint32

	if newGen != 0 {
		// Rotation: the live active vault must exist, its generation must agree with
		// the active-gen counter, and the successor's lineage must bind to it.
		if !hadPredecessor {
			return 0, 0, false, ce.NewContractError(ce.ErrTransaction,
				"cannot activate a successor: no active vault to retire")
		}
		if vaults[oldActiveIdx].Generation != activeGen {
			return 0, 0, false, ce.NewContractError(ce.ErrTransaction,
				"state inconsistency: active vault generation does not match the active-gen counter")
		}
		if vaults[pendingIdx].Predecessor != activeGen {
			return 0, 0, false, ce.NewContractError(ce.ErrTransaction,
				"pending vault predecessor does not match the active generation (broken lineage)")
		}
	}

	if hadPredecessor {
		vaults[oldActiveIdx].Status = VaultStatusRetiring
		vaults[oldActiveIdx].RetiredHeight = height
		retiredGen = vaults[oldActiveIdx].Generation
	}

	vaults[pendingIdx].Status = VaultStatusActive
	vaults[pendingIdx].ActivatedHeight = height
	activeGen = newGen

	// Post-condition invariant: exactly one active vault, and it is the new gen.
	if countVaultsWithStatus(vaults, VaultStatusActive) != 1 {
		return 0, 0, false, ce.NewContractError(ce.ErrTransaction,
			"invariant violation: expected exactly one active vault after activation")
	}

	SaveVaultState(vaults, nextGen, activeGen)
	return newGen, retiredGen, hadPredecessor, nil
}

// DiscardPendingGeneration removes the single pending vault — the escape hatch for
// a keygen that stalled or failed. A pending vault has never been active and holds
// no funds, so discarding it is always safe; it lets the owner re-mint. It refuses
// to touch anything but a PENDING vault (never an active/retiring one that may hold
// funds). NextGen is deliberately NOT rolled back: generation numbers are monotonic
// and never reused, so a re-mint gets a fresh number that cannot collide with the
// keyId of a keygen that may have partially completed on some nodes. Returns the
// discarded generation number.
func DiscardPendingGeneration() (uint32, error) {
	vaults, nextGen, activeGen, err := LoadVaultState()
	if err != nil {
		return 0, err
	}
	pendingIdx := firstVaultWithStatus(vaults, VaultStatusPending)
	if pendingIdx < 0 {
		return 0, ce.NewContractError(ce.ErrTransaction, "no pending vault to discard")
	}
	discarded := vaults[pendingIdx].Generation
	vaults = append(vaults[:pendingIdx], vaults[pendingIdx+1:]...)
	SaveVaultState(vaults, nextGen, activeGen)
	return discarded, nil
}
