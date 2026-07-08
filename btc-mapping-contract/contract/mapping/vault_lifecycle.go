package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"encoding/binary"
	"encoding/hex"
	"strings"
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
// NEVER-BRICK INVARIANTS:
//   - The active/retiring vault ALWAYS keeps its keys and funds until fund-gated
//     out in S5. Rotation moves active->Retiring (still fully spendable), never
//     purges it.
//   - Every guard failure aborts the whole tx (no partial state), so the live
//     vault keeps signing through any failed ceremony.
//   - Generation numbers are monotonic and NEVER reused — including a discarded
//     genesis (a re-mint gets a fresh number, so a partially-completed keygen can
//     never collide with a later one).
//
// GENESIS is marked by a self-referential predecessor (Predecessor == Generation):
// the bootstrap key has no ancestor. Genesis vaults auto-activate (no predecessor
// to retire) and skip the rotation lineage check. Rotation successors have
// Predecessor = the (lower) active generation they descend from.
//
// KEY AUTHENTICITY (D-1): before any vault activates, its primary key is attested
// against the TSS ceremony output via TssGetKey (consensus-deterministic — the
// keystore is written on the state-processing path). A compromised owner cannot
// activate a self-generated key, because it won't match the ceremony. Registered
// keys are set-once immutable. The BACKUP key is the operator's CSV-recovery key
// (not a TSS key) — immutable-once-set; a compromised owner+backup could still
// spend via the backup path AFTER the CSV timelock (by design: the timelock is the
// response window).

// TssGetKey status strings (mirror tss_db.TssKeyActive / TssKeyDeprecated in
// go-vsc-node). "active" = current key; "deprecated" = expired but still renewable
// (renewal reactivates it).
const (
	tssKeyActiveStatus     = "active"
	tssKeyDeprecatedStatus = "deprecated"
)

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
// fold's direct writes, keeping the key ceremony's write blast-radius to exactly
// the three vault keys (never touches UTXO/supply/txspends registries).
func SaveVaultState(vaults VaultRegistry, nextGen, activeGen uint32) {
	sdk.StateSetObject(constants.VaultRegistryKey, string(MarshalVaultRegistry(vaults)))
	var nextGenBuf, activeGenBuf [4]byte
	binary.BigEndian.PutUint32(nextGenBuf[:], nextGen)
	binary.BigEndian.PutUint32(activeGenBuf[:], activeGen)
	sdk.StateSetObject(constants.VaultNextGenKey, string(nextGenBuf[:]))
	sdk.StateSetObject(constants.VaultActiveGenKey, string(activeGenBuf[:]))
}

// FoldLegacyGen0IfNeeded folds the legacy single-slot key (pubkey/backupkey) into
// generation 0 of the vault list, IF the list is empty and a genuine 33-byte legacy
// key pair exists. Idempotent + fail-safe: never overwrites a populated list, never
// folds an absent/short key (that would brick address derivation). Returns true if
// it folded.
//
// Shared by migrate()'s v2 step AND every key-ceremony write op. This is the B-1
// fix: an UPGRADED funded deploy has legacy flat keys but no vault list until
// migrate runs — without the fold-first guard, a createKey before migrate would
// treat len(vaults)==0 as "genesis" and mint a DIVERGENT gen-0, stranding every
// legacy UTXO (they'd resolve to the zero-key pending gen-0). Folding first makes
// that impossible: genesis only ever fires on a truly fresh deploy (no legacy key).
func FoldLegacyGen0IfNeeded() bool {
	if existing := sdk.StateGetObject(constants.VaultRegistryKey); len(*existing) > 0 {
		return false // already populated — never clobber a real vault list
	}
	primaryRaw := sdk.StateGetObject(constants.PrimaryPublicKeyStateKey)
	backupRaw := sdk.StateGetObject(constants.BackupPublicKeyStateKey)
	if primaryRaw == nil || backupRaw == nil || len(*primaryRaw) != 33 || len(*backupRaw) != 33 {
		return false // no genuinely registered legacy key pair to fold
	}
	var gen0 Vault
	gen0.Generation = 0
	copy(gen0.Primary[:], *primaryRaw)
	copy(gen0.Backup[:], *backupRaw)
	gen0.Status = VaultStatusActive
	gen0.Predecessor = 0 // self (== Generation) — genesis marker
	// Heights left 0: gen-0 predates per-generation height tracking.
	SaveVaultState(VaultRegistry{gen0}, 1, 0) // nextGen=1, activeGen=0
	sdk.Log("fold|gen0")
	return true
}

// isGenesisVault reports whether a vault is a bootstrap (genesis) vault — one with
// no ancestor, marked by a self-referential predecessor. Rotation successors have
// Predecessor < Generation (the active gen they descend from), so this cleanly
// separates the two without special-casing generation 0.
func isGenesisVault(v *Vault) bool {
	return v.Predecessor == v.Generation
}

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

// attestPrimaryKey verifies that `primary` is the actual TSS ceremony output for the
// generation's keyId. The contract trusts the TSS network's attestation, not the
// owner's submission: TssGetKey reads consensus-committed key state (deterministic —
// the keystore is written on the state-processing path), returning
// "status,pubkeyHex,algo". Requires status "active" and an exact 33-byte match. This
// is the anti-governance-attack guard (D-1): a compromised owner cannot activate a
// self-generated key, because it will not match the ceremony output.
func attestPrimaryKey(gen uint32, primary CompressedPubKey) error {
	raw := sdk.TssGetKey(VaultKeyId(gen))
	parts := strings.Split(raw, ",")
	if len(parts) < 2 || parts[0] != tssKeyActiveStatus {
		return ce.NewContractError(ce.ErrTransaction,
			"cannot activate generation: its TSS key is not active (keygen incomplete or missing) — attestation failed")
	}
	attested, derr := hex.DecodeString(parts[1])
	if derr != nil || len(attested) != 33 {
		return ce.NewContractError(ce.ErrTransaction, "cannot attest generation key: malformed TSS pubkey")
	}
	for i := 0; i < 33; i++ {
		if attested[i] != primary[i] {
			return ce.NewContractError(ce.ErrTransaction,
				"generation primary key does not match the TSS ceremony output (attestation failed)")
		}
	}
	return nil
}

// MintNextGeneration appends a new PENDING vault — the successor whose TSS key the
// caller must then request — and returns its generation + keyId. It folds any
// unmigrated legacy gen-0 FIRST (so a pre-migrate createKey can't diverge). Genesis
// (empty vault list on a truly fresh deploy) mints a self-referential vault at the
// next monotonic generation number; a rotation mints the next generation bound to
// the current active gen as predecessor (NN#12 lineage). It NEVER activates and
// NEVER mutates the active generation, so the live vault keeps signing.
//
// Guards (never-brick): at most ONE keygen in flight (refuse if a PENDING vault
// exists — discard a stalled one first); rotation requires EXACTLY ONE active vault.
func MintNextGeneration(height uint32) (uint32, string, error) {
	FoldLegacyGen0IfNeeded()
	vaults, nextGen, activeGen, err := LoadVaultState()
	if err != nil {
		return 0, "", err
	}

	if firstVaultWithStatus(vaults, VaultStatusPending) >= 0 {
		return 0, "", ce.NewContractError(ce.ErrTransaction,
			"a key generation is already in flight (a pending vault exists); discard or activate it before minting another")
	}

	gen := nextGen // monotonic: never reused, even across a discarded genesis
	var predecessor uint32
	if len(vaults) == 0 {
		// GENESIS: no ancestor. Self-referential predecessor marks it.
		predecessor = gen
	} else {
		// ROTATION: exactly one active vault to bind lineage to.
		if countVaultsWithStatus(vaults, VaultStatusActive) != 1 {
			return 0, "", ce.NewContractError(ce.ErrTransaction,
				"cannot mint a successor: expected exactly one active vault to rotate from")
		}
		predecessor = activeGen
	}

	vaults = append(vaults, Vault{
		Generation:    gen,
		Status:        VaultStatusPending,
		Predecessor:   predecessor,
		CreatedHeight: height,
	})
	nextGen = gen + 1 // gen == the old nextGen, so this is strictly monotonic
	// activeGen is deliberately unchanged — the live vault keeps receiving deposits.
	SaveVaultState(vaults, nextGen, activeGen)
	return gen, VaultKeyId(gen), nil
}

// RegisterVaultKeys routes freshly-registered TSS pubkeys into the pending vault
// (whichever key(s) are provided; nil = not provided). Keys are SET-ONCE immutable:
// a second registration with a DIFFERENT key is rejected (re-submitting the same key
// is idempotent). For a GENESIS vault (self-predecessor) it activates immediately
// once both keys are set, no other active vault exists, and the primary attests to
// the TSS ceremony output — there is no predecessor to retire and no funds to sweep.
// Returns (targetGen, hasPending, isGenesis). No pending vault -> no-op; the caller
// keeps the legacy flat-key path.
func RegisterVaultKeys(primary, backup *CompressedPubKey, height uint32) (uint32, bool, bool, error) {
	FoldLegacyGen0IfNeeded()
	vaults, nextGen, activeGen, err := LoadVaultState()
	if err != nil {
		return 0, false, false, err
	}
	pendingIdx := firstVaultWithStatus(vaults, VaultStatusPending)
	if pendingIdx < 0 {
		return 0, false, false, nil
	}
	v := &vaults[pendingIdx]

	// Set-once immutability (D-1 / E overwrite): never silently replace a key.
	if primary != nil {
		if !isZeroKey(v.Primary) && v.Primary != *primary {
			return 0, false, false, ce.NewContractError(ce.ErrTransaction,
				"primary key already registered for this generation (immutable)")
		}
		v.Primary = *primary
	}
	if backup != nil {
		if !isZeroKey(v.Backup) && v.Backup != *backup {
			return 0, false, false, ce.NewContractError(ce.ErrTransaction,
				"backup key already registered for this generation (immutable)")
		}
		v.Backup = *backup
	}
	targetGen := v.Generation
	isGenesis := isGenesisVault(v)

	// Genesis auto-activate: self-predecessor, both keys real, no other active vault,
	// and the primary attests to the TSS ceremony.
	if isGenesis && !isZeroKey(v.Primary) && !isZeroKey(v.Backup) &&
		countVaultsWithStatus(vaults, VaultStatusActive) == 0 {
		if aerr := attestPrimaryKey(v.Generation, v.Primary); aerr != nil {
			return 0, false, false, aerr
		}
		v.Status = VaultStatusActive
		v.ActivatedHeight = height
		activeGen = v.Generation
	}
	SaveVaultState(vaults, nextGen, activeGen)
	return targetGen, true, isGenesis, nil
}

// ActivatePendingGeneration promotes the (keygen-complete, TSS-attested) pending
// vault to ACTIVE and retires the current active vault. The retired vault goes to
// RETIRING — it KEEPS its keys and its funds and can still be swept; it is NEVER
// purged here (purge is fund-gated in S5).
//
// Guards (never-brick): a pending vault must exist with BOTH real pubkeys; its
// primary must attest to the TSS ceremony (D-1); for a rotation the active-vault
// generation must agree with the counter and the successor's predecessor must equal
// the active gen (lineage); post-condition exactly ONE active vault. Any failure
// aborts the tx -> the live vault keeps working. Returns (activatedGen, retiredGen,
// hadPredecessor).
func ActivatePendingGeneration(height uint32) (uint32, uint32, bool, error) {
	FoldLegacyGen0IfNeeded()
	vaults, nextGen, activeGen, err := LoadVaultState()
	if err != nil {
		return 0, 0, false, err
	}
	pendingIdx := firstVaultWithStatus(vaults, VaultStatusPending)
	if pendingIdx < 0 {
		return 0, 0, false, ce.NewContractError(ce.ErrTransaction, "no pending vault to activate")
	}
	v := &vaults[pendingIdx]
	if isZeroKey(v.Primary) || isZeroKey(v.Backup) {
		return 0, 0, false, ce.NewContractError(ce.ErrTransaction,
			"pending vault has no registered keys yet (keygen incomplete) — cannot activate")
	}
	// Attest the primary against the TSS ceremony output (anti key-substitution).
	if aerr := attestPrimaryKey(v.Generation, v.Primary); aerr != nil {
		return 0, 0, false, aerr
	}
	newGen := v.Generation

	oldActiveIdx := firstVaultWithStatus(vaults, VaultStatusActive)
	hadPredecessor := oldActiveIdx >= 0
	var retiredGen uint32

	if isGenesisVault(v) {
		// Genesis: no ancestor to retire — there must be no active vault yet.
		if hadPredecessor {
			return 0, 0, false, ce.NewContractError(ce.ErrTransaction,
				"genesis vault cannot activate while an active vault already exists")
		}
	} else {
		// Rotation: the live active vault must exist, agree with the counter, and be
		// the successor's bound predecessor.
		if !hadPredecessor {
			return 0, 0, false, ce.NewContractError(ce.ErrTransaction,
				"cannot activate a successor: no active vault to retire")
		}
		if vaults[oldActiveIdx].Generation != activeGen {
			return 0, 0, false, ce.NewContractError(ce.ErrTransaction,
				"state inconsistency: active vault generation does not match the active-gen counter")
		}
		if v.Predecessor != activeGen {
			return 0, 0, false, ce.NewContractError(ce.ErrTransaction,
				"pending vault predecessor does not match the active generation (broken lineage)")
		}
	}

	if hadPredecessor {
		vaults[oldActiveIdx].Status = VaultStatusRetiring
		vaults[oldActiveIdx].RetiredHeight = height
		retiredGen = vaults[oldActiveIdx].Generation
	}

	v.Status = VaultStatusActive
	v.ActivatedHeight = height
	activeGen = newGen

	if countVaultsWithStatus(vaults, VaultStatusActive) != 1 {
		return 0, 0, false, ce.NewContractError(ce.ErrTransaction,
			"invariant violation: expected exactly one active vault after activation")
	}

	SaveVaultState(vaults, nextGen, activeGen)
	return newGen, retiredGen, hadPredecessor, nil
}

// DiscardPendingGeneration removes the single pending vault — the escape hatch for a
// keygen that stalled or failed. A pending vault has never been active and holds no
// funds, so discarding it is always safe; it lets the owner re-mint. It refuses to
// touch anything but a PENDING vault. NextGen is deliberately NOT rolled back:
// generation numbers are monotonic and never reused, so a re-mint gets a fresh
// number/keyId that cannot collide with a keygen that may have partially completed.
// Returns the discarded generation number.
func DiscardPendingGeneration() (uint32, error) {
	FoldLegacyGen0IfNeeded()
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

// tssKeyIsRenewable reports whether the TSS key for keyId can be renewed WITHOUT
// aborting the tx. sdk.TssRenewKey traps on a retired key, a missing key, and an
// "active" key with no expiry; it does NOT trap on "active" (with expiry — every
// contract key has one, createKey epochs=365) nor on "deprecated" — for a deprecated
// (expired) key renewal REACTIVATES it, which is exactly the D-2 recovery. So the
// renewable set is {active, deprecated} (round-3 R3-1: "active"-only wrongly skipped a
// deprecated fund-holding key, defeating the recovery). TssGetKey returns
// "status,pubkey,algo" and never traps on a missing key (returns an empty status).
func tssKeyIsRenewable(keyId string) bool {
	parts := strings.Split(sdk.TssGetKey(keyId), ",")
	if len(parts) < 1 {
		return false
	}
	return parts[0] == tssKeyActiveStatus || parts[0] == tssKeyDeprecatedStatus
}

// RenewableVaultKeyIds returns the keyIds of every fund-holding vault (active +
// retiring + draining) whose TSS key can be renewed WITHOUT trapping — i.e. status
// active or deprecated. The pre-check is the error-isolation (round-2 H/I finding):
// sdk.TssRenewKey aborts the ENTIRE tx on any un-renewable key (missing / retired /
// active-no-expiry), so without filtering, one bad key in ANY generation would block
// renewing the active fund-signing key forever — the never-brick violation D-2 exists
// to prevent. Including "deprecated" restores renewal of an EXPIRED fund-holding key
// (R3-1). It also folds an unmigrated legacy gen-0 first so a pre-fold contract's
// gen-0 is covered.
func RenewableVaultKeyIds() ([]string, error) {
	FoldLegacyGen0IfNeeded()
	vaults, _, _, err := LoadVaultState()
	if err != nil {
		return nil, err
	}
	var ids []string
	for i := range vaults {
		switch vaults[i].Status {
		case VaultStatusActive, VaultStatusRetiring, VaultStatusDraining:
			if keyId := VaultKeyId(vaults[i].Generation); tssKeyIsRenewable(keyId) {
				ids = append(ids, keyId)
			}
		}
	}
	return ids, nil
}
