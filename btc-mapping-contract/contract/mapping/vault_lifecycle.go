package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"encoding/binary"
	"encoding/hex"
	"strconv"
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

// VaultKeysCorrectable reports whether the contract provably holds NO value, so
// re-registering the vault key pair cannot strand or redirect anyone's coins.
//
// VR2-21. This replaces the IsTestnet build-flag escape that used to guard the flat
// key writes. A build flag is the wrong question twice over: it let a testnet
// operator re-point the keys of a FUNDED contract, and it refused a mainnet operator
// a correction even when nothing whatsoever was at stake. What actually matters is
// whether any BTC is riding on the current pair, and the contract can answer that
// directly — the same answer on every network.
//
// Deliberately conservative: an unreadable supply blob counts as value at risk. The
// UTXO registry is only tested for EMPTINESS, never unmarshalled, so this stays a
// cheap state read on the key-ceremony path.
func VaultKeysCorrectable() bool {
	if raw := sdk.StateGetObject(constants.UtxoRegistryKey); raw != nil && len(*raw) > 0 {
		return false // the vault is tracking coins
	}
	if raw := sdk.StateGetObject(constants.SupplyKey); raw != nil && len(*raw) > 0 {
		supply, err := UnmarshalSupply([]byte(*raw))
		if err != nil {
			return false // unreadable supply — assume value at risk
		}
		// BaseFeeRate is configuration, not value, so it is deliberately not tested.
		if supply.ActiveSupply != 0 || supply.UserSupply != 0 || supply.FeeSupply != 0 {
			return false
		}
	}
	return true
}

// ActiveGenerationKeys returns the ACTIVE generation's key pair, and whether one
// exists.
//
// The vault list is the source of truth: IntializeContractState resolves the
// contract's public keys from it whenever an Active generation matches ActiveGen,
// and the flat slots are only a legacy fallback for a contract that has no vault
// list yet. So once a generation holds the authoritative pair, the flat slots may
// MIRROR it but must never disagree with it.
func ActiveGenerationKeys() (primary, backup CompressedPubKey, ok bool) {
	vaults, _, activeGen, err := LoadVaultState()
	if err != nil {
		return primary, backup, false
	}
	for i := range vaults {
		v := &vaults[i]
		if v.Generation == activeGen && v.Status == VaultStatusActive && !isZeroKey(v.Primary) {
			return v.Primary, v.Backup, true
		}
	}
	return primary, backup, false
}

// CorrectGenesisVaultKeys re-points a folded generation 0 at a corrected key pair,
// and reports whether it changed anything.
//
// VR2-21. FoldLegacyGen0IfNeeded freezes whatever flat pair exists into vaults[0],
// and it fires on the very call an operator makes to FIX a mistyped key — so without
// this the corrected flat key is dead state, because IntializeContractState resolves
// the contract's keys from the vault list. The backup half has no other escape at
// all: MintNextGeneration pins every successor's backup to the active vault's (F1)
// and RegisterVaultKeys rejects a different one as immutable, so a wrong backup
// folded into gen-0 is inherited by every future generation, permanently.
//
// Narrow by construction: it touches ONLY a lone, Active, genesis generation 0 — the
// exact shape the fold produces — and only while VaultKeysCorrectable() holds. It
// never runs once a rotation has minted a successor, and never once value exists.
func CorrectGenesisVaultKeys(primary, backup *CompressedPubKey) (bool, error) {
	if !VaultKeysCorrectable() {
		return false, nil
	}
	vaults, nextGen, activeGen, err := LoadVaultState()
	if err != nil {
		return false, err
	}
	if len(vaults) != 1 {
		return false, nil // a successor exists — lineage is live, never rewrite it
	}
	v := &vaults[0]
	if v.Generation != 0 || v.Status != VaultStatusActive || !isGenesisVault(v) {
		return false, nil
	}

	// THE GATE THAT KEEPS THIS FROM BEING A KEY-SUBSTITUTION PRIMITIVE.
	//
	// "Holds no value" is a point-in-time fact, not "was never used". A live,
	// never-rotated vault sits at exactly one Active genesis generation and reaches
	// zero UTXOs and zero supply every time the last outstanding withdrawal clears.
	// Without this, that window would let the owner key swap the vault's spending
	// primary for a self-generated one — and the deposit script is a bare
	// OP_IF <primary> OP_CHECKSIG (createP2WSHAddressWithBackup), so Bitcoin has no
	// notion of "this pubkey must belong to a TSS quorum". Every later deposit would
	// be unilaterally spendable by whoever supplied the replacement. Rotation cannot
	// do that — it routes through attestPrimaryKey — and this path must not become
	// the exception.
	//
	// So: a generation whose primary IS the ceremony output is FROZEN, and where a
	// ceremony output exists the only correction permitted is the one that makes the
	// generation AGREE with it. That grants no new power — the key was always going
	// to be the ceremony's. Only a generation with no ceremony key at all (the
	// legacy flat bootstrap, which never ran createKey and is the sole scenario
	// VR2-21 documents) stays freely correctable, and there the owner already chose
	// the key unilaterally.
	attested, hasActiveKey, readable := attestedGenerationPrimary(v.Generation)
	if !readable {
		return false, nil // an active ceremony key we cannot read — fail closed
	}
	if hasActiveKey {
		if v.Primary == attested {
			return false, nil // already agrees with the ceremony: immutable
		}
		if primary == nil || *primary != attested {
			return false, nil // the only permitted correction is "agree with the ceremony"
		}
	}

	changed := false
	if primary != nil && v.Primary != *primary {
		v.Primary = *primary
		changed = true
	}
	if backup != nil && v.Backup != *backup {
		v.Backup = *backup
		changed = true
	}
	if !changed {
		return false, nil
	}
	SaveVaultState(vaults, nextGen, activeGen)
	sdk.Log("gen0-corrected")
	return true, nil
}

// attestedGenerationPrimary reads the TSS ceremony's ACTIVE output for a
// generation.
//
// Returns (key, hasActiveKey, readable). `readable` is false only when there IS an
// active ceremony key whose pubkey cannot be decoded — callers must treat that as
// "do not proceed", so an unreadable keystore refuses a correction rather than
// permitting one. A generation with no active ceremony key at all is reported
// positively as (zero, false, true): that is the legacy flat bootstrap, not an
// error.
//
// This is deliberately narrower than attestPrimaryKey, which additionally requires
// a verified BRK-2 check-signature before ACTIVATING a generation. Nothing is
// being activated here — generation 0 is already Active — and requiring a
// check-signature would block precisely the legacy-bootstrap correction this
// serves, since a folded gen-0 never went through attestation in the first place.
func attestedGenerationPrimary(gen uint32) (key CompressedPubKey, hasActiveKey bool, readable bool) {
	parts := strings.Split(sdk.TssGetKey(VaultKeyId(gen)), ",")
	if len(parts) < 2 || parts[0] != tssKeyActiveStatus {
		return key, false, true // no active ceremony key for this generation
	}
	raw, derr := hex.DecodeString(parts[1])
	if derr != nil || len(raw) != 33 {
		return key, true, false
	}
	copy(key[:], raw)
	return key, true, true
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
	// BRK-2 (check-SIGNATURE-before-activate, brick council FS3-1): agreement on a
	// pubkey (attested above) is NOT proof the fresh committee can SIGN with it.
	// When vault-rotation-v2 is chain-active the node appends a 4th field to
	// TssGetKey — the SignatureVerified flag ("1" iff a consensus-verified
	// check-signature with this key has landed). REQUIRE it: activating an
	// agreed-but-unsignable key would route funds into a vault only the single CSV
	// backup can spend. Gated by field PRESENCE (backward-compatible): when v2 is
	// off the node returns the legacy 3-field string and this is a no-op — which,
	// together with the gen-0 fold activating directly (never through attest),
	// leaves the inert / pre-v2 path unchanged. A genesis activation under an
	// active v2 chain is gated too (it also flows through attest) — acceptable: the
	// genesis key simply check-signs first (fresh deploy, zero funds at risk).
	if !checkSigVerified(parts) {
		return ce.NewContractError(ce.ErrTransaction,
			"cannot activate generation: its TSS key has not produced a verified check-signature yet (BRK-2)")
	}
	return nil
}

// checkSigVerified reports whether a split TssGetKey response
// ("status,pubkey,algo[,flag]") carries a verified BRK-2 check-signature. When
// the node has vault-rotation-v2 chain-active it appends the flag as a 4th field
// ("1" iff a consensus-verified check-signature with this key has landed); when
// off it returns 3 fields and this returns true — no requirement (pre-v2 / inert
// path; the contract deploy + node flag are the real gate). A present-but-not-"1"
// flag fails closed (activation refused).
func checkSigVerified(parts []string) bool {
	if len(parts) < 4 {
		return true // legacy 3-field (v2 off): no check-sig requirement
	}
	return parts[3] == "1"
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
	var successorBackup CompressedPubKey // zero for genesis; pinned to the predecessor's for a rotation (F1)
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
		// F1 (S1-close trust-boundary, HIGH): PIN the successor's BACKUP to the active
		// predecessor's backup. The backup is an operator CSV-recovery key, NOT a TSS
		// ceremony output, so activation can't attest it the way it attests the primary.
		// Left owner-chosen, a rotation could introduce an owner-controlled backup (the
		// real attested primary + a malicious backup); the owner could then `pause` to
		// block the committee's primary-path evacuation and, after the CSV window, drain
		// all post-rotation deposits via the backup branch. Carrying the predecessor's
		// backup forward makes it lineage-immutable (it traces to the genesis backup);
		// RegisterVaultKeys' set-once guard then REJECTS any different backup a
		// registerPublicKey would try to set. (Genesis keeps its owner-set backup = the
		// accepted deployer-trust residual G-1. A deliberate backup rotation must be a
		// separate operator-authenticated path — not owner-alone — out of scope here.)
		successorBackup = vaults[firstVaultWithStatus(vaults, VaultStatusActive)].Backup
	}

	vaults = append(vaults, Vault{
		Generation:    gen,
		Backup:        successorBackup,
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

// isFundHoldingStatus reports whether a vault generation holds — or may still
// receive — funds: active, retiring, or draining. It defines the generations that
// (a) stay deposit-address-matchable (S1.4 dual-generation crediting) and (b) are
// candidates for TSS-key renewal (RenewableVaultKeyIds, below).
//
// ★ These two sets share this STATUS predicate but are NOT identical: Renewable-
// VaultKeyIds further intersects with tssKeyIsRenewable (a key that has aged to
// `retired`/missing on the TSS side can't be renewed and is dropped), so the
// deposit-matchable set is a SUPERSET of the renewable set. The safety property is
// therefore "matched ⇒ RECOVERABLE", NOT "matched ⇒ renewable": funds credited to a
// matched gen are spendable via its PRIMARY key while that key is kept renewed
// (renewKey renews every fund-holding gen — the operational control), and are
// recoverable via the CSV BACKUP path regardless, because a gen's backup shares
// survive until it is PURGED (never-brick invariant #4). Keeping a funded gen's
// primary key alive until it is swept+empty is never-brick invariant #1 — enforced
// by renewKey + the fund-gated purge (S5), not by this predicate. Matching a
// late deposit is always strictly better than dropping it (dropped = uncredited
// loss; matched = credited + at-least-backup-recoverable).
//
// EXCLUSIONS: Pending (no keys yet) is excluded. Purged is excluded (shares destroyed
// → unspendable → its address must not be advertised). Inactive is INCLUDED (S5): an
// emptied-but-unpurged gen stays deposit-matchable so a late/in-flight deposit to its
// address is still credited (S1-DESIGN §5a-#4, the C-2/NR-4 fund-loss guard). Because
// Inactive is matchable, such a deposit re-tags a UTXO to the gen; the retire op
// (ReconcileRetiringVaults) then observes the gen is registry-non-empty and REVERTS it
// INACTIVE→DRAINING so the sweep re-engages ("match-until-purged" + revert-on-late-
// deposit). A gen only leaves the matchable set at PURGE, which is gated on registry-
// emptiness + grace, so no matchable gen can be purged out from under a live deposit.
func isFundHoldingStatus(s VaultStatus) bool {
	return s == VaultStatusActive || s == VaultStatusRetiring ||
		s == VaultStatusDraining || s == VaultStatusInactive
}

// hasSupersededGen reports whether ANY superseded (non-active) fund-holding generation
// currently exists — Retiring, Draining, or Inactive (isFundHoldingStatus minus Active).
// This is the "rotation is live" signal (V-1 build-map §4/§7): a pre-rotation / single-
// active-gen contract always returns false here, so any behavior gated on it (the
// mapping.go indexOutputs min-deposit floor) is BYTE-IDENTICAL to pre-slice behavior until
// the owner rotates for the first time — kept the deploy inert-until-rotation wherever
// possible. Mirrors (but is intentionally independent of) the equivalent inline
// computation in unmapping.go's getInputUtxoIds (D-1 unmap generation filter) — left
// separate to keep this slice's blast radius to the new call site only, rather than
// touching validated D-1 logic. MUST stay in lock-step with isFundHoldingStatus: if you
// add a status there, reconsider whether it belongs here too.
func hasSupersededGen(vaults VaultRegistry) bool {
	return countVaultsWithStatus(vaults, VaultStatusRetiring)+
		countVaultsWithStatus(vaults, VaultStatusDraining)+
		countVaultsWithStatus(vaults, VaultStatusInactive) > 0
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
func RenewableVaultKeyIds() (renewable []string, skipped []string, err error) {
	FoldLegacyGen0IfNeeded()
	vaults, _, _, lerr := LoadVaultState()
	if lerr != nil {
		return nil, nil, lerr
	}
	for i := range vaults {
		// Same fund-holding STATUS set as S1.4 deposit matching (isFundHoldingStatus),
		// then further filtered by tssKeyIsRenewable — so the renewable set is a SUBSET
		// of the deposit-matchable set (see isFundHoldingStatus: a matched gen's funds
		// stay recoverable via a renew-kept primary key or the CSV backup path, NOT
		// because the two sets are identical — they are not).
		if !isFundHoldingStatus(vaults[i].Status) {
			continue
		}
		keyId := VaultKeyId(vaults[i].Generation)
		if tssKeyIsRenewable(keyId) {
			renewable = append(renewable, keyId)
		} else {
			// L-1 (S1-close lifecycle): a fund-holding gen whose TSS key can't be renewed
			// (aged to `retired`/missing) is SKIPPED and RETURNED so the caller can surface
			// it — the never-brick #1 precursor (a retiring gen's primary about to die,
			// leaving its funds CSV-backup-only) must be visible, not a silent success.
			skipped = append(skipped, keyId)
		}
	}
	return renewable, skipped, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// S5 — fund-gated retirement tail (DRAINING → INACTIVE → PURGED).
//
// S1 owns Pending→Active→Retiring; S2 owns Retiring→Draining (on a completed,
// confirmed sweep). This is the S5 consumer that migration.go deliberately left
// unbuilt ("producing INACTIVE in S2 — before this consumer exists — would drop the
// gen out of isFundHoldingStatus and reopen the C-2/NR-4 late-deposit loss"). It is
// invoked by the owner-only, pause-gated retireVault op.
//
// ★ S5.0 (this file): the CONTRACT state machine only. It performs NO TSS key
// destruction — a PURGED gen's shares still exist. Purging only removes the gen from
// the deposit-matchable set (address retired). S5.1 (node side) reads the PURGED status
// as the signal to destroy shares, and gates that destroy on leg (d) (the independent
// zero-balance attestation) — the one irreversible, permanent-loss-capable step.
// ─────────────────────────────────────────────────────────────────────────────

// ReconcileRetiringVaults reconciles every superseded generation's STATUS against the
// live UTXO registry + BTC block height. Owner-only, pause-gated (caller). Idempotent and
// deterministic: slice scans + keyed loads; the funded-gen set is a map used ONLY for
// lookups (never ranged), so every consensus-re-executing node computes the identical
// transitions at a given height.
//
// Per generation, at most ONE transition fires (mutually exclusive on current status):
//
//	DRAINING & registry-non-empty              -> stays DRAINING   (still funded; the sweep owns it)
//	DRAINING & registry-EMPTY                  -> INACTIVE          [leg (a): all known UTXOs swept+confirmed]
//	                                              (records InactiveHeight = height → the grace anchor)
//	INACTIVE & registry-non-empty              -> DRAINING (REVERT) [match-until-purged: a late deposit re-funded it]
//	INACTIVE & registry-EMPTY & canPurgeGen    -> PURGED            [legs (a)+(c)+(d); (b) = purge retires the address]
//	INACTIVE & registry-EMPTY & !canPurgeGen   -> stays INACTIVE    (grace not yet elapsed / attestation absent)
//
// SAFETY — a registry-funded gen can NEVER be purged: the purge branch requires
// registry-EMPTY, and because INACTIVE is in isFundHoldingStatus, a late deposit to an
// emptied gen re-tags a UTXO to it (registry-non-empty) → the REVERT branch fires first →
// back to DRAINING → swept. So funds ever credited to a gen are never destroyed by a purge.
// PENDING/ACTIVE/RETIRING/PURGED gens are untouched here (Retiring→Draining is S2's job).
func ReconcileRetiringVaults(height uint32) (string, error) {
	FoldLegacyGen0IfNeeded()
	vaults, nextGen, activeGen, err := LoadVaultState()
	if err != nil {
		return "", err
	}
	funded, err := fundedGenerations()
	if err != nil {
		return "", err
	}
	var toInactive, toDraining, toPurged []uint32
	for i := range vaults {
		v := &vaults[i]
		switch v.Status {
		case VaultStatusDraining:
			if !funded[v.Generation] {
				v.Status = VaultStatusInactive
				v.InactiveHeight = height
				toInactive = append(toInactive, v.Generation)
			}
		case VaultStatusInactive:
			if funded[v.Generation] {
				// A late/reorg deposit re-funded an emptied gen — revert so the sweep
				// re-engages (AnyFundedSupersededGen / HandleMigrateVault only act on
				// RETIRING|DRAINING). Reset the grace anchor: a fresh emptying must restart
				// the full grace clock before this gen can be purged again.
				v.Status = VaultStatusDraining
				v.InactiveHeight = 0
				toDraining = append(toDraining, v.Generation)
			} else if canPurgeGen(v, height) {
				v.Status = VaultStatusPurged
				toPurged = append(toPurged, v.Generation)
			}
		}
	}
	// Always persist (matches every other lifecycle op; also persists any fold). The
	// active-gen / next-gen counters are passed through unchanged — retire never touches
	// the ACTIVE generation (it is never DRAINING/INACTIVE).
	SaveVaultState(vaults, nextGen, activeGen)
	return retireResultString(toInactive, toDraining, toPurged), nil
}

// fundedGenerations returns the set of vault generations that currently hold at least one
// UTXO in the registry. The returned map is for keyed LOOKUPS only (never ranged) →
// determinism-safe. Mirrors AnyFundedSupersededGen's scan (loadUtxo per registry entry).
// An empty/absent registry → empty set (every superseded gen is then registry-empty).
func fundedGenerations() (map[uint32]bool, error) {
	funded := make(map[uint32]bool)
	utxoState := sdk.StateGetObject(constants.UtxoRegistryKey)
	if utxoState == nil || len(*utxoState) == 0 {
		return funded, nil
	}
	utxos, err := UnmarshalUtxoRegistry([]byte(*utxoState))
	if err != nil {
		return nil, ce.NewContractError(ce.ErrStateAccess, "error decoding utxo registry: "+err.Error())
	}
	for i := range utxos {
		u, lerr := loadUtxo(utxos[i].Id)
		if lerr != nil {
			return nil, lerr
		}
		funded[u.Generation] = true
	}
	return funded, nil
}

// canPurgeGen reports whether an emptied INACTIVE gen may transition to PURGED. A purge
// retires the gen's address out of the deposit-matchable set, so it must be provably safe:
//
//	(c) grace ≥ reorg depth — height ≥ InactiveHeight + VaultPurgeGraceBlocks. Guarded by a
//	    hard fail-closed check that InactiveHeight is set (non-zero): never purge a gen that
//	    did not pass DRAINING→INACTIVE under this op. Overflow-safe (subtract after the ≥).
//	(d) zero-balance attestation — zeroBalanceAttested (TRACKED; see its doc).
//
// (a) registry-emptiness is the caller's precondition (the INACTIVE&&!funded branch); (b)
// address-retirement is intrinsic to the PURGE transition itself (Purged ∉ isFundHoldingStatus).
func canPurgeGen(v *Vault, height uint32) bool {
	if v.InactiveHeight == 0 {
		return false // fail-closed: no grace anchor recorded
	}
	if height < v.InactiveHeight || height-v.InactiveHeight < constants.VaultPurgeGraceBlocks {
		return false // grace window not yet elapsed
	}
	return zeroBalanceAttested(v)
}

// zeroBalanceAttested is S5 gate leg (d): an INDEPENDENT attestation that the gen's vault
// address holds ZERO L1 balance. SPV proves a tx is IN a block but CANNOT prove the ABSENCE
// of UTXOs at an address, so a genuine zero-balance proof needs an external oracle (same
// class as the M1.1b solvency-observation oracle). That oracle is NOT built yet — this is
// the TRACKED leg (user directive: "build (a)+(b)+(c) now, track (d)").
//
// ★ INTENTIONAL PERMISSIVE STUB (returns true). It keeps the DRAINING→INACTIVE→PURGED state
// machine reachable so the full rotation cycle can be devnet-proven now. SAFE pre-pin because:
//  1. the whole rotation feature is inert behind the node deploy gate;
//  2. S5.0 purge only STOPS matching — it destroys NO keys (S5.1 does, and S5.1 will gate the
//     real, irreversible destroy on this attestation); and
//  3. the HARD DEPLOY GATE forbids pinning the rotation activation height until leg (d) is
//     genuinely built + devnet-proven (project memory / node params.go pin-gate (m2)).
//
// When the oracle lands, replace this body with the real attestation read — nothing else changes.
func zeroBalanceAttested(_ *Vault) bool {
	return true // TODO(S5-leg-d): read the independent zero-balance oracle attestation.
}

// retireResultString renders a deterministic human-readable summary of the transitions a
// single retireVault call performed (vault-index order). Purely informational return value.
func retireResultString(toInactive, toDraining, toPurged []uint32) string {
	if len(toInactive) == 0 && len(toDraining) == 0 && len(toPurged) == 0 {
		return "retire: no generation transitions"
	}
	result := "retire:"
	if len(toInactive) > 0 {
		result += " inactivated=" + joinGens(toInactive)
	}
	if len(toDraining) > 0 {
		result += " reverted-to-draining=" + joinGens(toDraining)
	}
	if len(toPurged) > 0 {
		result += " purged=" + joinGens(toPurged)
	}
	return result
}

func joinGens(gens []uint32) string {
	parts := make([]string, len(gens))
	for i, g := range gens {
		parts[i] = strconv.FormatUint(uint64(g), 10)
	}
	return strings.Join(parts, ",")
}
