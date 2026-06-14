// Package governance contains the propose/activate/remove logic for the
// trusted-forwarders allow-list. Kept separate from the wasmexport entry
// points in main.go so it can be exercised by pure-Go unit tests with a
// fake state store, without standing up tinygo + wasmedge.
package governance

import (
	"governance-trusted-forwarders-contract/contract/constants"
	ce "governance-trusted-forwarders-contract/contract/contracterrors"

	"strconv"
	"strings"
)

// State is the host-side surface the contract calls into for state I/O.
// In production this is satisfied by direct sdk.State{Get,Set,Delete}
// adapters (see main.go). Tests substitute a fake to drive cases the
// wasm runtime can't reach (e.g. corrupted state).
type State interface {
	Get(key string) *string
	Set(key, val string)
	Delete(key string)
}

// Env exposes the per-call environment the contract needs. Mirrors the
// subset of sdk.GetEnv() / GetEnvKey() that affects business logic.
type Env interface {
	Caller() string         // hive:<acct> form for L1 callers, contract:<id> for nested
	ContractOwner() string  // hive:<acct> who deployed the contract
	BlockHeight() uint64    // current L1 block height
}

// Store wraps a State + Env with strongly-typed accessors for the three
// state-key lists + the two single-value config keys. Pure Go — no sdk
// dep, so unit tests can construct one over a fake state.
type Store struct {
	S   State
	Env Env
}

// ===== single-config-key accessors =====

// Timelock returns the active timelock window in L1 blocks. Falls back to
// constants.DefaultTimelockBlocks when unset.
func (st *Store) Timelock() uint64 {
	raw := st.S.Get(constants.TimelockKey)
	if raw == nil || *raw == "" {
		return constants.DefaultTimelockBlocks
	}
	v, err := strconv.ParseUint(*raw, 10, 64)
	if err != nil {
		// Corrupt state: degrade to default rather than abort every read.
		// The setTimelock action validates input, so seeing garbage here
		// means out-of-band tampering or a bug we want to be loud about.
		return constants.DefaultTimelockBlocks
	}
	return v
}

// SetTimelock writes a new timelock window. Bounds: ≥ 1 block (else
// every propose would activate immediately on the same block), ≤ ~30d
// of L1 blocks (defence-in-depth against an admin proposal that locks
// adds for years). Bounds rejected with ErrInput.
func (st *Store) SetTimelock(blocks uint64) error {
	const maxBlocks = 30 * 24 * 60 * 60 / 3 // ~30 days at 3s/block
	if blocks < 1 {
		return ce.NewError(ce.ErrInput, "timelock must be ≥ 1 block")
	}
	if blocks > maxBlocks {
		return ce.NewError(ce.ErrInput, "timelock exceeds 30-day cap")
	}
	st.S.Set(constants.TimelockKey, strconv.FormatUint(blocks, 10))
	return nil
}

// EmergencyRevokeAllowed reports whether emergencyRevoke is currently
// usable. Defaults to true; a future hardening step can explicitly
// disable.
func (st *Store) EmergencyRevokeAllowed() bool {
	raw := st.S.Get(constants.EmergencyRevokeAllowedKey)
	if raw == nil {
		return true
	}
	return *raw != "0"
}

// SetEmergencyRevokeAllowed flips the kill-switch flag. Persisting "1"
// is functionally identical to deleting the key (both default to true),
// but we write the explicit value so the audit history shows the flip.
func (st *Store) SetEmergencyRevokeAllowed(allowed bool) {
	v := "1"
	if !allowed {
		v = "0"
	}
	st.S.Set(constants.EmergencyRevokeAllowedKey, v)
}

// ===== active list =====

// ActiveList returns the current active forwarders. Each entry carries
// the canonical constants.ContractPrefix prefix already attached.
func (st *Store) ActiveList() []string {
	return splitNonEmpty(st.S.Get(constants.ActiveListKey), constants.EntryDelim)
}

// IsActive is a convenience for membership without rebuilding the slice
// on the caller side. Comparison is exact string equality.
func (st *Store) IsActive(id string) bool {
	for _, e := range st.ActiveList() {
		if e == id {
			return true
		}
	}
	return false
}

// SetActiveList rewrites the active list. Caller is responsible for
// dedup + ordering — the contract's add/remove paths maintain those
// invariants.
func (st *Store) SetActiveList(entries []string) {
	if len(entries) == 0 {
		st.S.Delete(constants.ActiveListKey)
		return
	}
	st.S.Set(constants.ActiveListKey, strings.Join(entries, constants.EntryDelim))
}

// ===== pending-add list =====

// PendingAddEntry is a one-line view of the pending-add queue.
type PendingAddEntry struct {
	Id           string
	UnlockHeight uint64
}

func (st *Store) PendingAddList() []PendingAddEntry {
	raw := splitNonEmpty(st.S.Get(constants.PendingAddListKey), constants.EntryDelim)
	out := make([]PendingAddEntry, 0, len(raw))
	for _, r := range raw {
		parts := strings.SplitN(r, constants.FieldDelim, 2)
		if len(parts) != 2 {
			continue // corrupt — skip rather than abort the whole read
		}
		h, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, PendingAddEntry{Id: parts[0], UnlockHeight: h})
	}
	return out
}

func (st *Store) FindPendingAdd(id string) (PendingAddEntry, bool) {
	for _, e := range st.PendingAddList() {
		if e.Id == id {
			return e, true
		}
	}
	return PendingAddEntry{}, false
}

func (st *Store) SetPendingAddList(entries []PendingAddEntry) {
	if len(entries) == 0 {
		st.S.Delete(constants.PendingAddListKey)
		return
	}
	parts := make([]string, len(entries))
	for i, e := range entries {
		parts[i] = e.Id + constants.FieldDelim + strconv.FormatUint(e.UnlockHeight, 10)
	}
	st.S.Set(constants.PendingAddListKey, strings.Join(parts, constants.EntryDelim))
}

// ===== pending-remove list =====

type PendingRemoveEntry struct {
	Id           string
	UnlockHeight uint64
}

func (st *Store) PendingRemoveList() []PendingRemoveEntry {
	raw := splitNonEmpty(st.S.Get(constants.PendingRemoveListKey), constants.EntryDelim)
	out := make([]PendingRemoveEntry, 0, len(raw))
	for _, r := range raw {
		parts := strings.SplitN(r, constants.FieldDelim, 2)
		if len(parts) != 2 {
			continue
		}
		h, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, PendingRemoveEntry{Id: parts[0], UnlockHeight: h})
	}
	return out
}

func (st *Store) FindPendingRemove(id string) (PendingRemoveEntry, bool) {
	for _, e := range st.PendingRemoveList() {
		if e.Id == id {
			return e, true
		}
	}
	return PendingRemoveEntry{}, false
}

func (st *Store) SetPendingRemoveList(entries []PendingRemoveEntry) {
	if len(entries) == 0 {
		st.S.Delete(constants.PendingRemoveListKey)
		return
	}
	parts := make([]string, len(entries))
	for i, e := range entries {
		parts[i] = e.Id + constants.FieldDelim + strconv.FormatUint(e.UnlockHeight, 10)
	}
	st.S.Set(constants.PendingRemoveListKey, strings.Join(parts, constants.EntryDelim))
}

// ===== helpers =====

// splitNonEmpty handles the (nil ptr | "" string | actual content) shapes
// the SDK returns from StateGetObject for an absent / empty / present
// key uniformly. Empty fragments inside the delim are skipped because
// they only appear when a contract bug writes a malformed list — the
// safe behaviour is "ignore that fragment" rather than "treat it as
// an entry equal to the empty string" (which compares equal to no real
// contract id but could trip a callsite assuming non-empty entries).
func splitNonEmpty(raw *string, delim string) []string {
	if raw == nil || *raw == "" {
		return nil
	}
	parts := strings.Split(*raw, delim)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
