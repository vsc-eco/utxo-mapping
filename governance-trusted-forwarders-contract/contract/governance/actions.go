package governance

import (
	"governance-trusted-forwarders-contract/contract/constants"
	ce "governance-trusted-forwarders-contract/contract/contracterrors"

	"strings"
)

// CheckAdmin guards every state-mutating action against the contract
// owner. Owner is set at deploy time via the contract-deployer (-owner
// flag); env.ContractOwner() reflects that for the lifetime of the
// contract. Posting auth (not active) is sufficient — the contract's
// only state changes are the four lists below.
//
// Future revision can extend this to accept a configurable multisig
// account; for v1 single-owner mirrors the dash-forwarder + dash-
// mapping admin pattern operators already understand.
func CheckAdmin(env Env) error {
	caller := env.Caller()
	owner := env.ContractOwner()
	if caller == "" || owner == "" {
		return ce.NewError(ce.ErrNoPermission, "caller or owner unset")
	}
	if caller != owner {
		return ce.NewError(ce.ErrNoPermission,
			"admin action requires contract owner ("+owner+"); got "+caller)
	}
	return nil
}

// validateContractId is a defensive sanity check on a proposed id. The
// magi side eventually treats whatever's in the active list as a
// trusted forwarder, so a malformed id passing through here would be a
// gift to anyone who can persuade the admin to propose it. Cheap
// checks: non-empty, bounded length, no delimiters that would corrupt
// the pipe-or-semicolon-delimited list encoding.
func validateContractId(id string) error {
	if id == "" {
		return ce.NewError(ce.ErrInput, "contract id required")
	}
	if len(id) > constants.MaxIdLength {
		return ce.NewError(ce.ErrInput, "contract id exceeds MaxIdLength")
	}
	if strings.Contains(id, constants.EntryDelim) || strings.Contains(id, constants.FieldDelim) {
		return ce.NewError(ce.ErrInput, "contract id must not contain '|' or ';'")
	}
	// Magi compares "contract:" + ctx.env.ContractId, so require the
	// canonical prefix up-front. Lets the magi side do exact string
	// compare without re-prefixing in the hot path.
	if !strings.HasPrefix(id, constants.ContractPrefix) {
		return ce.NewError(ce.ErrInput,
			"contract id must start with '"+constants.ContractPrefix+
				"' (got: "+id+")")
	}
	return nil
}

// ProposeForwarder queues an add. Caller must be admin. Fails if:
//   - id already active
//   - id already in pending-add
//   - id has a pending-remove (conflict — operator should cancel the
//     remove first, otherwise an active forwarder would be racing
//     between adds and removes)
//   - active list is at or beyond MaxForwardersHardCap
func ProposeForwarder(st *Store, id string) error {
	if err := CheckAdmin(st.Env); err != nil {
		return err
	}
	if err := validateContractId(id); err != nil {
		return err
	}
	if st.IsActive(id) {
		return ce.NewError(ce.ErrConflict,
			"forwarder already active: "+id)
	}
	if _, ok := st.FindPendingAdd(id); ok {
		return ce.NewError(ce.ErrConflict,
			"forwarder already has pending-add: "+id)
	}
	if _, ok := st.FindPendingRemove(id); ok {
		return ce.NewError(ce.ErrConflict,
			"forwarder has pending-remove; cancel that first before re-proposing add: "+id)
	}
	if len(st.ActiveList()) >= constants.MaxForwardersHardCap {
		return ce.NewError(ce.ErrConflict,
			"active list at MaxForwardersHardCap; activate-remove an entry first")
	}

	entry := PendingAddEntry{
		Id:           id,
		UnlockHeight: st.Env.BlockHeight() + st.Timelock(),
	}
	list := append(st.PendingAddList(), entry)
	st.SetPendingAddList(list)
	return nil
}

// CancelProposeForwarder removes a pending-add. Admin-only.
func CancelProposeForwarder(st *Store, id string) error {
	if err := CheckAdmin(st.Env); err != nil {
		return err
	}
	if err := validateContractId(id); err != nil {
		return err
	}
	list := st.PendingAddList()
	out := make([]PendingAddEntry, 0, len(list))
	found := false
	for _, e := range list {
		if e.Id == id {
			found = true
			continue
		}
		out = append(out, e)
	}
	if !found {
		return ce.NewError(ce.ErrConflict,
			"no pending-add for forwarder: "+id)
	}
	st.SetPendingAddList(out)
	return nil
}

// ActivateForwarder promotes a pending-add → active once the unlock
// height has been reached. Anyone can call this; the timelock is the
// security gate, not the caller identity.
//
// Why open-permission: it lets a watchful community member nudge an
// add through the moment the timelock expires, even if the admin is
// asleep. Symmetric to ActivateRemoveForwarder — the timelock IS the
// privilege boundary.
func ActivateForwarder(st *Store, id string) error {
	if err := validateContractId(id); err != nil {
		return err
	}
	entry, ok := st.FindPendingAdd(id)
	if !ok {
		return ce.NewError(ce.ErrConflict,
			"no pending-add for forwarder: "+id)
	}
	if st.Env.BlockHeight() < entry.UnlockHeight {
		return ce.NewError(ce.ErrTimelock,
			"pending-add still locked: "+id)
	}
	// Defensive: re-check active membership at activate time even though
	// propose rejects duplicates. Two consecutive proposes that race
	// across a timelock could otherwise leave the same id present twice
	// after both activate.
	if st.IsActive(id) {
		// Idempotent success — just clean up the pending entry.
		removeFromPendingAdd(st, id)
		return nil
	}
	// Cap re-check at activate time too (active count can only grow
	// monotonically here, but a future op that adds via a different
	// path would still want this guard).
	if len(st.ActiveList()) >= constants.MaxForwardersHardCap {
		return ce.NewError(ce.ErrConflict,
			"active list at MaxForwardersHardCap; cannot activate")
	}
	active := append(st.ActiveList(), id)
	st.SetActiveList(active)
	removeFromPendingAdd(st, id)
	return nil
}

// ProposeRemoveForwarder queues a remove. Admin-only.
func ProposeRemoveForwarder(st *Store, id string) error {
	if err := CheckAdmin(st.Env); err != nil {
		return err
	}
	if err := validateContractId(id); err != nil {
		return err
	}
	if !st.IsActive(id) {
		return ce.NewError(ce.ErrConflict,
			"forwarder not active; cannot propose remove: "+id)
	}
	if _, ok := st.FindPendingRemove(id); ok {
		return ce.NewError(ce.ErrConflict,
			"forwarder already has pending-remove: "+id)
	}
	if _, ok := st.FindPendingAdd(id); ok {
		// This should not happen: an id with pending-add cannot also be
		// active (propose rejects). But mirror the symmetric reject so
		// any future code path that bypasses propose surfaces the
		// inconsistency loudly.
		return ce.NewError(ce.ErrConflict,
			"forwarder has pending-add; cancel that first: "+id)
	}

	entry := PendingRemoveEntry{
		Id:           id,
		UnlockHeight: st.Env.BlockHeight() + st.Timelock(),
	}
	list := append(st.PendingRemoveList(), entry)
	st.SetPendingRemoveList(list)
	return nil
}

// CancelProposeRemoveForwarder removes a pending-remove. Admin-only.
func CancelProposeRemoveForwarder(st *Store, id string) error {
	if err := CheckAdmin(st.Env); err != nil {
		return err
	}
	if err := validateContractId(id); err != nil {
		return err
	}
	list := st.PendingRemoveList()
	out := make([]PendingRemoveEntry, 0, len(list))
	found := false
	for _, e := range list {
		if e.Id == id {
			found = true
			continue
		}
		out = append(out, e)
	}
	if !found {
		return ce.NewError(ce.ErrConflict,
			"no pending-remove for forwarder: "+id)
	}
	st.SetPendingRemoveList(out)
	return nil
}

// ActivateRemoveForwarder promotes a pending-remove → deletion. Open
// permission for the same reason as ActivateForwarder.
func ActivateRemoveForwarder(st *Store, id string) error {
	if err := validateContractId(id); err != nil {
		return err
	}
	entry, ok := st.FindPendingRemove(id)
	if !ok {
		return ce.NewError(ce.ErrConflict,
			"no pending-remove for forwarder: "+id)
	}
	if st.Env.BlockHeight() < entry.UnlockHeight {
		return ce.NewError(ce.ErrTimelock,
			"pending-remove still locked: "+id)
	}
	// Idempotent: if id is already gone, just drop the stale pending.
	if !st.IsActive(id) {
		removeFromPendingRemove(st, id)
		return nil
	}
	active := st.ActiveList()
	out := make([]string, 0, len(active))
	for _, a := range active {
		if a != id {
			out = append(out, a)
		}
	}
	st.SetActiveList(out)
	removeFromPendingRemove(st, id)
	return nil
}

// EmergencyRevoke immediately removes a forwarder from the active list
// without a timelock. Admin-only and gated on the
// EmergencyRevokeAllowed flag — if the flag has been disabled (e.g.
// after a stability milestone is reached), the action errors.
//
// Use case: a trusted forwarder is discovered to have a critical bug
// or has been compromised. Operators broadcast emergencyRevoke
// immediately; the standard proposeRemove → 48h wait is too slow.
func EmergencyRevoke(st *Store, id string) error {
	if err := CheckAdmin(st.Env); err != nil {
		return err
	}
	if err := validateContractId(id); err != nil {
		return err
	}
	if !st.EmergencyRevokeAllowed() {
		return ce.NewError(ce.ErrNoPermission,
			"emergency revoke disabled by governance")
	}
	if !st.IsActive(id) {
		return ce.NewError(ce.ErrConflict,
			"forwarder not active; nothing to revoke: "+id)
	}
	active := st.ActiveList()
	out := make([]string, 0, len(active))
	for _, a := range active {
		if a != id {
			out = append(out, a)
		}
	}
	st.SetActiveList(out)
	// Best-effort: drop any pending-remove for the same id (since it's
	// no longer active to remove). Don't error if absent — caller's
	// goal was "id is gone from active", which is satisfied.
	removeFromPendingRemove(st, id)
	return nil
}

// SetTimelock changes the propose→activate window. Admin-only.
//
// Existing pending entries retain their unlock_height as recorded at
// propose time — changing the timelock does NOT retroactively shorten
// or extend pending operations (otherwise an admin could compress a
// pending-add's window to zero). Take effect: new proposes after this
// call use the new value.
func SetTimelock(st *Store, blocks uint64) error {
	if err := CheckAdmin(st.Env); err != nil {
		return err
	}
	return st.SetTimelock(blocks)
}

// SetEmergencyRevokeAllowed flips the emergency-revoke kill-switch.
// Admin-only. Designed to be flipped exactly once in the contract's
// life ("we trust governance + timelock now, disable emergency"),
// but the path is bidirectional in case a future incident requires
// re-enabling.
func SetEmergencyRevokeAllowed(st *Store, allowed bool) error {
	if err := CheckAdmin(st.Env); err != nil {
		return err
	}
	st.SetEmergencyRevokeAllowed(allowed)
	return nil
}

// ===== internal helpers =====

func removeFromPendingAdd(st *Store, id string) {
	list := st.PendingAddList()
	out := make([]PendingAddEntry, 0, len(list))
	for _, e := range list {
		if e.Id != id {
			out = append(out, e)
		}
	}
	st.SetPendingAddList(out)
}

func removeFromPendingRemove(st *Store, id string) {
	list := st.PendingRemoveList()
	out := make([]PendingRemoveEntry, 0, len(list))
	for _, e := range list {
		if e.Id != id {
			out = append(out, e)
		}
	}
	st.SetPendingRemoveList(out)
}
