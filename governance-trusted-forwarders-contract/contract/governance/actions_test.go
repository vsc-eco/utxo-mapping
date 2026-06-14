package governance

import (
	"strings"
	"testing"

	"governance-trusted-forwarders-contract/contract/constants"
)

// fakeState is a map-backed State for tests. Mirrors the SDK's nil-on-
// absent + string value semantics.
type fakeState struct {
	m map[string]string
}

func newFakeState() *fakeState { return &fakeState{m: map[string]string{}} }

func (f *fakeState) Get(k string) *string {
	if v, ok := f.m[k]; ok {
		return &v
	}
	return nil
}
func (f *fakeState) Set(k, v string) { f.m[k] = v }
func (f *fakeState) Delete(k string) { delete(f.m, k) }

// fakeEnv is a settable Env for tests so each case can pick caller +
// block height precisely.
type fakeEnv struct {
	caller string
	owner  string
	height uint64
}

func (f *fakeEnv) Caller() string        { return f.caller }
func (f *fakeEnv) ContractOwner() string { return f.owner }
func (f *fakeEnv) BlockHeight() uint64   { return f.height }

// newStore creates a fresh Store with the given owner + height + caller.
func newStore(owner, caller string, height uint64) *Store {
	return &Store{
		S:   newFakeState(),
		Env: &fakeEnv{caller: caller, owner: owner, height: height},
	}
}

// withCaller returns a *Store sharing s's state but with a different
// caller + height. Used to simulate a non-admin observer calling
// activateForwarder after the timelock.
func withCaller(s *Store, caller string, height uint64) *Store {
	return &Store{
		S: s.S,
		Env: &fakeEnv{
			caller: caller,
			owner:  s.Env.ContractOwner(),
			height: height,
		},
	}
}

const (
	ownerAcct = "hive:gov.admin"
	idA       = "contract:vsc1Aforwarder1"
	idB       = "contract:vsc1Bforwarder2"
)

// === Admin gating ===

func TestProposeForwarder_RejectsNonAdmin(t *testing.T) {
	st := newStore(ownerAcct, "hive:malicious", 100)
	err := ProposeForwarder(st, idA)
	if err == nil || !strings.Contains(err.Error(), "ErrNoPermission") {
		t.Fatalf("expected ErrNoPermission, got %v", err)
	}
}

func TestProposeForwarder_RejectsMalformedId(t *testing.T) {
	st := newStore(ownerAcct, ownerAcct, 100)
	cases := map[string]string{
		"empty":            "",
		"missing prefix":   "vsc1Anoprefix",
		"contains pipe":    "contract:vsc1A|bad",
		"contains semicolon": "contract:vsc1A;bad",
		"too long":         "contract:" + strings.Repeat("a", constants.MaxIdLength),
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			err := ProposeForwarder(st, id)
			if err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}

// === Happy path: propose → wait → activate → propose-remove → wait → remove ===

func TestFullLifecycle(t *testing.T) {
	st := newStore(ownerAcct, ownerAcct, 100)

	if err := ProposeForwarder(st, idA); err != nil {
		t.Fatalf("ProposeForwarder: %v", err)
	}
	// Propose succeeded → pending-add entry recorded with unlock=100+57600.
	pa, ok := st.FindPendingAdd(idA)
	if !ok || pa.UnlockHeight != 100+constants.DefaultTimelockBlocks {
		t.Fatalf("expected pending-add at unlock=%d, got %+v", 100+constants.DefaultTimelockBlocks, pa)
	}
	if st.IsActive(idA) {
		t.Fatal("idA should not be active before activate")
	}

	// Activate before unlock → ErrTimelock.
	early := withCaller(st, ownerAcct, 100)
	if err := ActivateForwarder(early, idA); err == nil || !strings.Contains(err.Error(), "ErrTimelock") {
		t.Fatalf("expected ErrTimelock pre-unlock, got %v", err)
	}

	// Anyone can activate after unlock.
	late := withCaller(st, "hive:randomwatcher", 100+constants.DefaultTimelockBlocks)
	if err := ActivateForwarder(late, idA); err != nil {
		t.Fatalf("ActivateForwarder post-unlock: %v", err)
	}
	if !st.IsActive(idA) {
		t.Fatal("idA should be active post-activate")
	}
	if _, ok := st.FindPendingAdd(idA); ok {
		t.Fatal("pending-add should be cleared post-activate")
	}

	// Propose remove → timelock → activate-remove.
	farFuture := newStore(ownerAcct, ownerAcct, 1_000_000)
	farFuture.S = st.S // share state
	if err := ProposeRemoveForwarder(farFuture, idA); err != nil {
		t.Fatalf("ProposeRemoveForwarder: %v", err)
	}
	pr, ok := farFuture.FindPendingRemove(idA)
	if !ok || pr.UnlockHeight != 1_000_000+constants.DefaultTimelockBlocks {
		t.Fatalf("unexpected pending-remove: %+v", pr)
	}
	activator := withCaller(farFuture, "hive:randomwatcher", 1_000_000+constants.DefaultTimelockBlocks)
	if err := ActivateRemoveForwarder(activator, idA); err != nil {
		t.Fatalf("ActivateRemoveForwarder: %v", err)
	}
	if activator.IsActive(idA) {
		t.Fatal("idA should be gone post-activate-remove")
	}
	if _, ok := activator.FindPendingRemove(idA); ok {
		t.Fatal("pending-remove should be cleared post-activate")
	}
}

// === Edge cases ===

func TestProposeForwarder_DuplicateActive(t *testing.T) {
	st := newStore(ownerAcct, ownerAcct, 100)
	st.SetActiveList([]string{idA})
	err := ProposeForwarder(st, idA)
	if err == nil || !strings.Contains(err.Error(), "already active") {
		t.Fatalf("expected 'already active', got %v", err)
	}
}

func TestProposeForwarder_DuplicatePendingAdd(t *testing.T) {
	st := newStore(ownerAcct, ownerAcct, 100)
	if err := ProposeForwarder(st, idA); err != nil {
		t.Fatal(err)
	}
	err := ProposeForwarder(st, idA)
	if err == nil || !strings.Contains(err.Error(), "already has pending-add") {
		t.Fatalf("expected 'already has pending-add', got %v", err)
	}
}

func TestProposeForwarder_ConflictWithActivePendingRemove(t *testing.T) {
	// id is active + has pending-remove. Admin re-proposes add — the
	// canonical rejection is "already active" because that's the
	// more actionable diagnostic (admin should cancel the pending-
	// remove, not try to re-propose-add). Tests the precedence order
	// in ProposeForwarder's checks.
	st := newStore(ownerAcct, ownerAcct, 100)
	st.SetActiveList([]string{idA})
	if err := ProposeRemoveForwarder(st, idA); err != nil {
		t.Fatal(err)
	}
	err := ProposeForwarder(st, idA)
	if err == nil || !strings.Contains(err.Error(), "already active") {
		t.Fatalf("expected 'already active' (more actionable than pending-remove conflict), got %v", err)
	}
}

func TestProposeRemoveForwarder_ConflictWithPendingAdd(t *testing.T) {
	// id has a pending-add (not yet active) + admin tries to propose-
	// remove. propose-remove rejects with "not active" because that's
	// the precondition; the pending-add conflict is dead-code defensive
	// (any id with pending-add can't also be in the active list).
	st := newStore(ownerAcct, ownerAcct, 100)
	if err := ProposeForwarder(st, idA); err != nil {
		t.Fatal(err)
	}
	err := ProposeRemoveForwarder(st, idA)
	if err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("expected 'not active', got %v", err)
	}
}

func TestProposeForwarder_HardCap(t *testing.T) {
	st := newStore(ownerAcct, ownerAcct, 100)
	full := make([]string, constants.MaxForwardersHardCap)
	for i := range full {
		full[i] = "contract:vsc1cap" + strings.Repeat("X", 4)
	}
	st.SetActiveList(full)
	err := ProposeForwarder(st, idA)
	if err == nil || !strings.Contains(err.Error(), "MaxForwardersHardCap") {
		t.Fatalf("expected hard cap rejection, got %v", err)
	}
}

func TestCancelProposeForwarder(t *testing.T) {
	st := newStore(ownerAcct, ownerAcct, 100)
	if err := ProposeForwarder(st, idA); err != nil {
		t.Fatal(err)
	}
	if err := CancelProposeForwarder(st, idA); err != nil {
		t.Fatalf("CancelProposeForwarder: %v", err)
	}
	if _, ok := st.FindPendingAdd(idA); ok {
		t.Fatal("pending-add should be cleared")
	}
	// Cancel again should error (nothing to cancel).
	err := CancelProposeForwarder(st, idA)
	if err == nil || !strings.Contains(err.Error(), "no pending-add") {
		t.Fatalf("expected 'no pending-add', got %v", err)
	}
}

func TestProposeRemoveForwarder_NotActive(t *testing.T) {
	st := newStore(ownerAcct, ownerAcct, 100)
	err := ProposeRemoveForwarder(st, idA)
	if err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("expected 'not active', got %v", err)
	}
}

// === EmergencyRevoke ===

func TestEmergencyRevoke_HappyPath(t *testing.T) {
	st := newStore(ownerAcct, ownerAcct, 100)
	st.SetActiveList([]string{idA, idB})
	if err := EmergencyRevoke(st, idA); err != nil {
		t.Fatalf("EmergencyRevoke: %v", err)
	}
	active := st.ActiveList()
	if len(active) != 1 || active[0] != idB {
		t.Fatalf("expected only idB remaining, got %v", active)
	}
}

func TestEmergencyRevoke_RejectsNonAdmin(t *testing.T) {
	st := newStore(ownerAcct, "hive:malicious", 100)
	st.SetActiveList([]string{idA})
	err := EmergencyRevoke(st, idA)
	if err == nil || !strings.Contains(err.Error(), "ErrNoPermission") {
		t.Fatalf("expected ErrNoPermission, got %v", err)
	}
}

func TestEmergencyRevoke_DisabledByGovernance(t *testing.T) {
	st := newStore(ownerAcct, ownerAcct, 100)
	st.SetActiveList([]string{idA})
	st.SetEmergencyRevokeAllowed(false)
	err := EmergencyRevoke(st, idA)
	if err == nil || !strings.Contains(err.Error(), "disabled by governance") {
		t.Fatalf("expected disabled-by-governance, got %v", err)
	}
}

func TestEmergencyRevoke_NotActive(t *testing.T) {
	st := newStore(ownerAcct, ownerAcct, 100)
	err := EmergencyRevoke(st, idA)
	if err == nil || !strings.Contains(err.Error(), "nothing to revoke") {
		t.Fatalf("expected nothing-to-revoke, got %v", err)
	}
}

// === Timelock management ===

func TestSetTimelock_BoundChecks(t *testing.T) {
	st := newStore(ownerAcct, ownerAcct, 100)
	if err := SetTimelock(st, 0); err == nil {
		t.Fatal("expected error on 0 timelock")
	}
	if err := SetTimelock(st, 1_000_000_000); err == nil {
		t.Fatal("expected error on absurdly high timelock")
	}
	if err := SetTimelock(st, 7200); err != nil {
		t.Fatalf("expected 7200 to succeed, got %v", err)
	}
	if got := st.Timelock(); got != 7200 {
		t.Fatalf("expected timelock=7200, got %d", got)
	}
}

func TestSetTimelock_PendingEntriesRetainOldUnlock(t *testing.T) {
	st := newStore(ownerAcct, ownerAcct, 100)
	if err := ProposeForwarder(st, idA); err != nil {
		t.Fatal(err)
	}
	originalUnlock := 100 + constants.DefaultTimelockBlocks
	if err := SetTimelock(st, 60); err != nil {
		t.Fatal(err)
	}
	pa, _ := st.FindPendingAdd(idA)
	if pa.UnlockHeight != originalUnlock {
		t.Fatalf("expected pending unlock to retain %d, got %d (admin should NOT be able to compress pending windows)",
			originalUnlock, pa.UnlockHeight)
	}
}

// === The wire-encoding round-trip the magi side depends on ===

func TestActiveList_WireFormatStable(t *testing.T) {
	st := newStore(ownerAcct, ownerAcct, 100)
	st.SetActiveList([]string{idA, idB})
	raw := st.S.Get(constants.ActiveListKey)
	if raw == nil {
		t.Fatal("active list should be persisted")
	}
	// Magi reads exactly this string. Verify the encoding contract:
	//   - canonical "contract:" prefix kept on each entry
	//   - pipe delimiter (matches constants.EntryDelim)
	//   - no leading/trailing delim
	if *raw != idA+"|"+idB {
		t.Fatalf("expected wire format %q, got %q", idA+"|"+idB, *raw)
	}
	parsed := strings.Split(*raw, "|")
	if len(parsed) != 2 || parsed[0] != idA || parsed[1] != idB {
		t.Fatalf("split should round-trip; got %v", parsed)
	}
}
