package current_test

import (
	"strconv"
	"strings"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/require"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"
)

// S5.0 — fund-gated retirement contract state machine (retireVault →
// ReconcileRetiringVaults). Drives the DRAINING→INACTIVE→PURGED tail that S1/S2
// deliberately leave unbuilt, over the REAL compiled WASM with controlled state.
// These prove: (1) the four transitions, (2) the grace gate, (3) the fail-closed
// no-anchor guard, (4) the load-bearing safety invariant — a registry-funded gen is
// NEVER purged (revert-on-late-deposit wins over purge even past the grace window),
// (5) pause- and owner-gating. S5.0 performs NO key destruction (that is S5.1); a
// PURGED status here only retires the gen's address out of the matchable set.

func newRetireCT(t *testing.T) (*test_utils.ContractTest, string, string) {
	t.Helper()
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	return &ct, contractId, owner
}

// seedRetireState sets the vault registry + gen counters + the BTC block height
// (read by blocklist.LastHeightFromState) directly, bypassing the full rotation
// ceremony so a single transition can be exercised in isolation.
func seedRetireState(ct *test_utils.ContractTest, contractId string, height uint32, vaults mapping.VaultRegistry, nextGen, activeGen uint32) {
	ct.StateSet(contractId, constants.VaultRegistryKey, string(mapping.MarshalVaultRegistry(vaults)))
	ct.StateSet(contractId, constants.VaultNextGenKey, u32be(nextGen))
	ct.StateSet(contractId, constants.VaultActiveGenKey, u32be(activeGen))
	ct.StateSet(contractId, constants.LastHeightKey, strconv.FormatUint(uint64(height), 10))
}

// fundGenUtxo tags one UTXO to `gen` in the registry (a late deposit that landed on an
// emptied gen's still-matchable address). fundedGenerations reads only u.Generation, so
// the script/tag are irrelevant — the txid must be 32 bytes (MarshalUtxo requirement).
func fundGenUtxo(t *testing.T, ct *test_utils.ContractTest, contractId string, id uint16, gen uint32) {
	t.Helper()
	ct.StateSet(contractId, constants.UtxoRegistryKey,
		string(mapping.MarshalUtxoRegistry(mapping.UtxoRegistry{{Id: id, Amount: 5000}})))
	u := mapping.Utxo{TxId: strings.Repeat("ab", 32), Vout: 0, Amount: 5000, Generation: gen}
	blob := mapping.MarshalUtxo(&u)
	require.NotNil(t, blob, "MarshalUtxo returned nil (bad txid length)")
	ct.StateSet(contractId, constants.UtxoPrefix+strconv.FormatUint(uint64(id), 16), string(blob))
}

func vaultByGen(t *testing.T, vaults mapping.VaultRegistry, gen uint32) mapping.Vault {
	t.Helper()
	for _, v := range vaults {
		if v.Generation == gen {
			return v
		}
	}
	t.Fatalf("generation %d not found in vault registry", gen)
	return mapping.Vault{}
}

// (1) DRAINING & registry-empty → INACTIVE, recording InactiveHeight = current height
// (the grace anchor). The ACTIVE successor is untouched.
func TestRetireVault_DrainingToInactiveWhenEmpty(t *testing.T) {
	ct, contractId, owner := newRetireCT(t)
	const h = 900000
	seedRetireState(ct, contractId, h, mapping.VaultRegistry{
		{Generation: 1, Status: mapping.VaultStatusDraining, Predecessor: 0, RetiredHeight: 899000},
		{Generation: 2, Status: mapping.VaultStatusActive, Predecessor: 1},
	}, 3, 2)

	r := callKeyAction(t, ct, contractId, owner, "retireVault", []byte(""))
	require.Empty(t, r.Err, "retireVault should succeed")

	vaults, _, activeGen := loadVaults(t, ct, contractId)
	require.Equal(t, uint32(2), activeGen, "active gen untouched")
	require.Equal(t, mapping.VaultStatusInactive, vaultByGen(t, vaults, 1).Status, "empty draining gen → inactive")
	require.Equal(t, uint32(h), vaultByGen(t, vaults, 1).InactiveHeight, "InactiveHeight anchored to current height")
	require.Equal(t, mapping.VaultStatusActive, vaultByGen(t, vaults, 2).Status, "active gen stays active")
}

// (2) INACTIVE & registry-empty & grace NOT elapsed → stays INACTIVE.
func TestRetireVault_InactiveHoldsBeforeGrace(t *testing.T) {
	ct, contractId, owner := newRetireCT(t)
	const anchor = 900000
	seedRetireState(ct, contractId, anchor+constants.VaultPurgeGraceBlocks-1, mapping.VaultRegistry{
		{Generation: 1, Status: mapping.VaultStatusInactive, InactiveHeight: anchor},
		{Generation: 2, Status: mapping.VaultStatusActive},
	}, 3, 2)

	r := callKeyAction(t, ct, contractId, owner, "retireVault", []byte(""))
	require.Empty(t, r.Err)

	vaults, _, _ := loadVaults(t, ct, contractId)
	require.Equal(t, mapping.VaultStatusInactive, vaultByGen(t, vaults, 1).Status, "one block short of grace must not purge")
}

// (3) INACTIVE & registry-empty & grace elapsed → PURGED (address retired). Exactly at
// the grace boundary (height == anchor + grace) must purge.
func TestRetireVault_InactiveToPurgedAtGraceBoundary(t *testing.T) {
	ct, contractId, owner := newRetireCT(t)
	const anchor = 900000
	seedRetireState(ct, contractId, anchor+constants.VaultPurgeGraceBlocks, mapping.VaultRegistry{
		{Generation: 1, Status: mapping.VaultStatusInactive, InactiveHeight: anchor},
		{Generation: 2, Status: mapping.VaultStatusActive},
	}, 3, 2)

	r := callKeyAction(t, ct, contractId, owner, "retireVault", []byte(""))
	require.Empty(t, r.Err)

	vaults, _, _ := loadVaults(t, ct, contractId)
	require.Equal(t, mapping.VaultStatusPurged, vaultByGen(t, vaults, 1).Status, "empty inactive gen past grace → purged")
}

// (4) FAIL-CLOSED: an INACTIVE gen with a ZERO grace anchor (InactiveHeight==0) is NEVER
// purged, even at an absurdly high height. Guards against destroying a gen that did not
// pass DRAINING→INACTIVE under this op (no recorded anchor).
func TestRetireVault_NeverPurgesWithoutGraceAnchor(t *testing.T) {
	ct, contractId, owner := newRetireCT(t)
	seedRetireState(ct, contractId, 100000000, mapping.VaultRegistry{
		{Generation: 1, Status: mapping.VaultStatusInactive, InactiveHeight: 0},
		{Generation: 2, Status: mapping.VaultStatusActive},
	}, 3, 2)

	r := callKeyAction(t, ct, contractId, owner, "retireVault", []byte(""))
	require.Empty(t, r.Err)

	vaults, _, _ := loadVaults(t, ct, contractId)
	require.Equal(t, mapping.VaultStatusInactive, vaultByGen(t, vaults, 1).Status, "no grace anchor → never purge (fail-closed)")
}

// (5) ★ LOAD-BEARING SAFETY: an INACTIVE gen that a late deposit re-funded is REVERTED to
// DRAINING (so the sweep re-engages) — and is NEVER purged, EVEN past the grace window.
// This is the invariant the whole build rests on: a registry-funded gen can never have its
// address retired / shares destroyed out from under live funds.
func TestRetireVault_RevertsFundedInactiveAndNeverPurges(t *testing.T) {
	ct, contractId, owner := newRetireCT(t)
	const anchor = 900000
	// height WELL past grace — purge would fire if the funded UTXO were ignored.
	seedRetireState(ct, contractId, anchor+constants.VaultPurgeGraceBlocks+500, mapping.VaultRegistry{
		{Generation: 1, Status: mapping.VaultStatusInactive, InactiveHeight: anchor},
		{Generation: 2, Status: mapping.VaultStatusActive},
	}, 3, 2)
	fundGenUtxo(t, ct, contractId, 1024, 1) // a late deposit tagged to the emptied gen 1

	r := callKeyAction(t, ct, contractId, owner, "retireVault", []byte(""))
	require.Empty(t, r.Err)

	vaults, _, _ := loadVaults(t, ct, contractId)
	g1 := vaultByGen(t, vaults, 1)
	require.Equal(t, mapping.VaultStatusDraining, g1.Status, "funded inactive gen must revert to draining, NOT purge")
	require.Equal(t, uint32(0), g1.InactiveHeight, "grace anchor reset on revert (a fresh emptying restarts the clock)")
}

// (6) No-op / idempotent: nothing to reconcile (only an ACTIVE gen) → registry unchanged,
// informational "no generation transitions".
func TestRetireVault_NoOpWhenNothingToReconcile(t *testing.T) {
	ct, contractId, owner := newRetireCT(t)
	seedRetireState(ct, contractId, 900000, mapping.VaultRegistry{
		{Generation: 0, Status: mapping.VaultStatusActive},
	}, 1, 0)
	before := ct.StateGet(contractId, constants.VaultRegistryKey)

	r := callKeyAction(t, ct, contractId, owner, "retireVault", []byte(""))
	require.Empty(t, r.Err)
	require.Contains(t, string(r.Ret), "no generation transitions")
	require.Equal(t, before, ct.StateGet(contractId, constants.VaultRegistryKey), "registry unchanged")
}

// (7) PAUSE-GATED: a purge retires an address (and, via S5.1, signals share destruction) —
// exactly the irreversible action that must not proceed during an emergency pause.
func TestRetireVault_RefusedWhenPaused(t *testing.T) {
	ct, contractId, owner := newRetireCT(t)
	seedRetireState(ct, contractId, 900000, mapping.VaultRegistry{
		{Generation: 1, Status: mapping.VaultStatusDraining},
		{Generation: 2, Status: mapping.VaultStatusActive},
	}, 3, 2)
	ct.StateSet(contractId, constants.PausedKey, "1")

	r := callKeyAction(t, ct, contractId, owner, "retireVault", []byte(""))
	require.NotEmpty(t, r.Err, "retireVault must abort while paused")

	vaults, _, _ := loadVaults(t, ct, contractId)
	require.Equal(t, mapping.VaultStatusDraining, vaultByGen(t, vaults, 1).Status, "no transition on a reverted (paused) call")
}

// (8) OWNER-ONLY: a non-owner caller is refused; no state change.
func TestRetireVault_OwnerOnly(t *testing.T) {
	ct, contractId, _ := newRetireCT(t)
	seedRetireState(ct, contractId, 900000, mapping.VaultRegistry{
		{Generation: 1, Status: mapping.VaultStatusDraining},
		{Generation: 2, Status: mapping.VaultStatusActive},
	}, 3, 2)

	r := callKeyAction(t, ct, contractId, "hive:attacker", "retireVault", []byte(""))
	require.NotEmpty(t, r.Err, "non-owner retireVault must be refused")

	vaults, _, _ := loadVaults(t, ct, contractId)
	require.Equal(t, mapping.VaultStatusDraining, vaultByGen(t, vaults, 1).Status, "no transition on a refused call")
}

// ★ S5 council HIGH regression — a user unmap must NEVER select an INACTIVE gen's UTXO.
// S5 added INACTIVE to isFundHoldingStatus (matchable for late deposits), which widened
// the deposit-matchable set but NOT the unmap generation-scoping filter (hasSuperseded).
// Left unfixed, in the normal post-rotation state (active + inactive, no retiring/draining)
// an unmap would select the INACTIVE gen's UTXO, DEBIT the user, then the node's
// output-scoped signing gate would refuse the superseded key → silent debit-without-delivery
// (the D-1 hole). The fix adds VaultStatusInactive to hasSuperseded (unmapping.go). This is
// the exact Inactive analogue of TestUnmapExcludesRetiringGenUtxo.
func TestUnmapExcludesInactiveGenUtxo(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const amount = int64(100000)
	const blockHeight = uint32(100)
	fixture := buildMapFixture(t, instruction, amount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	seedActiveGen0(t, &ct, contractId, owner)

	// Deposit to gen-0 while ACTIVE → one confirmed gen-0 UTXO + user balance.
	params := mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight: blockHeight, RawTxHex: fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex, TxIndex: fixture.TxIndex,
		},
		Instructions: []string{instruction},
	}
	payload, err := tinyjson.Marshal(params)
	require.NoError(t, err)
	require.True(t, ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "map-dep", BlockId: "block:map", Index: 70, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "map", Payload: payload,
		RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: owner,
	}).Success)
	require.Equal(t, encodeBalance(t, amount), ct.StateGet(contractId, constants.BalancePrefix+owner))

	// Rotate: gen-0 → retiring, gen-1 → active (gen-1 holds NO UTXO).
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "activateKey", []byte("")).Err)

	// Drive gen-0 RETIRING → INACTIVE directly (the emptied-but-unpurged state S5 produces;
	// its UTXO is the late-deposit that keeps it matchable). This is the exact state the
	// unmap filter must still exclude.
	vaults, nextGen, activeGen := loadVaults(t, &ct, contractId)
	g0 := firstIdxByGen(t, vaults, 0)
	require.Equal(t, mapping.VaultStatusRetiring, vaults[g0].Status)
	vaults[g0].Status = mapping.VaultStatusInactive
	vaults[g0].InactiveHeight = 100
	ct.StateSet(contractId, constants.VaultRegistryKey, string(mapping.MarshalVaultRegistry(vaults)))
	_ = nextGen
	_ = activeGen

	// A user unmap that would need the gen-0 (now INACTIVE) UTXO must be refused — the
	// only UTXO belongs to a superseded gen, gen-1 (active) holds none.
	unmapPayload, err := tinyjson.Marshal(mapping.TransferParams{Amount: "50000", To: regtestDestAddress(t)})
	require.NoError(t, err)
	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "unmap-i1", BlockId: "block:unmap", Index: 71, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "unmap", Payload: unmapPayload,
		RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: owner,
	})
	require.False(t, r.Success, "unmap must be refused: only the INACTIVE gen-0 UTXO exists (D-1 / S5 council HIGH)")

	// Fail-safe: no debit, the gen-0 UTXO untouched.
	require.Equal(t, encodeBalance(t, amount), ct.StateGet(contractId, constants.BalancePrefix+owner),
		"a refused unmap must not debit the caller")
	reg, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, reg, 1, "the inactive gen-0 UTXO is untouched by the refused unmap")
	require.Equal(t, uint32(0), utxoGenerationForId(t, &ct, contractId, reg[0].Id))
}

// grace F7 — retireVault on an UNFOLDED legacy contract (flat keys, no vault list) is
// inert: FoldLegacyGen0IfNeeded writes an ACTIVE gen-0, which the reconcile loop never
// touches (it matches only Draining/Inactive). Mirrors the createKey fold-safety test.
func TestRetireVaultOnUnfoldedLegacyContractIsInert(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	// Legacy flat keys, NO vault list, a seeded height — the upgraded-but-un-rotated state.
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	ct.StateSet(contractId, constants.LastHeightKey, "900000")

	r := callKeyAction(t, &ct, contractId, owner, "retireVault", []byte(""))
	require.Empty(t, r.Err, "retireVault must succeed (fold + no-op) on a legacy contract")
	require.Contains(t, string(r.Ret), "no generation transitions")

	vaults, nextGen, activeGen := loadVaults(t, &ct, contractId)
	require.Len(t, vaults, 1, "legacy gen-0 folded")
	require.Equal(t, mapping.VaultStatusActive, vaults[0].Status, "folded gen-0 is ACTIVE, untouched by reconcile")
	require.Equal(t, uint32(1), nextGen)
	require.Equal(t, uint32(0), activeGen)
}

func firstIdxByGen(t *testing.T, vaults mapping.VaultRegistry, gen uint32) int {
	t.Helper()
	for i := range vaults {
		if vaults[i].Generation == gen {
			return i
		}
	}
	t.Fatalf("generation %d not found", gen)
	return -1
}
