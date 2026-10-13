package current_test

// F3 + F2 — S5 purge must be safe once vault-rotation-v2 is live.
//
// F3: zeroBalanceAttested was a permissive stub (return true). Its "safe pre-pin"
// justification is void — GATE-1 showed VaultRotationV2InForce turns on at the attested
// floor >= 0.8 regardless of the params.go pin — so once mainnet rises to 0.10 the stub
// would PURGE emptied gens with no independent L1 zero-balance proof, and a later deposit
// to the retired address would map successfully while crediting nobody. The fix reads leg
// (d)'s attestation key and FAILS CLOSED when absent (no oracle writes it yet, so no gen
// purges in production — it simply rests in INACTIVE, which is still fund-matchable).
//
// F2: an abandoned migration sweep still owes its output to a SuccessorGen on a late
// confirm. If that successor is PURGED before the sweep confirms, settleAbandonedSweep
// indexes the output to a retired, non-fund-matchable gen (coins unspendable, FeeSupply
// credited, I1 still balancing, so no assert fires — invisible insolvency). The fix counts,
// per gen, the live abandoned sweeps naming it as successor (asc-<gen>) and refuses to
// purge while > 0.

import (
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"github.com/stretchr/testify/require"
)

// TestWR_F3_NoPurgeWithoutAttestation: an emptied INACTIVE gen past the grace window is NOT
// purged when leg (d)'s attestation is absent — the production state, since no oracle
// writer exists. Before the fix the permissive stub purged it unconditionally.
func TestWR_F3_NoPurgeWithoutAttestation(t *testing.T) {
	ct, contractId, owner := newRetireCT(t)
	const anchor = 900000
	seedRetireState(ct, contractId, anchor+constants.VaultPurgeGraceBlocks, mapping.VaultRegistry{
		{Generation: 1, Status: mapping.VaultStatusInactive, InactiveHeight: anchor},
		{Generation: 2, Status: mapping.VaultStatusActive},
	}, 3, 2)
	// Deliberately set NO zba- attestation for gen 1 (the production condition).

	require.Empty(t, callKeyAction(t, ct, contractId, owner, "retireVault", []byte("")).Err)

	vaults, _, _ := loadVaults(t, ct, contractId)
	require.Equal(t, mapping.VaultStatusInactive, vaultByGen(t, vaults, 1).Status,
		"without the independent zero-balance attestation, purge must fail closed (gen stays INACTIVE, still fund-matchable)")
}

// TestWR_F2_NoPurgeWhileAbandonedSweepTargetsGen: even WITH the attestation and the grace
// window elapsed, a gen that is the successor of a live abandoned sweep is not purged; once
// the tracker clears, the same gen purges.
func TestWR_F2_NoPurgeWhileAbandonedSweepTargetsGen(t *testing.T) {
	ct, contractId, owner := newRetireCT(t)
	const anchor = 900000
	seedRetireState(ct, contractId, anchor+constants.VaultPurgeGraceBlocks, mapping.VaultRegistry{
		{Generation: 1, Status: mapping.VaultStatusInactive, InactiveHeight: anchor},
		{Generation: 2, Status: mapping.VaultStatusActive},
	}, 3, 2)
	// Attestation present, so ONLY the F2 guard can block the purge here.
	ct.StateSet(contractId, constants.ZeroBalanceAttestPrefix+"1", "1")
	// A live abandoned sweep names gen 1 as its successor.
	ct.StateSet(contractId, constants.AbandonedSuccessorPrefix+"1", "1")

	require.Empty(t, callKeyAction(t, ct, contractId, owner, "retireVault", []byte("")).Err)
	vaults, _, _ := loadVaults(t, ct, contractId)
	require.Equal(t, mapping.VaultStatusInactive, vaultByGen(t, vaults, 1).Status,
		"a gen that still owes an abandoned-sweep output must not be purged (F2)")

	// Clear the tracker (the sweep settled or was otherwise resolved) → the gen may purge.
	ct.StateSet(contractId, constants.AbandonedSuccessorPrefix+"1", "")
	require.Empty(t, callKeyAction(t, ct, contractId, owner, "retireVault", []byte("")).Err)
	vaults, _, _ = loadVaults(t, ct, contractId)
	require.Equal(t, mapping.VaultStatusPurged, vaultByGen(t, vaults, 1).Status,
		"with no abandoned sweep targeting it and the attestation present, the gen purges")
}

// TestWR_F2_AbandonTracksSuccessorForPurgeGate: the REAL abandon path increments the
// successor tracker and a late settle clears it, so the F2 guard above is actually fed.
func TestWR_F2_AbandonTracksSuccessorForPurgeGate(t *testing.T) {
	const amount = int64(40_000)
	const reserve = int64(100_000)
	ct, contractId, owner := newH2CT(t, []utxoSeed{{10, amount}}, reserve)
	orig, repl, build := migrateAndRedrive(t, ct, contractId, owner)
	replTx := signingTx(t, ct, contractId, repl)

	// The sweep sweeps retiring gen 0 to the active successor gen 1; nothing targets it yet.
	require.Empty(t, ct.StateGet(contractId, constants.AbandonedSuccessorPrefix+"1"),
		"no abandoned sweep targets gen 1 before the abandon")

	setHeight(ct, contractId, build+constants.SweepAbandonBlocks)
	require.True(t, callAs(t, ct, contractId, owner, "abandonSweep", []byte(orig)).Success)

	// Abandon incremented the successor tracker → gen 1 is now purge-blocked (F2).
	require.NotEmpty(t, ct.StateGet(contractId, constants.AbandonedSuccessorPrefix+"1"),
		"abandonSweep must register gen 1 as an abandoned-sweep successor")

	// A late confirmation settles the sweep and clears the tracker.
	require.True(t, confirmTxBytes(t, ct, contractId, owner, replTx, build+constants.SweepAbandonBlocks+5).Success)
	require.Empty(t, ct.StateGet(contractId, constants.AbandonedSuccessorPrefix+"1"),
		"the late settle must clear the successor tracker so the gen can eventually purge")
}
