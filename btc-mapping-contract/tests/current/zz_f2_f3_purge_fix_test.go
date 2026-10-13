package current_test

// F3 + F2 - S5 purge safety under vault-rotation-v2, minimum-viable.
//
// F3: the contract-side purge gates ONLY on what it can prove on-chain - registry-empty +
// the 144-block grace window (fail-closed anchor) + F2 below. It does NOT wait on an
// independent zero-balance oracle: no such writer exists, and gating on it would hold every
// superseded gen in INACTIVE forever and lock its committee's POA-1 consensus bonds
// permanently. Contract purge is not the irreversible step - it only retires the old address
// from the matchable set; the node-side share destroy (S5.1) carries its own zero-balance
// check if and when it is built. The only residual is a coin sent to a retired address and
// never SPV-submitted within the grace window - the accepted SPV-absence limitation.
//
// F2: an abandoned migration sweep still owes its output to a SuccessorGen on a late
// confirm. If that successor is PURGED before the sweep confirms, settleAbandonedSweep
// indexes the output to a retired, non-fund-matchable gen (coins unspendable, FeeSupply
// credited, I1 still balancing, so no assert fires - invisible insolvency). The fix counts,
// per gen, the live abandoned sweeps naming it as successor (asc-<gen>) and refuses to
// purge while > 0.

import (
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"github.com/stretchr/testify/require"
)

// TestWR_F3_PurgesOnGraceWithoutOracle: an emptied INACTIVE gen past the grace window PURGES
// with no zero-balance oracle present - the production condition, since no such writer
// exists. This is the operator unlock: purge is what lets POA-1 release the retiring
// committee's consensus bonds, so gating it on an unbuilt oracle would lock those bonds
// forever. Purge only retires the address from matching here; it destroys no keys.
func TestWR_F3_PurgesOnGraceWithoutOracle(t *testing.T) {
	ct, contractId, owner := newRetireCT(t)
	const anchor = 900000
	seedRetireState(ct, contractId, anchor+constants.VaultPurgeGraceBlocks, mapping.VaultRegistry{
		{Generation: 1, Status: mapping.VaultStatusInactive, InactiveHeight: anchor},
		{Generation: 2, Status: mapping.VaultStatusActive},
	}, 3, 2)
	// No oracle attestation anywhere - the production condition.

	require.Empty(t, callKeyAction(t, ct, contractId, owner, "retireVault", []byte("")).Err)

	vaults, _, _ := loadVaults(t, ct, contractId)
	require.Equal(t, mapping.VaultStatusPurged, vaultByGen(t, vaults, 1).Status,
		"an empty INACTIVE gen past the grace window must purge on grace alone (unlocks POA-1 bonds); it must not wait on an unbuilt zero-balance oracle")
}

// TestWR_F3_NoPurgeBeforeGrace: the grace window is still load-bearing - an emptied INACTIVE
// gen one block short of InactiveHeight+VaultPurgeGraceBlocks must NOT purge. Guards against
// the simplification having dropped the grace gate along with the oracle leg.
func TestWR_F3_NoPurgeBeforeGrace(t *testing.T) {
	ct, contractId, owner := newRetireCT(t)
	const anchor = 900000
	seedRetireState(ct, contractId, anchor+constants.VaultPurgeGraceBlocks-1, mapping.VaultRegistry{
		{Generation: 1, Status: mapping.VaultStatusInactive, InactiveHeight: anchor},
		{Generation: 2, Status: mapping.VaultStatusActive},
	}, 3, 2)

	require.Empty(t, callKeyAction(t, ct, contractId, owner, "retireVault", []byte("")).Err)

	vaults, _, _ := loadVaults(t, ct, contractId)
	require.Equal(t, mapping.VaultStatusInactive, vaultByGen(t, vaults, 1).Status,
		"one block short of the grace window, the gen must stay INACTIVE (still fund-matchable)")
}

// TestWR_F2_NoPurgeWhileAbandonedSweepTargetsGen: even with the grace window elapsed, a gen
// that is the successor of a live abandoned sweep is not purged; once the tracker clears, the
// same gen purges.
func TestWR_F2_NoPurgeWhileAbandonedSweepTargetsGen(t *testing.T) {
	ct, contractId, owner := newRetireCT(t)
	const anchor = 900000
	seedRetireState(ct, contractId, anchor+constants.VaultPurgeGraceBlocks, mapping.VaultRegistry{
		{Generation: 1, Status: mapping.VaultStatusInactive, InactiveHeight: anchor},
		{Generation: 2, Status: mapping.VaultStatusActive},
	}, 3, 2)
	// Grace elapsed and no oracle gate, so ONLY the F2 guard can block the purge here.
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
		"with no abandoned sweep targeting it, the gen purges on grace alone")
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
