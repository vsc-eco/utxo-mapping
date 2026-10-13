package current_test

// F3 + F2 - S5 purge safety under vault-rotation-v2, minimum-viable.
//
// F3: the contract-side purge gates ONLY on what it can prove on-chain - registry-empty +
// the 144-block grace window (fail-closed anchor). It does NOT wait on a zero-balance oracle
// (none exists; gating on it would hold every superseded gen in INACTIVE forever and lock its
// POA-1 consensus bonds). Contract purge is not the irreversible step - it only retires the
// old address from the matchable set; node-side share-destroy (S5.1) keeps its own check
// if/when built. Residual: a coin sent to a retired address and never SPV-submitted within
// grace (accepted SPV-absence limit).
//
// F2: a late confirm of an abandoned migration sweep must not index its output onto a PURGED
// successor (unspendable UTXO + phantom FeeSupply credit = invisible insolvency). An earlier
// design held the successor's purge with an asc- counter until the sweep settled - but
// abandoned sweeps are usually the never-confirm kind (inputs gone / double-spent), so that
// hold was effectively forever and bond-locked the committee (H3 returning via F2). The
// minimum-viable fix DROPS the hold entirely and guards at SETTLE instead: settleAbandonedSweep
// indexes the output only while the successor is still fund-holding, and on a purged successor
// does a SUCCESSFUL no-op (output left unindexed - the write-off stands - and the sa- records
// cleared so the bot's BOT-ABANDON-2 confirmSpend retry sees success and stops). So purge
// proceeds on grace and a never-confirming sweep holds nothing.

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

// TestWR_F2_LateConfirmFundHoldingSuccessorSettles: the live settle path is UNCHANGED while
// the successor is fund-holding. Abandon a real sweep, then confirm it late while its
// successor (gen 1, Active) still holds funds: the recovered output is indexed to the
// successor and the written-off amount returns to the fee reserve.
func TestWR_F2_LateConfirmFundHoldingSuccessorSettles(t *testing.T) {
	const amount = int64(40_000)
	const reserve = int64(100_000)
	ct, contractId, owner := newH2CT(t, []utxoSeed{{10, amount}}, reserve)
	orig, repl, build := migrateAndRedrive(t, ct, contractId, owner)
	replTx := signingTx(t, ct, contractId, repl)

	setHeight(ct, contractId, build+constants.SweepAbandonBlocks)
	require.True(t, callAs(t, ct, contractId, owner, "abandonSweep", []byte(orig)).Success)
	feeAfterAbandon := readFeeSupply(t, ct, contractId)
	idsAfterAbandon := len(registryIds(t, ct, contractId))

	require.True(t, confirmTxBytes(t, ct, contractId, owner, replTx, build+constants.SweepAbandonBlocks+5).Success)

	require.Greater(t, len(registryIds(t, ct, contractId)), idsAfterAbandon,
		"a fund-holding successor must get the recovered output indexed")
	require.Greater(t, readFeeSupply(t, ct, contractId), feeAfterAbandon,
		"settle returns the written-off amount to the fee reserve")
}

// TestWR_F2_LateConfirmPurgedSuccessorNoOps: the guard. Abandon a real sweep, drive its
// successor (gen 1) to PURGED as it would be many rotations later, then confirm the sweep
// late. settleAbandonedSweep must NOT index the output or credit FeeSupply onto the purged
// (retired, non-matchable) successor - that would be the invisible insolvency F2 exists to
// stop. It must SUCCEED as a no-op (a refusal would loop BOT-ABANDON-2's confirmSpend retry
// forever) and clear the sa- records. Removing the guard (indexing onto the purged gen) fails
// the FeeSupply / registry assertions below - this is the mutation guard.
func TestWR_F2_LateConfirmPurgedSuccessorNoOps(t *testing.T) {
	const amount = int64(40_000)
	const reserve = int64(100_000)
	ct, contractId, owner := newH2CT(t, []utxoSeed{{10, amount}}, reserve)
	orig, repl, build := migrateAndRedrive(t, ct, contractId, owner)
	replTx := signingTx(t, ct, contractId, repl)

	setHeight(ct, contractId, build+constants.SweepAbandonBlocks)
	require.True(t, callAs(t, ct, contractId, owner, "abandonSweep", []byte(orig)).Success)

	// Flip the successor gen 1 to PURGED (its address is now retired). The abandoned sweep's
	// output still pays that retired address on a late confirm.
	vaults, nextGen, activeGen := loadVaults(t, ct, contractId)
	for i := range vaults {
		if vaults[i].Generation == 1 {
			vaults[i].Status = mapping.VaultStatusPurged
		}
	}
	ct.StateSet(contractId, constants.VaultRegistryKey, string(mapping.MarshalVaultRegistry(vaults)))
	_, _ = nextGen, activeGen

	feeBefore := readFeeSupply(t, ct, contractId)
	idsBefore := len(registryIds(t, ct, contractId))

	res := confirmTxBytes(t, ct, contractId, owner, replTx, build+constants.SweepAbandonBlocks+5)
	require.True(t, res.Success,
		"a late confirm after purge must SUCCEED as a no-op, not refuse (a refusal loops the bot's confirmSpend retry forever)")

	require.Equal(t, feeBefore, readFeeSupply(t, ct, contractId),
		"no FeeSupply credit onto a purged successor (would be phantom solvency)")
	require.Equal(t, idsBefore, len(registryIds(t, ct, contractId)),
		"no UTXO indexed onto a purged successor (would be an unspendable registry entry)")
	require.Empty(t, ct.StateGet(contractId, constants.AbandonedSweepPrefix+repl),
		"the sa- record must be cleared on the no-op settle so BOT-ABANDON-2's retry stops")
}
