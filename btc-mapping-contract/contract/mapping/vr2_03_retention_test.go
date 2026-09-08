package mapping

import (
	"testing"

	"btc-mapping-contract/contract/constants"
)

// VR2-03: header retention must outlast the spends that depend on it, and the
// mechanism that guarantees that must itself be bounded.
//
// confirmSpend proves a spend against the exact header at its mined height.
// Pruning deleted headers on a fixed schedule with no knowledge that a spend was
// still waiting for one, so a sweep mined on Bitcoin but not reported to the
// contract within the retention window lost its proof permanently: it could never
// settle, redrive could not help because the coins had already moved, and the
// generation stayed "funded" forever, blocking every rotation and holding every
// witness's bond.
//
// The retention clamp fixes that by anchoring on the oldest live spend. These
// tests pin the two properties that make the clamp safe rather than a new problem.
func TestVR203_RetentionClampIsBounded(t *testing.T) {
	// An unbounded clamp would let one never-confirming spend pin header retention
	// forever, growing contract state without limit — trading a liveness bug for a
	// storage one.
	if constants.MaxRetentionWithPendingSpend <= constants.MaxBlockRetention {
		t.Fatal("the pending-spend retention bound must exceed the normal window, " +
			"or the clamp can never hold a header at all")
	}
	if constants.MaxRetentionWithPendingSpend > 4*constants.MaxBlockRetention {
		t.Errorf("the pending-spend retention bound is %d against a normal window of "+
			"%d: an unbounded-in-practice clamp lets one stuck spend pin state growth",
			constants.MaxRetentionWithPendingSpend, constants.MaxBlockRetention)
	}
}

// The clamp is only safe because the number of live spends is capped. Unmap is
// permissionless and rate-limited by SATOSHIS per block, with no limit on count or
// duration, so without this bound an attacker could hold open an unbounded number
// of cheap never-confirming unmaps — each pinning retention at its own build
// height — and both stall pruning and force the clear-time recompute to scale with
// their spend.
func TestVR203_ConcurrentSpendsAreCapped(t *testing.T) {
	if constants.MaxConcurrentPendingSpends <= 0 {
		t.Fatal("an uncapped pending-spend count makes the retention clamp an " +
			"unbounded state-growth vector")
	}
	// The cap must still leave room for ordinary withdrawal traffic; refusing real
	// unmaps would be a worse failure than the one being prevented.
	if constants.MaxConcurrentPendingSpends < 64 {
		t.Errorf("a cap of %d is low enough to refuse legitimate withdrawal traffic",
			constants.MaxConcurrentPendingSpends)
	}
}
