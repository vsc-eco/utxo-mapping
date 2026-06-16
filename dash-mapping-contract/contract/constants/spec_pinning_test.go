// Spec pinning tests. These lock down security-critical numeric
// constants to the values agreed in the spec. They exist so that any
// silent change to a load-bearing economic-security parameter shows up
// as a red test on the PR, forcing a spec-change discussion rather
// than slipping through code review.
//
// If you intentionally change one of these constants, update the spec
// reference in the comment AND the expected value in the test in the
// SAME commit. Reviewers should see the spec section name change
// alongside the constant change.
package constants

import "testing"

// TestSpecPinning_DustFloors locks down the per-op amount floors from
// spec §5.2.4 / §5.2.7.
//
// Increasing MinDustDuffs makes small payments uneconomic to relay.
// Decreasing it widens the attack surface for fee-exhaustion DoS —
// the network burns a fee on every replay but the relayer never
// recovers (no credit issued because rate-limit / abort).
//
// Increasing MinCallFundingDuffs locks small-value calls out of the
// op=call dispatch. Decreasing it lets an attacker fund spam calls
// at near-zero economic cost.
func TestSpecPinning_DustFloors(t *testing.T) {
	if MinDustDuffs != 10_000 {
		t.Errorf("MinDustDuffs = %d, want 10_000 (0.0001 DASH per spec §5.2.4). "+
			"Changing this constant requires a spec change.", MinDustDuffs)
	}
	if MinCallFundingDuffs != 1_000_000 {
		t.Errorf("MinCallFundingDuffs = %d, want 1_000_000 (0.01 DASH per spec §5.2.7). "+
			"Changing this constant requires a spec change.", MinCallFundingDuffs)
	}
	// Sanity: call funding floor must exceed dust floor — otherwise the
	// op=call ladder collapses (value-bearing call would be cheaper to
	// fake than a plain auth).
	if MinCallFundingDuffs <= MinDustDuffs {
		t.Errorf("MinCallFundingDuffs (%d) must exceed MinDustDuffs (%d) — "+
			"otherwise §5.2.7's op=call funding floor is meaningless",
			MinCallFundingDuffs, MinDustDuffs)
	}
}

// TestSpecPinning_PerDIDRateLimit locks down the per-DashDID rate
// limit from spec §5.2.7.
//
// Increasing the max (or shrinking the window) lets an attacker burn
// more aggregator RC per identity before the limiter kicks in.
// Decreasing the max (or widening the window) is mostly harmless but
// risks legitimate-user denial-of-service if usage patterns spike.
//
// The "blocks not seconds" naming is load-bearing — see the
// `rate-limit-uses-block-height-as-seconds` audit fix. Tests below
// pin both the value AND assert the type so a future change from
// uint64 → time.Duration would break compilation here.
func TestSpecPinning_PerDIDRateLimit(t *testing.T) {
	const (
		wantMax    = 30
		wantWindow = uint64(600)
	)
	if PerDashDIDRateLimitMax != wantMax {
		t.Errorf("PerDashDIDRateLimitMax = %d, want %d (per spec §5.2.7). "+
			"Changing this requires a spec change.",
			PerDashDIDRateLimitMax, wantMax)
	}
	if PerDashDIDRateLimitWindowBlocks != wantWindow {
		t.Errorf("PerDashDIDRateLimitWindowBlocks = %d, want %d "+
			"(600 blocks ≈ 30 min at 3s Hive block time, spec §5.2.7). "+
			"Changing this requires a spec change.",
			PerDashDIDRateLimitWindowBlocks, wantWindow)
	}
	// Type-pin: must be uint64 because the comparison `now - windowStart`
	// in checkAndBumpRateLimit (forwarder_integration.go) is uint64
	// arithmetic. A signed type would underflow into a huge number on
	// first call (windowStart=0, now=0 ⇒ wraps).
	var _ uint64 = PerDashDIDRateLimitWindowBlocks
}

// TestSpecPinning_ForwardQueuePruneAge locks down the forwardQueue
// pruning age. 86_400 blocks ≈ 3 days at Hive's 3s block time.
// Shrinking this prunes still-relevant traces; widening it grows
// the state bloat per epoch.
func TestSpecPinning_ForwardQueuePruneAge(t *testing.T) {
	if ForwardQueuePruneAgeBlocks != 86_400 {
		t.Errorf("ForwardQueuePruneAgeBlocks = %d, want 86_400 "+
			"(~3 days at 3s blocks). Changing this requires a spec change.",
			ForwardQueuePruneAgeBlocks)
	}
}
