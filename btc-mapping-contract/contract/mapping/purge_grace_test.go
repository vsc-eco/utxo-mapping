package mapping

import (
	"testing"

	"btc-mapping-contract/contract/constants"
)

// ADDR-ROTATE-1 / PURGE-GRIEF-1: the purge grace is one backup-CSV period on mainnet and
// 144 blocks elsewhere; a late deposit does not restart it, but the purge still waits the
// reorg margin after the last emptying.
func TestPurgeGraceAndAnchor(t *testing.T) {
	if got := constants.VaultPurgeGraceBlocks("mainnet"); got != constants.BackupCSVBlocks {
		t.Fatalf("mainnet grace = %d, want %d", got, constants.BackupCSVBlocks)
	}
	for _, m := range []string{constants.Regtest, constants.Testnet3, constants.Testnet4} {
		if got := constants.VaultPurgeGraceBlocks(m); got != constants.VaultPurgeReorgBlocks {
			t.Fatalf("%s grace = %d, want %d", m, got, constants.VaultPurgeReorgBlocks)
		}
	}
	main := constants.VaultPurgeGraceBlocks("mainnet")
	reorg := uint32(constants.VaultPurgeReorgBlocks)
	purgeAt := func(anchor, grace uint32) uint32 { return anchor + grace }

	// First emptying: anchored at the height.
	a := inactiveAnchor(0, 900_000, main)
	if a != 900_000 {
		t.Fatalf("first anchor = %d", a)
	}
	// A late deposit is swept and the gen empties again 10 days later: the purge does NOT
	// move (first + grace is still later than last + margin).
	a2 := inactiveAnchor(a, 900_000+1_440, main)
	if purgeAt(a2, main) != 900_000+main {
		t.Fatalf("re-emptying 10 days in moved the purge to %d", purgeAt(a2, main))
	}
	// A deposit right before the purge: the purge waits the reorg margin after the last
	// emptying, not another 30 days.
	last := uint32(900_000 + main - 10)
	a3 := inactiveAnchor(a2, last, main)
	if purgeAt(a3, main) != last+reorg {
		t.Fatalf("late re-emptying: purge at %d, want %d", purgeAt(a3, main), last+reorg)
	}
	// Testnets: grace == margin, so every emptying restarts the clock, as before.
	tg := constants.VaultPurgeGraceBlocks(constants.Testnet3)
	if b := inactiveAnchor(500, 700, tg); b != 700 {
		t.Fatalf("testnet re-emptying anchor = %d, want 700", b)
	}
	// canPurgeGen: fail-closed without an anchor, exact at the boundary.
	v := &Vault{InactiveHeight: 0}
	if canPurgeGen(v, 1_000_000, main) {
		t.Fatal("no anchor must never purge")
	}
	v.InactiveHeight = 900_000
	if canPurgeGen(v, 900_000+main-1, main) || !canPurgeGen(v, 900_000+main, main) {
		t.Fatal("purge boundary wrong")
	}
}
