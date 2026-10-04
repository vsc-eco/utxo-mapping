package current_test

import (
	"os"
	"testing"

	"vsc-node/modules/common/params"
)

// TestMain raises the free-RC allowance for this suite only.
//
// Gas for a contract call is min(availableRCs, tx.RcLimit) (go-vsc-node
// state-processing/transactions.go), and availableRCs derives from
// params.RC_HIVE_FREE_AMOUNT plus the caller's HBD balance. The accounts this
// suite invents hold ~0 HBD, so they fall back to the free tier, which defaults
// to the 10_000 production value. That is not enough gas for the SPV-heavy ops
// (map, migrateVault): they abort with gas_limit_hit, which is a property of the
// fixture's funding, not of the contract under test.
//
// This deliberately lives HERE rather than in go-vsc-node's MocknetConfig /
// DevnetConfig / FromNetwork:
//
//   - RC_HIVE_FREE_AMOUNT is a process-wide mutable global with no reset path.
//     Raising it inside a config constructor leaks into every later config built
//     in the same process, including Testnet/Mainnet, which never reset it.
//   - go-vsc-node's own modules/wasm/e2e TestContractTestUtil asserts the
//     free-tier boundary through the SAME test_utils.NewContractTest() harness
//     and requires the 10_000 default. Raising it there is not a trade-off, it
//     is a direct contradiction: that test fails.
//
// Scoping the raise to this test binary gives this suite the gas it needs and
// leaves every go-vsc-node consumer, production and test, untouched.
func TestMain(m *testing.M) {
	params.RC_HIVE_FREE_AMOUNT = 1_000_000
	os.Exit(m.Run())
}
