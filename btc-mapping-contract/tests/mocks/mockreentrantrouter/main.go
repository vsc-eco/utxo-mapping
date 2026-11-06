// Mock RE-ENTRANT router — the MAP-CEI (15a) regression fixture.
//
// On a swap-tagged deposit the mapping contract credits itself, grants this
// router an allowance, and calls it — all with the deposit's UTXO registered
// and supply credited in MEMORY only. Nothing is persisted yet: before the fix
// the observed list was written after the loop, and the eight whole-state blobs
// are written by SaveToState only once the handler returns.
//
// So a router is called at the one instant when the contract's persisted state
// disagrees with its in-memory state. This mock does what a compromised or
// malicious router would do with that: it calls straight back into a
// blob-writing export of the mapping contract.
//
// Two ways that pays off without the guard. Re-entering `map` with the same
// output sees an observed list in state that does not yet contain it, and
// credits the same real BTC twice. Re-entering any other blob-writing export
// has its writes erased moments later, when the outer frame's SaveToState
// overwrites all eight blobs from its stale snapshot — while the account
// credits that inner call made survive, because those go straight to "a-" keys.
//
// It re-enters `drainUnmapQueue`, chosen deliberately: it IGNORES its payload
// and calls SaveToState unconditionally, so with the guard removed the
// re-entrant call genuinely SUCCEEDS. A target that needed a valid payload
// would fail on input validation whether or not the guard were present, and the
// test would pass for the wrong reason — it would not be testing the guard at
// all. (Verified by neutering the guard and watching the test go red.)
//
// TryContractCall is used so a refusal does not trap this mock; it reports the
// outcome through amount_out instead, which steers the mapping contract down
// either its refund path or its success path and makes the difference visible
// in the depositor's balance.
//
// Build (ids are fixed at build time because the test controls both):
//
//	tinygo build -gc=custom -scheduler=none -panic=trap -no-debug \
//	    -target=wasm-unknown \
//	    -o tests/mocks/mockreentrantrouter/bin/mock_reentrant_router.wasm \
//	    tests/mocks/mockreentrantrouter/main.go
package main

import (
	"btc-mapping-contract/sdk"
)

func main() {}

// Must match the id the test registers.
const mappingContractId = "btc_map_reentrant_test"

//go:wasmexport execute
func Execute(_ *string) *string {
	// Re-enter a blob-writing export mid-call. drainUnmapQueue ignores its
	// payload, so nothing here can fail for an input reason — if this call is
	// refused it is because of the guard, and if the guard is gone it succeeds.
	res := sdk.TryContractCall(mappingContractId, "drainUnmapQueue", `{}`, nil)

	// Report the re-entry outcome through amount_out:
	//   "0" = re-entry refused (guard held)    -> mapping takes its REFUND path
	//   "1" = re-entry SUCCEEDED (guard gone)  -> mapping takes its SUCCESS path
	// So the depositor's balance distinguishes the two, which is what the test
	// asserts on.
	amountOut := "0"
	if res.Ok {
		amountOut = "1"
	}
	out := `{"amount_out":"` + amountOut + `","pool_state":{"asset0":"BTC","asset1":"HBD","reserve0":"0","reserve1":"0","fee":0,"total_lp":"0"}}`
	return &out
}
