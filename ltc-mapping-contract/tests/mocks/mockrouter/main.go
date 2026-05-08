// Mock router contract for BTC-C4 test fixture.
//
// The real DEX router (vsc-eco/dex-contracts/dex-router-v2) exposes an
// `execute` entrypoint that the LTC mapping contract calls during
// swap-tagged deposits. When the router fails or returns
// `amount_out == "0"`, ltc-mapping-contract previously reverted the
// entire map transaction — losing the user's deposit credit. The
// BTC-C4 fix instead refunds the depositor with raw BTC.
//
// This mock router lets the test exercise that refund path
// deterministically. It exports `execute`, which always returns
// `{"amount_out":"0", "pool_state":{...}}`. TinyGo auto-generates
// the `_initialize` export from the runtime; we don't declare it.
//
// Build:
//   tinygo build -gc=custom -scheduler=none -panic=trap -no-debug \
//       -target=wasm-unknown \
//       -o tests/mocks/mockrouter/bin/mock_router.wasm \
//       tests/mocks/mockrouter/main.go
//
// The resulting bin/mock_router.wasm is checked into git (gitignore
// exception) so tests don't depend on a tinygo install at run time.
package main

import (
	// SDK import is required for the wasm runtime's import section to
	// resolve. We don't actually call any SDK functions from this mock,
	// but the import has to be present so `_initialize` works.
	_ "ltc-mapping-contract/sdk"
)

func main() {}

// Always returns {"amount_out":"0", "pool_state":{...}} regardless of
// input. Drives ltc-mapping-contract into the BTC-C4 router-failure
// branch so the refund path can be observed.
//
//go:wasmexport execute
func Execute(_ *string) *string {
	const fixed = `{"amount_out":"0","pool_state":{"asset0":"BTC","asset1":"HBD","reserve0":"0","reserve1":"0","fee":0,"total_lp":"0"}}`
	s := fixed
	return &s
}
