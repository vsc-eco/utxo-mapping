// Mock DRAINING router — the VR2-23 regression fixture.
//
// The plain mockrouter reports `amount_out:"0"` WITHOUT touching its allowance,
// which exercises only the benign half of the router-failure path. This one is
// the adversarial half: it first PULLS the full allowance it was granted (an
// ordinary transferFrom, exactly what a compromised or buggy DEX router can do)
// and only THEN reports zero output.
//
// That combination is what made an earlier version of the VR2-23 refund unsafe:
// the refund decided how much to return by reading the mapping contract's
// AGGREGATE balance, which is a shared account across every deposit. A drained
// swap could therefore be "refunded" out of an unrelated depositor's stranded
// credit — paying the same sats twice and zeroing an innocent third party.
//
// With the provenance-based refund (unspent allowance for THIS swap), a router
// that consumed everything must produce a refund of ZERO.
//
// Build (ids are fixed at build time because the test controls both):
//   tinygo build -gc=custom -scheduler=none -panic=trap -no-debug \
//       -target=wasm-unknown \
//       -o tests/mocks/mockdrainrouter/bin/mock_drain_router.wasm \
//       tests/mocks/mockdrainrouter/main.go
package main

import (
	"btc-mapping-contract/sdk"
)

func main() {}

// Must match the ids the test registers.
const (
	mappingContractId = "btc_map_drain_test"
	attacker          = "hive:evildrain"
	pullAmount        = "333333"
)

//go:wasmexport execute
func Execute(_ *string) *string {
	// Pull the whole allowance to the attacker, then claim the swap produced
	// nothing. A genuine transferFrom — no exploit of the transfer mechanism.
	payload := `{"amount":"` + pullAmount + `","to":"` + attacker + `","from":"contract:` + mappingContractId + `"}`
	sdk.ContractCall(mappingContractId, "transferFrom", payload, nil)

	const fixed = `{"amount_out":"0","pool_state":{"asset0":"BTC","asset1":"HBD","reserve0":"0","reserve1":"0","fee":0,"total_lp":"0"}}`
	s := fixed
	return &s
}
