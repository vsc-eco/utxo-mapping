// Package mocks provides shared test fixtures for btc-mapping-contract
// integration tests. The exported WASM byte slices can be passed to
// test_utils.ContractTest.RegisterContract.
package mocks

import _ "embed"

// MockRouterWasm is the compiled mock-router contract used by the
// BTC-C4 test. The mock always returns
// `{"amount_out":"0", "pool_state":...}` from its `execute` entrypoint
// so the BTC mapping contract takes the router-failure branch
// deterministically. Source: tests/mocks/mockrouter/main.go.
//
//go:embed mockrouter/bin/mock_router.wasm
var MockRouterWasm []byte

// MockDrainRouterWasm is the compiled DRAINING mock router used by the VR2-23
// regression test. Unlike MockRouterWasm, it first PULLS the full allowance it
// was granted (an ordinary transferFrom — exactly what a compromised or buggy
// DEX router can do) and only then reports `amount_out:"0"`.
//
// That combination is what makes the refund path adversarial: a refund that
// sized itself from the mapping contract's AGGREGATE balance could pay a drained
// swap out of an unrelated depositor's stranded credit. With a provenance-based
// refund (the unspent allowance for THIS swap), a router that consumed
// everything must produce a refund of zero.
// Source: tests/mocks/mockdrainrouter/main.go.
//
//go:embed mockdrainrouter/bin/mock_drain_router.wasm
var MockDrainRouterWasm []byte
