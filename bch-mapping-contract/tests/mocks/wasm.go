// Package mocks provides shared test fixtures for bch-mapping-contract
// integration tests. The exported WASM byte slices can be passed to
// test_utils.ContractTest.RegisterContract.
package mocks

import _ "embed"

// MockRouterWasm is the compiled mock-router contract used by the
// BTC-C4 test. The mock always returns
// `{"amount_out":"0", "pool_state":...}` from its `execute` entrypoint
// so the BCH mapping contract takes the router-failure branch
// deterministically. Source: tests/mocks/mockrouter/main.go.
//
//go:embed mockrouter/bin/mock_router.wasm
var MockRouterWasm []byte
