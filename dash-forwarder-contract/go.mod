module dash-forwarder-contract

go 1.25.7

// DO NOT modify by hand for routine updates — bump the replace target when
// upgrading vsc-node. For local dev against the in-progress feature branch,
// add a go.work file (gitignored) pointing at the local go-vsc-node-develop:
//
//   // go.work — gitignored, NOT committed
//   go 1.25.6
//   use .
//   use ../../../../go-vsc-node-develop
//
// This is required to consume the new contracts.call_as host function from
// modules/wasm/sdk/sdk.go that this contract depends on.
replace vsc-node => github.com/vsc-eco/go-vsc-node v0.0.0-20260602002529-75c384f4f95f

replace github.com/agl/ed25519 => github.com/binance-chain/edwards25519 v0.0.0-20200305024217-f36fc4b53d43

require (
	github.com/CosmWasm/tinyjson v0.9.0
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
