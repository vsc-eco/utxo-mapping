// dash-forwarder-contract is the ERC-2771-style trusted forwarder for
// the Dash InstantSend login feature. See README.md and the design spec
// at magi/testnet/docs/superpowers/specs/2026-05-14-...-design.md §5.3.
//
// Build command:
//
//	tinygo build -o bin/dev.wasm -gc=custom -scheduler=none -panic=trap -no-debug \
//	    -target=wasm-unknown -ldflags="-X 'main.NetworkMode=regtest'" contract/main.go
//
// Caveats inherited from the dash-mapping-contract pattern:
//   - Goroutines, channels, and defer are disabled
//   - panic() always halts the program
//   - sdk import is required for build
//   - exported entry points use //go:wasmexport
package main

import (
	"dash-forwarder-contract/contract/constants"
	ce "dash-forwarder-contract/contract/contracterrors"
	"dash-forwarder-contract/contract/forwarder"
	_ "dash-forwarder-contract/sdk" // ensure sdk is imported

	"dash-forwarder-contract/sdk"
)

// NetworkMode is set via ldflags at build time:
//   - "" (default) → mainnet
//   - "testnet"    → testnet
//   - "regtest"    → regression test
var NetworkMode string

// checkOracleOrAdmin gates admin-only entry points to either the oracle
// (system entity that bootstraps state) or the contract owner during
// testnet/regtest.
func checkOracleOrAdmin() error {
	env := sdk.GetEnv()
	caller := env.Caller.String()
	owner := env.ContractOwner
	if caller == owner {
		return nil
	}
	// In a future revision, also accept a configurable governance multisig.
	return ce.NewError(ce.ErrNoPermission, "admin action requires contract owner; got "+caller)
}

//go:wasmexport init
//
// init sets the canonical dash-mapping-contract id. Must be called once
// at deployment by the contract owner.
//
// Payload: the mapping contract id (e.g. "vsc1...").
func Init(payload *string) *string {
	if err := checkOracleOrAdmin(); err != nil {
		return strPtr("ABORT:" + err.Error())
	}
	if payload == nil || *payload == "" {
		return strPtr("ABORT:" + ce.NewError(ce.ErrInput, "mapping contract id required").Error())
	}
	// Idempotent: re-init with same id is a no-op.
	existing := sdk.StateGetObject(constants.DashMappingContractIdStateKey)
	if existing != nil && *existing != "" && *existing == *payload {
		return strPtr("ok:idempotent")
	}
	if existing != nil && *existing != "" && *existing != *payload {
		return strPtr("ABORT:" + ce.NewError(ce.ErrInput, "mapping contract id already set; re-init must use same value").Error())
	}
	sdk.StateSetObject(constants.DashMappingContractIdStateKey, *payload)
	return strPtr("ok:" + *payload)
}

//go:wasmexport execute
//
// execute is the forwarder's only externally-callable action. Per spec
// §5.3, it MUST only be invokable by the registered dash-mapping-contract.
// Any other caller is rejected.
//
// Payload: the Dash transaction id (txid) whose forwardQueue entry to
// process. Mapping contract calls this synchronously inside its
// mapInstantSend execution with the matching txid.
func Execute(payload *string) *string {
	if payload == nil || *payload == "" {
		return strPtr("ABORT:" + ce.NewError(ce.ErrInput, "txid required").Error())
	}
	if err := forwarder.Execute(*payload); err != nil {
		return strPtr("ABORT:" + err.Error())
	}
	return strPtr("ok:" + *payload)
}

func strPtr(s string) *string {
	return &s
}

// main is required by TinyGo's wasm-unknown target but never runs in
// the WASM contract — entry points are wasmexport-ed functions.
func main() {}
