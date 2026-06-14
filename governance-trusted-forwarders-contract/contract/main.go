// governance-trusted-forwarders-contract — on-chain registry of contracts
// trusted by the magi protocol to invoke contracts.call_as (ERC-2771-style
// effective-caller override).
//
// Replaces the previous per-witness sysconfig.TrustedForwarders file as
// the canonical source above consensus version
// TrustedForwardersFromContractVersion. Sysconfig retains a subtract-only
// kill-switch (RevokedForwarders) for emergency operator response.
//
// See docs/dash-is-login/trusted-forwarders-governance.md for the full
// design spec.
//
// Build:
//
//	tinygo build -o bin/dev.wasm -gc=custom -scheduler=none -panic=trap \
//	    -no-debug -target=wasm-unknown contract/main.go
//
// Same tinygo caveats as the dash-mapping/forwarder contracts:
//   - no goroutines, channels, deferred functions
//   - panic() halts the program
//   - sdk import is required for build
package main

import (
	"strconv"

	ce "governance-trusted-forwarders-contract/contract/contracterrors"
	"governance-trusted-forwarders-contract/contract/governance"

	_ "governance-trusted-forwarders-contract/sdk" // ensure sdk is imported

	"governance-trusted-forwarders-contract/sdk"
)

// NetworkMode is set via ldflags at build time, mirroring the sibling
// contracts. The governance contract itself has no network-specific
// behaviour (no regtest seedInternalHbd-style escape), but the
// Makefile's TESTNETFLAGS/REGTESTFLAGS expect this symbol to link, so
// it's kept as a declared global. Could later gate a per-network
// admin-account convention if needed.
var NetworkMode string

// _ = NetworkMode silences "declared and not used" for the unused
// global; using the blank-identifier read is the canonical idiom.
var _ = NetworkMode

// sdkState bridges the contract's governance.State interface (which
// returns *string) to the sdk's StateGetObject (which already returns
// *string, so this is mostly identity adapters). Kept as a thin layer
// so the business logic in package governance is testable with a fake
// state and doesn't need to import sdk.
type sdkState struct{}

func (sdkState) Get(k string) *string { return sdk.StateGetObject(k) }
func (sdkState) Set(k, v string)      { sdk.StateSetObject(k, v) }
func (sdkState) Delete(k string)      { sdk.StateDeleteObject(k) }

// sdkEnv satisfies governance.Env via the wasmedge runtime env exports.
// Caller / owner / blockHeight are pulled from sdk.GetEnv() /
// GetEnvKey at the moment of the call — no caching, since each
// wasmexport runs in its own host execution.
type sdkEnv struct{}

func (sdkEnv) Caller() string {
	return sdk.GetEnv().Caller.String()
}
func (sdkEnv) ContractOwner() string {
	if o := sdk.GetEnvKey("contract.owner"); o != nil {
		return *o
	}
	return ""
}
func (sdkEnv) BlockHeight() uint64 {
	if h := sdk.GetEnvKey("block.height"); h != nil {
		v, err := strconv.ParseUint(*h, 10, 64)
		if err == nil {
			return v
		}
	}
	return 0
}

func store() *governance.Store {
	return &governance.Store{S: sdkState{}, Env: sdkEnv{}}
}

func strPtr(s string) *string { return &s }

func abort(err error) *string {
	return strPtr("ABORT:" + err.Error())
}

// ===== wasmexport entry points =====

//go:wasmexport proposeForwarder
//
// proposeForwarder queues a trusted-forwarder add. Admin-only.
//
// Payload: the contract id to propose, prefixed with "contract:"
//
//	e.g. "contract:vsc1BfLqQfYsefXiYvDooMJuESfrMsef28v8Pb"
//
// On success returns "0". On failure returns "ABORT:<reason>".
func ProposeForwarder(payload *string) *string {
	if payload == nil {
		return abort(ce.NewError(ce.ErrInput, "payload required"))
	}
	if err := governance.ProposeForwarder(store(), *payload); err != nil {
		return abort(err)
	}
	return strPtr("0")
}

//go:wasmexport cancelProposeForwarder
//
// cancelProposeForwarder withdraws a pending-add. Admin-only.
// Payload: the contract id (with "contract:" prefix). Returns "0" or ABORT.
func CancelProposeForwarder(payload *string) *string {
	if payload == nil {
		return abort(ce.NewError(ce.ErrInput, "payload required"))
	}
	if err := governance.CancelProposeForwarder(store(), *payload); err != nil {
		return abort(err)
	}
	return strPtr("0")
}

//go:wasmexport activateForwarder
//
// activateForwarder promotes a pending-add → active once the timelock has
// elapsed. ANY caller may invoke — the timelock is the security gate.
// Payload: the contract id (with "contract:" prefix). Returns "0" or ABORT.
func ActivateForwarder(payload *string) *string {
	if payload == nil {
		return abort(ce.NewError(ce.ErrInput, "payload required"))
	}
	if err := governance.ActivateForwarder(store(), *payload); err != nil {
		return abort(err)
	}
	return strPtr("0")
}

//go:wasmexport proposeRemoveForwarder
//
// proposeRemoveForwarder queues a trusted-forwarder remove. Admin-only.
// Payload: the contract id (with "contract:" prefix). Returns "0" or ABORT.
func ProposeRemoveForwarder(payload *string) *string {
	if payload == nil {
		return abort(ce.NewError(ce.ErrInput, "payload required"))
	}
	if err := governance.ProposeRemoveForwarder(store(), *payload); err != nil {
		return abort(err)
	}
	return strPtr("0")
}

//go:wasmexport cancelProposeRemoveForwarder
//
// cancelProposeRemoveForwarder withdraws a pending-remove. Admin-only.
// Payload: the contract id (with "contract:" prefix). Returns "0" or ABORT.
func CancelProposeRemoveForwarder(payload *string) *string {
	if payload == nil {
		return abort(ce.NewError(ce.ErrInput, "payload required"))
	}
	if err := governance.CancelProposeRemoveForwarder(store(), *payload); err != nil {
		return abort(err)
	}
	return strPtr("0")
}

//go:wasmexport activateRemoveForwarder
//
// activateRemoveForwarder promotes a pending-remove → deletion. ANY
// caller may invoke. Returns "0" or ABORT.
func ActivateRemoveForwarder(payload *string) *string {
	if payload == nil {
		return abort(ce.NewError(ce.ErrInput, "payload required"))
	}
	if err := governance.ActivateRemoveForwarder(store(), *payload); err != nil {
		return abort(err)
	}
	return strPtr("0")
}

//go:wasmexport emergencyRevoke
//
// emergencyRevoke immediately removes a forwarder from the active list,
// bypassing the timelock. Admin-only, gated on the EmergencyRevokeAllowed
// flag. For compromise / critical-bug response.
// Payload: the contract id (with "contract:" prefix). Returns "0" or ABORT.
func EmergencyRevoke(payload *string) *string {
	if payload == nil {
		return abort(ce.NewError(ce.ErrInput, "payload required"))
	}
	if err := governance.EmergencyRevoke(store(), *payload); err != nil {
		return abort(err)
	}
	return strPtr("0")
}

//go:wasmexport setTimelock
//
// setTimelock changes the propose→activate window. Admin-only.
// Payload: the new timelock in L1 blocks, as a decimal string.
// Bounds: ≥1 block, ≤30 days of L1 blocks. Returns "0" or ABORT.
func SetTimelock(payload *string) *string {
	if payload == nil {
		return abort(ce.NewError(ce.ErrInput, "payload required"))
	}
	v, err := strconv.ParseUint(*payload, 10, 64)
	if err != nil {
		return abort(ce.NewError(ce.ErrInput, "timelock not a valid uint64: "+*payload))
	}
	if err := governance.SetTimelock(store(), v); err != nil {
		return abort(err)
	}
	return strPtr("0")
}

//go:wasmexport setEmergencyRevokeAllowed
//
// setEmergencyRevokeAllowed flips the emergency-revoke kill-switch.
// Admin-only. Payload: "1" enables, "0" disables. Returns "0" or ABORT.
func SetEmergencyRevokeAllowed(payload *string) *string {
	if payload == nil {
		return abort(ce.NewError(ce.ErrInput, "payload required"))
	}
	switch *payload {
	case "0":
		if err := governance.SetEmergencyRevokeAllowed(store(), false); err != nil {
			return abort(err)
		}
	case "1":
		if err := governance.SetEmergencyRevokeAllowed(store(), true); err != nil {
			return abort(err)
		}
	default:
		return abort(ce.NewError(ce.ErrInput, "payload must be '0' or '1', got: "+*payload))
	}
	return strPtr("0")
}

// main is required for the tinygo wasm target. No-op — entry points are
// the //go:wasmexport-tagged functions above.
func main() {}
