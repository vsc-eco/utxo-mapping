package mapping

import (
	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/sdk"
)

// MAP-CEI (15a): re-entrancy guard around this contract's single external call.
//
// See constants.ExternalCallGuardKey for why the window is dangerous and why
// the guard is selective rather than global.

// enterExternalCall marks an external contract call as in progress. Written to
// STATE, not memory, because a re-entrant call is a fresh wasm invocation with
// its own linear memory and would never see an in-process flag.
func enterExternalCall() {
	sdk.StateSetObject(constants.ExternalCallGuardKey, "1")
}

// exitExternalCall clears the guard once the external call has returned.
//
// Always reached: the call it brackets is TryContractCall, which reports a
// revert via its result instead of trapping, so there is no path where the
// callee's failure skips this. And if the enclosing handler later returns an
// error, the whole transaction reverts and the guard write reverts with it --
// the flag cannot be left stuck on across transactions in either direction.
func exitExternalCall() {
	sdk.StateSetObject(constants.ExternalCallGuardKey, "")
}

// InExternalCallGuard reports whether this invocation is re-entering while one
// of our own external calls is still outstanding.
func InExternalCallGuard() bool {
	v := sdk.StateGetObject(constants.ExternalCallGuardKey)
	return v != nil && *v == "1"
}
