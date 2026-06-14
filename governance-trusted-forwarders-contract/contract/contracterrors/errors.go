// Package contracterrors is a tiny error wrapper for the governance-
// trusted-forwarders contract. Mirrors the same error-code conventions
// the dash-mapping-contract and dash-forwarder-contract use so external
// tooling that parses ABORT messages doesn't need a separate code path
// per contract.
package contracterrors

import "errors"

// Error code constants — keep stable, external tooling parses them.
const (
	ErrNoPermission   = "ErrNoPermission"
	ErrStateAccess    = "ErrStateAccess"
	ErrInput          = "ErrInput"
	ErrInitialization = "ErrInitialization"
	ErrTimelock       = "ErrTimelock"
	ErrConflict       = "ErrConflict"
)

// NewError builds a tagged error. First arg is the code, rest are joined
// as the detail.
func NewError(code string, detail ...string) error {
	msg := code
	for _, d := range detail {
		if d != "" {
			msg += ": " + d
		}
	}
	return errors.New(msg)
}
