// Package contracterrors is a tiny error wrapper for the forwarder contract.
// Modeled on dash-mapping-contract's contracterrors package — kept separate
// so the forwarder doesn't depend on mapping at the Go-module level.
package contracterrors

import "errors"

// Error code constants mirror the dash-mapping-contract codes that the
// indexer/oracle expect to see. Keep these strings stable — any abort
// message starting with one of these is parsed by external tooling.
const (
	ErrNoPermission   = "ErrNoPermission"
	ErrStateAccess    = "ErrStateAccess"
	ErrInput          = "ErrInput"
	ErrInitialization = "ErrInitialization"
	ErrTransaction    = "ErrTransaction"
)

// NewError builds a tagged error. The first string is the code; the rest
// are joined as the detail message.
func NewError(code string, detail ...string) error {
	msg := code
	for _, d := range detail {
		if d != "" {
			msg += ": " + d
		}
	}
	return errors.New(msg)
}
