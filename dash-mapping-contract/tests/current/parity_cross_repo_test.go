//go:build cross_repo
// +build cross_repo

// Cross-repo parity tests. These import vsc-node/modules/islock-attestation
// which is only available on go-vsc-node-develop (not on the upstream
// `replace` target pinned in go.mod). Default CI runs with the stable
// upstream target and skips this file; developers with go.work pointing
// at the local in-progress checkout can exercise it via:
//
//   go test -tags cross_repo ./tests/current/...
//
// Round-3 audit OP-001 — the previous default-tag inclusion poisoned
// the entire pure-Go test suite at compile time under documented CI
// mode. Build-tagging surfaces the dependency explicitly and gives
// operators a single `-tags cross_repo` knob.
package current_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"dash-mapping-contract/contract/mapping"

	islockinstruction "vsc-node/lib/islock-instruction"
	islock "vsc-node/modules/islock-attestation"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseInstructionV2_RoundTripFromRealISServiceBuilder — round-3
// audit R3-09. Imports the ACTUAL BuildAuth/BuildCallInstruction
// builders from vsc-node/lib/islock-instruction (the shared
// source-of-truth that cmd/is-service/session.go also calls) and runs
// them through the contract's ParseInstructionV2. Drift in either side
// fails this test — closing the gap where the round-2 inlined-closure
// test couldn't catch real IS-service refactors.
func TestParseInstructionV2_RoundTripFromRealISServiceBuilder(t *testing.T) {
	t.Run("auth", func(t *testing.T) {
		p, err := mapping.ParseInstructionV2(islockinstruction.BuildAuthInstruction("the-sid"))
		require.NoError(t, err)
		assert.Equal(t, "auth", p.Op)
		assert.Equal(t, "the-sid", p.Sid)
	})
	t.Run("call without amount", func(t *testing.T) {
		p, err := mapping.ParseInstructionV2(
			islockinstruction.BuildCallInstruction("vsc1Target", "swap", "Zm9v", "abc", 0))
		require.NoError(t, err)
		assert.Equal(t, "call", p.Op)
		assert.Equal(t, "vsc1Target", p.Target)
		assert.Equal(t, "swap", p.Method)
		assert.Equal(t, "Zm9v", p.ArgsB64)
		assert.Equal(t, "abc", p.Sid)
		assert.Equal(t, int64(0), p.AmountDuffs)
	})
	t.Run("call with amount", func(t *testing.T) {
		p, err := mapping.ParseInstructionV2(
			islockinstruction.BuildCallInstruction("vsc1Target", "swap", "Zm9v", "abc", 1234))
		require.NoError(t, err)
		assert.Equal(t, int64(1234), p.AmountDuffs)
	})
	t.Run("call with base64 padding", func(t *testing.T) {
		p, err := mapping.ParseInstructionV2(
			islockinstruction.BuildCallInstruction("vsc1Target", "swap", "aGVsbG8=", "abc", 0))
		require.NoError(t, err)
		assert.Equal(t, "aGVsbG8=", p.ArgsB64)
	})
}

// TestCanonicalAttestationMessage_ByteParityWithValidator — regression
// for the canonical-message-txid-byte-order-drift audit. Same
// (chainId, epoch, rawTxHex, instruction) → byte-identical 32-byte
// digests on contract + validator sides.
func TestCanonicalAttestationMessage_ByteParityWithValidator(t *testing.T) {
	chainID := "vsc-testnet"
	var epoch uint64 = 42
	rawTxBytes := []byte("a-fake-but-stable-raw-tx-payload-bytes-for-testing")
	rawTxHex := hex.EncodeToString(rawTxBytes)
	instruction := "op=auth;sid=parity-test"

	contractMsg, err := mapping.CanonicalAttestationMessage(chainID, epoch, rawTxHex, instruction)
	require.NoError(t, err)
	require.Len(t, contractMsg, 32)

	first := sha256.Sum256(rawTxBytes)
	internal := sha256.Sum256(first[:])
	displayHash := islock.ReverseBytesCopy(internal[:])
	instrHash := sha256.Sum256([]byte(instruction))

	req := islock.IsLockAttestationRequest{
		TxId:               hex.EncodeToString(displayHash),
		RawTxHashHex:       hex.EncodeToString(displayHash),
		InstructionHashHex: hex.EncodeToString(instrHash[:]),
		Epoch:              epoch,
		ChainId:            chainID,
	}
	validatorMsg, err := islock.CanonicalSigningMessage(req)
	require.NoError(t, err)

	assert.Equal(t, contractMsg, validatorMsg,
		"contract and validator MUST produce identical canonical-message digests; "+
			"drift here breaks every BLS aggregate verification")
}
