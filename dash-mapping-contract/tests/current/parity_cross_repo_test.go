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
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"dash-mapping-contract/contract/mapping"

	"vsc-node/lib/dids"
	islockinstruction "vsc-node/lib/islock-instruction"
	islock "vsc-node/modules/islock-attestation"

	ethBls "github.com/protolambda/bls12-381-util"
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

// TestValidatorSetPayload_PoPMessageMatchesLibDids — round-4 audit
// R4-CSM-01 regression. Reconstructs the exact bytes that
// dids.GenerateBlsPoP signs and verifies a real PoP through the
// contract's ParseValidatorSetPayload → reproduce-message pipeline
// (we re-implement the verify step here because sdk.VerifyBls is a
// wasm host-fn unavailable to pure-Go tests; the message-binding
// equivalence is what we are pinning).
//
// If announcements.go's PoP message binding diverges from the
// contract's ParseValidatorSetPayload expectations (account vs DID),
// this test will fail and prevent the previously-shipped silent break.
func TestValidatorSetPayload_PoPMessageMatchesLibDids(t *testing.T) {
	// Stable 32-byte seed for determinism; the secret doesn't matter
	// for the parity assertion, only that we can produce a real PoP.
	seed := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	privKey := dids.BlsPrivKey{}
	err := privKey.Deserialize(&seed)
	require.NoError(t, err)
	pubKey, err := ethBls.SkToPk(&privKey)
	require.NoError(t, err)
	did, err := dids.NewBlsDID(pubKey)
	require.NoError(t, err)

	account := "tibfox"
	popB64, err := dids.GenerateBlsPoP(&privKey, account)
	require.NoError(t, err)

	// VerifyBlsPoP exercises the canonical PoP message binding from
	// lib/dids — any drift there is caught immediately.
	require.NoError(t, dids.VerifyBlsPoP(did, account, popB64))

	// Now reproduce the exact bytes the contract's
	// SaveValidatorSetForEpoch passes to sdk.VerifyBls and assert that
	// running the same BLS verify against them succeeds. This pins
	// account-binding to the wire-form the parser produces.
	pkBytes := pubKey.Serialize()
	const blsPoPDomain = "VSC-BLS-POP-v1"
	var msgBuf bytes.Buffer
	msgBuf.WriteString(blsPoPDomain)
	msgBuf.Write(pkBytes[:])
	msgBuf.WriteString(account)
	contractMsg := msgBuf.Bytes()

	popRaw, err := base64.RawURLEncoding.DecodeString(popB64)
	require.NoError(t, err)
	require.Len(t, popRaw, 96)
	sig := new(ethBls.Signature)
	var sigArr [96]byte
	copy(sigArr[:], popRaw)
	require.NoError(t, sig.Deserialize(&sigArr))
	assert.True(t, ethBls.Verify(pubKey, contractMsg, sig),
		"contract-reconstructed PoP message MUST verify against the announcer's "+
			"GenerateBlsPoP output — divergence here means validator-set "+
			"registration will reject every honest validator (audit R4-CSM-01)")

	// And the payload parser must accept a hex-encoded version of
	// the same PoP — round-trip through ParseValidatorSetPayload.
	popHex := hex.EncodeToString(popRaw)
	pkHex := hex.EncodeToString(pkBytes[:])
	payload := "7;" + did.String() + "=" + pkHex + "=" + popHex + "=" + account
	epoch, dToPk, dToPop, dToAccount, err := mapping.ParseValidatorSetPayload(payload)
	require.NoError(t, err)
	assert.Equal(t, uint64(7), epoch)
	assert.Equal(t, pkHex, dToPk[did.String()])
	assert.Equal(t, popHex, dToPop[did.String()])
	assert.Equal(t, account, dToAccount[did.String()])
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
