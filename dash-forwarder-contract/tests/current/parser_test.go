// Pure-Go tests for the instruction parser and entry serialiser.
//
// These exercise the forwarder package directly (no WASM compilation
// required) so they run without TinyGo set up. The full WASM-level
// integration tests (which verify the call_as host-function gating
// end-to-end) come in a follow-up commit once we have a contract test
// fixture wired against vsc-node/lib/test_utils — see comment at the
// bottom of this file for the integration test we want to write next.
package current_test

import (
	"testing"

	"dash-forwarder-contract/contract/constants"
	"dash-forwarder-contract/contract/forwarder"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ----- ParseInstruction -----

func TestParseInstruction_OpCallHappyPath(t *testing.T) {
	in := "op=call;contract=vsc1DexRouter;method=swap;args=eyJpbiI6IkRBU0giLCJvdXQiOiJIQkQifQ==;sid=ab12;amount=100000000"
	got, err := forwarder.ParseInstruction(in)
	require.NoError(t, err)
	assert.Equal(t, "call", got.Op)
	assert.Equal(t, "vsc1DexRouter", got.Target)
	assert.Equal(t, "swap", got.Method)
	assert.Equal(t, "eyJpbiI6IkRBU0giLCJvdXQiOiJIQkQifQ==", got.ArgsB64)
	assert.Equal(t, "ab12", got.Sid)
	assert.Equal(t, int64(100000000), got.AmountDuffs)
}

func TestParseInstruction_OpCallValueLess(t *testing.T) {
	// op=call without amount = value-less. Amount must default to 0.
	in := "op=call;contract=vsc1NftContract;method=transfer;args=eyJ0byI6IngifQ==;sid=ab12"
	got, err := forwarder.ParseInstruction(in)
	require.NoError(t, err)
	assert.Equal(t, "call", got.Op)
	assert.Equal(t, int64(0), got.AmountDuffs, "value-less call must default amount to 0")
}

func TestParseInstruction_OpAuth(t *testing.T) {
	// op=auth is handled by mapping, not forwarder — but ParseInstruction
	// shouldn't reject it outright, just leave Target/Method empty.
	in := "op=auth;sid=login123"
	got, err := forwarder.ParseInstruction(in)
	require.NoError(t, err)
	assert.Equal(t, "auth", got.Op)
	assert.Empty(t, got.Target)
	assert.Empty(t, got.Method)
	assert.Equal(t, "login123", got.Sid)
}

func TestParseInstruction_RejectsEmpty(t *testing.T) {
	_, err := forwarder.ParseInstruction("")
	assert.Error(t, err)
}

func TestParseInstruction_RejectsMissingOp(t *testing.T) {
	_, err := forwarder.ParseInstruction("contract=vsc1X;method=swap;sid=ab12")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing op=")
}

func TestParseInstruction_RejectsMissingSid(t *testing.T) {
	_, err := forwarder.ParseInstruction("op=call;contract=vsc1X;method=swap")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing sid=")
}

func TestParseInstruction_OpCallRequiresContractAndMethod(t *testing.T) {
	_, err := forwarder.ParseInstruction("op=call;sid=ab12")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "contract= and method=")
}

func TestParseInstruction_BadFieldShape(t *testing.T) {
	_, err := forwarder.ParseInstruction("op=call;malformedfield;sid=ab12")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "delimiter")
}

func TestParseInstruction_BadAmount(t *testing.T) {
	_, err := forwarder.ParseInstruction("op=call;contract=v;method=m;sid=s;amount=notanumber")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "amount")
}

func TestParseInstruction_UnknownKeysIgnored(t *testing.T) {
	// Forwards-compatibility: future op-grammar keys should be ignored,
	// not rejected, by older deployments.
	in := "op=call;contract=v;method=m;args=a;sid=s;future_field=xyz"
	got, err := forwarder.ParseInstruction(in)
	require.NoError(t, err)
	assert.Equal(t, "v", got.Target)
}

// ----- SerializeForwardQueueEntry round-trip -----

func TestForwardQueueEntry_RoundTrip(t *testing.T) {
	entry := forwarder.ForwardQueueEntry{
		Sender:      "did:pkh:bip122:00000bafbc94add76cb75e2ec9289483:yExampleDashAddr",
		Instruction: "op=call;contract=vsc1Dex;method=swap;args=AAA=;sid=ab12;amount=100000000",
		CallFunding: 100_000_000,
		Status:      constants.StatusPendingForward,
	}
	serialized := forwarder.SerializeForwardQueueEntry(entry)
	assert.Contains(t, serialized, entry.Sender)
	assert.Contains(t, serialized, entry.Instruction)
	assert.Contains(t, serialized, constants.StatusPendingForward)
}

// ----- DecodeArgs -----

func TestDecodeArgs_HappyPathJSON(t *testing.T) {
	// Spec §5.2.1: args is base64-encoded so the instruction grammar
	// (`;` field separator, `=` field/value separator) stays unambiguous
	// regardless of payload content. The forwarder MUST decode it
	// before invoking the target.
	const payload = `{"in":"DASH","out":"HBD"}`
	// Same b64-encoded form used in TestParseInstruction_OpCallHappyPath.
	got, err := forwarder.DecodeArgs("eyJpbiI6IkRBU0giLCJvdXQiOiJIQkQifQ==")
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func TestDecodeArgs_HappyPathCommaSeparated(t *testing.T) {
	// call-tss test target uses a "key,value" raw form. Spec §5.2.1
	// requires b64-encoding for ANY shape (the b64 wrapper exists to
	// dodge `;`/`=` collisions in the instruction grammar, not because
	// the payload must be JSON).
	got, err := forwarder.DecodeArgs("b3Boayxvc3B2YWw=")
	require.NoError(t, err)
	assert.Equal(t, "ophk,ospval", got)
}

func TestDecodeArgs_EmptyIsLegitimate(t *testing.T) {
	// Value-less calls with no parameters (e.g. nft-mint with no
	// extra args) are legitimate; empty input must decode to empty
	// output without error.
	got, err := forwarder.DecodeArgs("")
	require.NoError(t, err)
	assert.Equal(t, "", got)
}

func TestDecodeArgs_RejectsMalformedBase64(t *testing.T) {
	// Garbage at the field boundary surfaces as ErrInput from
	// Execute(); the target is never invoked. Pre-fix the forwarder
	// passed `parsed.ArgsB64` verbatim to the target, which then
	// silently failed any parse step (e.g. setString's
	// strings.SplitN(",") returned 1 part, function returned
	// "invalid input", but the forwarder saw result!=nil and reported
	// a false-positive success — no state was written).
	for _, in := range []string{
		"not!valid base64",
		"abc",  // length not multiple of 4
		"abc==", // length-4 padding but invalid chars
	} {
		_, err := forwarder.DecodeArgs(in)
		assert.Error(t, err, "input %q should fail base64 decode", in)
	}
}

// ===== integration test scaffold (BUILD IT NEXT) =====
//
// The above tests cover the pure-Go parser. The integration test we want
// to add once the WASM compile is wired up (TinyGo + vsc-node go.work):
//
//   1. Deploy a mapping-contract stub that writes a known forwardQueue
//      entry to its state.
//   2. Deploy dash-forwarder-contract; call Init() with the mapping
//      contract id.
//   3. Add forwarder's contract id to system-config.TrustedForwarders.
//   4. Have the stub mapping invoke forwarder.execute(txid).
//   5. Verify the target contract receives the call with
//      effectiveCaller=<DashDID from the forwardQueue entry>.
//   6. Verify a non-mapping caller invoking execute() gets
//      ABORT:ErrNoPermission.
//   7. Verify execute() with a target not in allowedTargets gets
//      ABORT:ErrNoPermission.
//
// Once test_utils.NewContractTest supports the forwarder's deps
// (effectiveCaller exposed in callee env), this scaffold becomes a real
// test file alongside mapping_test.go.
