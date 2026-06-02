// Pure-Go tests for workstream 5b validator-set lookup + governance
// timelock helpers. These test the payload parser only — the state
// reads/writes are exercised in the WASM-level integration suite when
// it lands (workstream 6 follow-up).
package current_test

import (
	"strings"
	"testing"

	"dash-mapping-contract/contract/mapping"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 96 hex chars = 48 bytes (the BLS12-381 G1 pubkey serialization size).
const validatorPubkey96 = "" +
	"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2" +
	"c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8"

func TestParseValidatorSetPayload_HappyPath(t *testing.T) {
	payload := "42;did:key:validator-1=" + validatorPubkey96 +
		"|did:key:validator-2=" + validatorPubkey96
	epoch, set, err := mapping.ParseValidatorSetPayload(payload)
	require.NoError(t, err)
	assert.Equal(t, uint64(42), epoch)
	assert.Len(t, set, 2)
	assert.Equal(t, validatorPubkey96, set["did:key:validator-1"])
	assert.Equal(t, validatorPubkey96, set["did:key:validator-2"])
}

func TestParseValidatorSetPayload_EmptyEntries(t *testing.T) {
	// Extra pipes / trailing pipe must be tolerated (skipped silently).
	payload := "1;did:key:v1=" + validatorPubkey96 + "||"
	epoch, set, err := mapping.ParseValidatorSetPayload(payload)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), epoch)
	assert.Len(t, set, 1)
}

func TestParseValidatorSetPayload_RejectsMissingSemicolon(t *testing.T) {
	_, _, err := mapping.ParseValidatorSetPayload("no-semicolon")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "<epoch>;<entries>")
}

func TestParseValidatorSetPayload_RejectsBadEpoch(t *testing.T) {
	_, _, err := mapping.ParseValidatorSetPayload("not-a-number;x=y")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid epoch")
}

func TestParseValidatorSetPayload_RejectsBadEntryShape(t *testing.T) {
	_, _, err := mapping.ParseValidatorSetPayload("0;no-equals")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing '='")
}

func TestParseValidatorSetPayload_RejectsEmptyComponents(t *testing.T) {
	cases := []string{
		"0;=" + validatorPubkey96, // empty did
		"0;did:key:v=",            // empty pubkey
	}
	for _, p := range cases {
		_, _, err := mapping.ParseValidatorSetPayload(p)
		assert.Error(t, err, "payload %q must reject", p)
	}
}

func TestParseValidatorSetPayload_RejectsShortPubkey(t *testing.T) {
	_, _, err := mapping.ParseValidatorSetPayload("0;did:key:v=deadbeef")
	assert.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "96 hex")
}

func TestSaveMinAttestations_RejectsZero(t *testing.T) {
	err := mapping.SaveMinAttestations(0)
	assert.Error(t, err)
}

func TestSaveMinAttestations_RejectsNegative(t *testing.T) {
	err := mapping.SaveMinAttestations(-5)
	assert.Error(t, err)
}
