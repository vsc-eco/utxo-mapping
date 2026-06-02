// Pure-Go tests for workstream 5b validator-set lookup + governance
// timelock helpers. These test the payload parser only — the state
// reads/writes (including PoP verify) are exercised in the WASM-level
// integration suite when it lands (workstream 6 follow-up).
//
// Round-3 audit R3-001: payload format now requires PoP per entry.
// Round-4 audit R4-CSM-01: payload format now ALSO carries the
// validator's Hive account so the contract can reconstruct
// lib/dids/bls.go's canonical PoP message:
//
//	<epoch>;<did1>=<pubkey1>=<pop1>=<account1>|...
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

// 192 hex chars = 96 bytes (the BLS12-381 G2 signature serialization size).
// This is a syntactically-valid hex-length value used to exercise the
// PARSER. WASM-level PoP verification (sdk.VerifyBls) is exercised in
// the integration suite — the parser only enforces length+presence.
const validatorPoP192 = validatorPubkey96 + validatorPubkey96

const validatorAccount1 = "tibfox"
const validatorAccount2 = "magi.contracts"

func TestParseValidatorSetPayload_HappyPath(t *testing.T) {
	payload := "42;did:key:validator-1=" + validatorPubkey96 + "=" + validatorPoP192 + "=" + validatorAccount1 +
		"|did:key:validator-2=" + validatorPubkey96 + "=" + validatorPoP192 + "=" + validatorAccount2
	epoch, set, pops, accounts, err := mapping.ParseValidatorSetPayload(payload)
	require.NoError(t, err)
	assert.Equal(t, uint64(42), epoch)
	assert.Len(t, set, 2)
	assert.Len(t, pops, 2)
	assert.Len(t, accounts, 2)
	assert.Equal(t, validatorPubkey96, set["did:key:validator-1"])
	assert.Equal(t, validatorPubkey96, set["did:key:validator-2"])
	assert.Equal(t, validatorPoP192, pops["did:key:validator-1"])
	assert.Equal(t, validatorAccount1, accounts["did:key:validator-1"])
	assert.Equal(t, validatorAccount2, accounts["did:key:validator-2"])
}

func TestParseValidatorSetPayload_EmptyEntries(t *testing.T) {
	// Extra pipes / trailing pipe must be tolerated (skipped silently).
	payload := "1;did:key:v1=" + validatorPubkey96 + "=" + validatorPoP192 + "=" + validatorAccount1 + "||"
	epoch, set, _, _, err := mapping.ParseValidatorSetPayload(payload)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), epoch)
	assert.Len(t, set, 1)
}

func TestParseValidatorSetPayload_RejectsMissingSemicolon(t *testing.T) {
	_, _, _, _, err := mapping.ParseValidatorSetPayload("no-semicolon")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "<epoch>;<entries>")
}

func TestParseValidatorSetPayload_RejectsBadEpoch(t *testing.T) {
	_, _, _, _, err := mapping.ParseValidatorSetPayload("not-a-number;x=y=z=q")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid epoch")
}

// Round-3 audit R3-001: legacy 2-field <did>=<pubkey> entries must
// now be rejected; the parser requires PoP. Round-4 audit R4-CSM-01:
// 3-field entries are ALSO rejected — the parser now requires account
// to bind the PoP correctly.
func TestParseValidatorSetPayload_RejectsTwoFieldLegacyFormat(t *testing.T) {
	_, _, _, _, err := mapping.ParseValidatorSetPayload("0;did:key:v=" + validatorPubkey96)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "<did>=<pubkey>=<pop>=<account>")
}

func TestParseValidatorSetPayload_RejectsThreeFieldLegacyFormat(t *testing.T) {
	_, _, _, _, err := mapping.ParseValidatorSetPayload("0;did:key:v=" + validatorPubkey96 + "=" + validatorPoP192)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "<did>=<pubkey>=<pop>=<account>")
}

func TestParseValidatorSetPayload_RejectsEmptyComponents(t *testing.T) {
	cases := []string{
		"0;=" + validatorPubkey96 + "=" + validatorPoP192 + "=" + validatorAccount1, // empty did
		"0;did:key:v==" + validatorPoP192 + "=" + validatorAccount1,                 // empty pubkey
		"0;did:key:v=" + validatorPubkey96 + "==" + validatorAccount1,               // empty pop
		"0;did:key:v=" + validatorPubkey96 + "=" + validatorPoP192 + "=",            // empty account
	}
	for _, p := range cases {
		_, _, _, _, err := mapping.ParseValidatorSetPayload(p)
		assert.Error(t, err, "payload %q must reject", p)
	}
}

func TestParseValidatorSetPayload_RejectsShortPubkey(t *testing.T) {
	_, _, _, _, err := mapping.ParseValidatorSetPayload("0;did:key:v=deadbeef=" + validatorPoP192 + "=" + validatorAccount1)
	assert.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "96 hex")
}

func TestParseValidatorSetPayload_RejectsShortPoP(t *testing.T) {
	_, _, _, _, err := mapping.ParseValidatorSetPayload("0;did:key:v=" + validatorPubkey96 + "=deadbeef=" + validatorAccount1)
	assert.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "192 hex")
}

// Round-5 audit R5-ADV-02: account charset/length validation.
func TestParseValidatorSetPayload_RejectsAccountLength(t *testing.T) {
	cases := []string{
		"ab",                       // too short
		"abcdefghijklmnopq",        // too long (17 > 16)
	}
	for _, account := range cases {
		_, _, _, _, err := mapping.ParseValidatorSetPayload(
			"0;did:key:v=" + validatorPubkey96 + "=" + validatorPoP192 + "=" + account)
		assert.Error(t, err, "account %q must reject (length)", account)
		assert.Contains(t, strings.ToLower(err.Error()), "length")
	}
}

func TestParseValidatorSetPayload_RejectsAccountCharset(t *testing.T) {
	cases := []string{
		"Mallory",        // uppercase
		"alice|smuggle",  // pipe
		"alice=smuggle",  // equals (smuggling delimiter)
		"alice/bob",      // slash
		"al ice",         // space
	}
	for _, account := range cases {
		_, _, _, _, err := mapping.ParseValidatorSetPayload(
			"0;did:key:v=" + validatorPubkey96 + "=" + validatorPoP192 + "=" + account)
		assert.Error(t, err, "account %q must reject (charset)", account)
	}
}

// Round-7 audit R7-DRIFT-04 — pin every R6-CORR-06 Hive consensus
// rule so a future refactor of validateHiveAccountSegment can't
// silently re-relax the grammar.
func TestValidateHiveAccount(t *testing.T) {
	cases := []struct {
		name    string
		account string
		ok      bool
	}{
		// Happy path — common Hive usernames.
		{"3-char", "abc", true},
		{"6-char", "tibfox", true},
		{"two-segment", "magi.contracts", true},
		{"16-char", "abcde.fghij.klmn", true},
		{"hyphen-inside", "magi-prod.bot", true},
		{"trailing-digit", "alice123", true},

		// Length boundaries.
		{"too-short-2", "ab", false},
		{"too-long-17", "abcdefghijklmnopq", false},
		{"empty", "", false},
		{"single-segment-2", "az.def", false}, // 'az' segment <3

		// Charset.
		{"uppercase", "Mallory", false},
		{"underscore", "alice_bob", false},
		{"shell-pipe", "alice|smuggle", false},
		{"shell-equals", "alice=smuggle", false},
		{"slash", "alice/bob", false},
		{"space", "al ice", false},
		{"nul-byte", "alice\x00bob", false},
		{"newline", "alice\nbob", false},
		{"tab", "alice\tbob", false},
		{"multibyte-utf8", "aliceé", false},

		// Segment-shape rules.
		{"leading-dot", ".alice", false},
		{"trailing-dot", "alice.", false},
		{"consecutive-dots", "al..ice", false},
		{"leading-digit", "1alice", false},
		{"leading-hyphen", "-alice", false},
		{"trailing-hyphen", "alice-", false},
		{"segment-trailing-hyphen", "ali-.bcd", false},
		{"segment-leading-digit", "alice.1bob", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := mapping.ValidateHiveAccount(c.account)
			if c.ok {
				assert.NoError(t, err, "account %q should be accepted", c.account)
			} else {
				assert.Error(t, err, "account %q should be rejected", c.account)
			}
		})
	}
}

func TestSaveMinAttestations_RejectsZero(t *testing.T) {
	err := mapping.SaveMinAttestations(0)
	assert.Error(t, err)
}

func TestSaveMinAttestations_RejectsNegative(t *testing.T) {
	err := mapping.SaveMinAttestations(-5)
	assert.Error(t, err)
}
