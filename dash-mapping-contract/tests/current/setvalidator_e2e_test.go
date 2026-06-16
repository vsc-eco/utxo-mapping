//go:build cross_repo
// +build cross_repo

// Round-13/14 follow-up — DEVNET-EQUIVALENT integration tests for
// the IS-login validator-set admin path. These run the contract
// wasm through the real test_utils host emulator (same harness the
// existing mapping_test.go uses) — which means the host crypto
// fn crypto.bls_verify is the actual BLS12-381 pairing check, NOT
// a stub. So when we call setValidatorSet with a real
// dids.GenerateBlsPoP-produced PoP, the contract's verifier
// performs real BLS verification end-to-end.
//
// This is the strongest possible "did our R4-CSM-01 critical fix
// actually work?" test short of a full docker-multi-node devnet —
// and unlike the docker devnet test (which keeps failing on a
// libp2p-bootstrap-during-deploy infra flake), this exercises the
// actual code path the audit loop hardened.
//
// Covers:
//   - R4-CSM-01: 4-field payload + account-bound PoP verifies end-to-end
//   - R4-CSM-01 negative: forged pubkey → BLS PoP reject
//   - R4-CSM-01 negative: forged account → BLS PoP reject (proves
//     account is genuinely part of the signed message)
//   - R6-CORR-06: ValidateHiveAccount rejects bad-shape accounts
//     BEFORE the PoP check (cheap fail-fast)
//   - admin gate: non-owner caller → reject

package current_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"dash-mapping-contract/contract/constants"

	"vsc-node/lib/dids"
	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	ethBls "github.com/protolambda/bls12-381-util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dashMappingContract "dash-mapping-contract"
)

// Use the same wasm constant the sibling tests use.
var contractWasmE2E = dashMappingContract.DevWasm

// Round-14 audit R14-WASM-NOT-COMMITTED-NONDETERMINISTIC: bin/dev.wasm
// is gitignored (.gitignore: '*.wasm') and contract_bytes.go's loader
// silently sets DevWasm=nil when the file isn't present. Without a
// nil-check the cross_repo E2E suite would fail with an opaque
// RegisterContract panic on a fresh clone where `make dev` hasn't
// been run. This helper fails the test loudly with the exact build
// hint so the operator knows to run `USE_DOCKER=1 make dev`.
func requireFreshDevWasm(t *testing.T) {
	t.Helper()
	if len(contractWasmE2E) == 0 {
		t.Fatalf("dash-mapping-contract DevWasm is empty/missing.\n" +
			"Build it first:\n" +
			"  cd dash-mapping-contract && USE_DOCKER=1 make dev\n" +
			"bin/dev.wasm is gitignored so a fresh checkout needs to " +
			"rebuild before this cross_repo suite can run. See " +
			"DEVELOPING.md §'Cross-repo parity tests'.")
	}
}

// validatorKeypair holds everything we need to build a wire-form
// payload entry: BLS DID string, hex pubkey, hex PoP signed over
// (domain || pkBytes || accountBytes).
type validatorKeypair struct {
	priv    *dids.BlsPrivKey
	pub     *ethBls.Pubkey
	did     dids.BlsDID
	pkHex   string
	account string
}

// makeValidatorKey deterministically derives a BLS keypair from a 32-byte
// seed, then builds the announcer-side PoP (base64 raw-url) and converts
// it to the hex form the contract verifier expects.
func makeValidatorKey(t *testing.T, seedByte byte, account string) (*validatorKeypair, string) {
	t.Helper()
	var seed [32]byte
	for i := range seed {
		seed[i] = seedByte
	}
	priv := &dids.BlsPrivKey{}
	require.NoError(t, priv.Deserialize(&seed))
	pub, err := ethBls.SkToPk(priv)
	require.NoError(t, err)
	did, err := dids.NewBlsDID(pub)
	require.NoError(t, err)

	popB64, err := dids.GenerateBlsPoP(priv, account)
	require.NoError(t, err)
	popRaw, err := base64.RawURLEncoding.DecodeString(popB64)
	require.NoError(t, err)
	require.Len(t, popRaw, 96)
	popHex := hex.EncodeToString(popRaw)

	pkBytes := pub.Serialize()
	pkHex := hex.EncodeToString(pkBytes[:])
	return &validatorKeypair{priv: priv, pub: pub, did: did, pkHex: pkHex, account: account}, popHex
}

// adminOwner is the hive account that owns the contract in every
// test. Diverges intentionally from sibling tests
// (mapping_test.go / blocklist_test.go / confirm_spend_test.go /
// edge_cases_test.go all use 'hive:milo-hpr') — the IS-login
// validator-set surface ships against the testnet/mainnet deployer
// identity 'hive:magi.contracts' (see MEMORY/vsc_contract_deployment).
// R14-DRIFT-ADMIN-OWNER-CONVENTION-WRONG-COMMENT closed the prior
// "matches the existing mapping_test.go convention" misleading comment.
const adminOwner = "hive:magi.contracts"

// epochE2E is the validator-set epoch under test; chosen to avoid
// collision with any constant the sibling tests preseed.
const epochE2E = uint64(7)

// makeContractTest spins up a fresh wasm-execution harness with the
// admin pubkeys pre-set so the wasmexport's checkAdmin gate accepts
// adminOwner as the caller.
func makeContractTest(t *testing.T) (test_utils.ContractTest, string) {
	t.Helper()
	// R14-WASM-NOT-COMMITTED-NONDETERMINISTIC fail-fast.
	requireFreshDevWasm(t)
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractID := "valset_e2e_contract"
	ct.RegisterContract(contractID, adminOwner, contractWasmE2E)
	return ct, contractID
}

func callSetValidatorSet(
	t *testing.T,
	ct *test_utils.ContractTest,
	contractID, caller, payload string,
) test_utils.ContractTestCallResult {
	t.Helper()
	// The wasmexport signature is `func SetValidatorSet(payload *string) *string`.
	// The framework passes the raw bytes from Payload (json.RawMessage)
	// straight through to the *string argument WITHOUT JSON-decoding,
	// so we wrap our raw `<epoch>;<did>=...` payload as RawMessage
	// directly (mirrors the modules/wasm/e2e fuzz harness pattern).
	return ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "tx-set-valset",
			BlockId:              "block:valset",
			Index:                42,
			OpIndex:              0,
			Timestamp:            "2026-06-03T00:00:00",
			RequiredAuths:        []string{caller},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractID,
		Action:     "setValidatorSet",
		Payload:    json.RawMessage([]byte(payload)),
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
		Caller:     caller,
	})
}

func TestSetValidatorSet_RealPoP_AcceptsValidEntry(t *testing.T) {
	ct, contractID := makeContractTest(t)
	vk, popHex := makeValidatorKey(t, 0x11, "tibfox")

	payload := buildEntry(epochE2E, vk.did.String(), vk.pkHex, popHex, vk.account)
	r := callSetValidatorSet(t, &ct, contractID, adminOwner, payload)
	assert.True(t, r.Success,
		"real-PoP setValidatorSet must succeed; err=%q errMsg=%q", r.Err, r.ErrMsg)

	// State must now hold the validator set under the epoch key.
	// Format is "<registeredAt>#<did>=<pk>|<did>=<pk>|..." — we
	// just confirm the DID and pubkey hex appear in the stored value.
	stateKey := constants.ValidatorSetKeyPrefix + "7"
	stored := ct.StateGet(contractID, stateKey)
	require.NotEmpty(t, stored, "validator set not written to state at key %q", stateKey)
	assert.Contains(t, stored, vk.did.String(),
		"stored validator-set value must contain the registered DID")
	assert.Contains(t, stored, vk.pkHex,
		"stored validator-set value must contain the registered pubkey hex")
}

func TestSetValidatorSet_RealPoP_RejectsForgedPubkey(t *testing.T) {
	ct, contractID := makeContractTest(t)

	// Generate a valid PoP for keyA, then swap in keyB's pubkey on
	// the wire. The contract verifier reconstructs
	// (domain || keyB.pubBytes || account) and tries to verify
	// keyA's signature against it — must fail.
	vkA, popHex := makeValidatorKey(t, 0x22, "tibfox")
	vkB, _ := makeValidatorKey(t, 0x33, "tibfox")

	payload := buildEntry(epochE2E, vkA.did.String(), vkB.pkHex, popHex, vkA.account)
	r := callSetValidatorSet(t, &ct, contractID, adminOwner, payload)
	require.False(t, r.Success, "PoP-vs-pubkey mismatch must be rejected; got success")
	// Reject reason MUST be the BLS-verify failure path — not a
	// parse error. Confirms the contract reached SaveValidatorSetForEpoch
	// and the host crypto.bls_verify host fn returned false.
	// Round-14 audit R14-BLS-ERROR-STRING-BRITTLE: assert against the
	// exported prefix constant so a future reword that keeps the
	// security property intact stays green.
	assert.True(t,
		strings.HasPrefix(r.ErrMsg, constants.ErrPrefixBlsPoPVerifyFailed),
		"reject must come from BLS verify (prefix %q), not parse; got %q",
		constants.ErrPrefixBlsPoPVerifyFailed, r.ErrMsg)
}

func TestSetValidatorSet_RealPoP_RejectsForgedAccount(t *testing.T) {
	ct, contractID := makeContractTest(t)

	// Generate a valid PoP bound to "tibfox", then swap the account
	// field to "magi.witness" on the wire. The contract verifier
	// reconstructs (domain || pkBytes || "magi.witness") — must fail
	// because the signature was over "tibfox". This proves the R4
	// fix actually binds the account into the signed message.
	vk, popHex := makeValidatorKey(t, 0x44, "tibfox")
	forgedAccount := "magi.witness"
	require.NotEqual(t, vk.account, forgedAccount)

	payload := buildEntry(epochE2E, vk.did.String(), vk.pkHex, popHex, forgedAccount)
	r := callSetValidatorSet(t, &ct, contractID, adminOwner, payload)
	require.False(t, r.Success, "PoP-vs-account mismatch must be rejected; got success")
	// Account is part of the BLS-signed message (R4-CSM-01 critical
	// fix); the contract MUST reject at the bls_verify step, not at
	// some earlier parse/length gate. This is the strongest
	// regression-pin for the round-4 critical bug. Round-14 audit
	// R14-BLS-ERROR-STRING-BRITTLE: assert via the exported prefix.
	assert.True(t,
		strings.HasPrefix(r.ErrMsg, constants.ErrPrefixBlsPoPVerifyFailed),
		"reject must come from BLS verify (prefix %q), not parse; got %q",
		constants.ErrPrefixBlsPoPVerifyFailed, r.ErrMsg)
}

func TestSetValidatorSet_RejectsBadHiveAccountShape(t *testing.T) {
	// R6-CORR-06 ValidateHiveAccount runs at parse time, after the
	// pop-length gate. Round-14 audit R14-TEST-FAKEPOP-WRONG-LENGTH:
	// the previous constant was 160 hex chars (64+64+32), not 192,
	// so the parser short-circuited at the pop-length gate
	// BEFORE reaching validateHiveAccount — a regression that
	// deleted validateHiveAccount entirely would still pass this
	// test. The constant below is now a real 192 hex chars
	// (64+64+64) so the parser advances to the account check, and
	// we also tighten the assertion to require the
	// invalid-Hive-account prefix.
	ct, contractID := makeContractTest(t)
	const fakePop192 = "" +
		"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2" +
		"c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" +
		"e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8"
	// Defence in depth — also catches the case where someone shortens
	// the constant in a future refactor.
	require.Equal(t, 192, len(fakePop192),
		"fakePop192 must be exactly 192 hex chars or the parser "+
			"rejects at the pop-length gate before validateHiveAccount runs")
	vk, _ := makeValidatorKey(t, 0x55, "placeholder")

	badAccounts := []string{
		"Mallory",                        // uppercase
		".leading",                       // leading dot
		"trailing.",                      // trailing dot
		"al..ice",                        // consecutive dots
		"1starts",                        // leading digit
		"alice-",                         // trailing hyphen
		"ab",                             // too short
		"way.too.long.account.name.here", // too long
		"alice_bob",                      // underscore
	}
	for _, acct := range badAccounts {
		t.Run("acct="+acct, func(t *testing.T) {
			payload := buildEntry(epochE2E, vk.did.String(), vk.pkHex, fakePop192, acct)
			r := callSetValidatorSet(t, &ct, contractID, adminOwner, payload)
			require.False(t, r.Success,
				"account %q must be rejected by ValidateHiveAccount; got success", acct)
			// Round-14 audit R14-BLS-ERROR-STRING-BRITTLE +
			// R14-TEST-FAKEPOP-WRONG-LENGTH: assert reject came
			// from the validateHiveAccount gate (not the earlier
			// pop-length gate or some other parse error). Pinned
			// to the exported prefix constant.
			assert.True(t,
				strings.HasPrefix(r.ErrMsg, constants.ErrPrefixInvalidHiveAccount),
				"account %q must hit validateHiveAccount (prefix %q); got %q",
				acct, constants.ErrPrefixInvalidHiveAccount, r.ErrMsg)
		})
	}
}

func TestSetValidatorSet_RejectsNonAdmin(t *testing.T) {
	ct, contractID := makeContractTest(t)
	vk, popHex := makeValidatorKey(t, 0x66, "tibfox")

	payload := buildEntry(epochE2E, vk.did.String(), vk.pkHex, popHex, vk.account)
	// Non-owner caller — must hit the contract's checkAdmin gate.
	r := callSetValidatorSet(t, &ct, contractID, "hive:not-the-admin", payload)
	assert.False(t, r.Success, "non-admin caller must be rejected; got success")
}

// buildEntry composes the R4-CSM-01 wire format:
//
//	<epoch>;<did>=<pk>=<pop>=<account>
//
// Mirrors mapping.gen-validator-set-payload but inline so this
// test stays self-contained.
func buildEntry(epoch uint64, did, pkHex, popHex, account string) string {
	var sb strings.Builder
	sb.WriteString(uint64ToStr(epoch))
	sb.WriteString(";")
	sb.WriteString(did)
	sb.WriteString("=")
	sb.WriteString(pkHex)
	sb.WriteString("=")
	sb.WriteString(popHex)
	sb.WriteString("=")
	sb.WriteString(account)
	return sb.String()
}

func uint64ToStr(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for n > 0 {
		pos--
		b[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(b[pos:])
}
