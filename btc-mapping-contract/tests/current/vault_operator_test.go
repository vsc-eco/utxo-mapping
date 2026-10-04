package current_test

import (
	"strings"
	"testing"

	"btc-mapping-contract/contract/constants"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	ledgerDb "vsc-node/modules/db/vsc/ledger"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/stretchr/testify/require"
)

// callAs invokes a contract action with an explicit caller (so we can exercise
// the owner / operator / stranger authorization paths directly).
func callAs(t *testing.T, ct *test_utils.ContractTest, contractId, caller, action string, payload []byte) test_utils.ContractTestCallResult {
	t.Helper()
	return ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: "tx-" + action + "-" + caller, BlockId: "block:" + action, Index: 1, OpIndex: 0,
			Timestamp:     "2025-10-14T00:00:00",
			RequiredAuths: []string{caller}, RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     action,
		Payload:    payload,
		RcLimit:    1_000_000,
		Intents:    []contracts.Intent{},
		Caller:     caller,
	})
}

// The scoped-operator model: an appointed operator DID may call the four
// OPERATIONAL vault ops, a stranger may not, governance stays owner-only, and the
// owner can rotate/clear the operator. These are the authorization guarantees the
// off-chain rotation driver depends on.
func TestVaultOperatorAuthorization(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "mapping_contract"
	owner := "hive:milo-hpr"
	operator := "did:pkh:eip155:1:0x00000000000000000000000000000000deadbeef"
	operator2 := "did:pkh:eip155:1:0x0000000000000000000000000000000000c0ffee"
	stranger := "did:pkh:eip155:1:0x000000000000000000000000000000000badc0de"
	ct.RegisterContract(contractId, owner, ContractWasm)

	// did:pkh accounts get no free-RC allowance (only hive: accounts do), so fund
	// them with HBD. Otherwise the harness rejects the call for 0 RC BEFORE the
	// contract's auth guard runs, and we'd be testing the RC gate, not checkOperator.
	for _, acct := range []string{operator, operator2, stranger} {
		ct.Deposit(acct, 1_000_000, ledgerDb.AssetHbd)
	}

	operationalOps := []string{"migrateVault", "retireVault", "writeOffDust", "redriveSpend"}
	governanceOps := []string{"pause", "registerRouter", "createKey", "discardPendingKey"}

	isAuthRejection := func(r test_utils.ContractTestCallResult) bool {
		// An auth failure aborts with our permission message; a call that PASSES the
		// guard fails later for a different reason (no vault to migrate, bad input, ...).
		return !r.Success && (strings.Contains(r.ErrMsg, "must be performed by the contract owner or the vault operator") ||
			strings.Contains(r.ErrMsg, "must be performed by the contract owner"))
	}

	// ── Before any operator is set: only the owner passes the operator guard. ──
	for _, op := range operationalOps {
		r := callAs(t, &ct, contractId, stranger, op, []byte(""))
		require.True(t, isAuthRejection(r), "%s: a stranger must be rejected before an operator is set (got %q)", op, r.ErrMsg)
	}

	// ── Appoint the operator (owner-only). ──
	r := callAs(t, &ct, contractId, stranger, "setVaultOperator", []byte(operator))
	require.False(t, r.Success, "a stranger must NOT be able to appoint the operator")
	require.Contains(t, r.ErrMsg, "must be performed by the contract owner")

	r = callAs(t, &ct, contractId, owner, "setVaultOperator", []byte(operator))
	require.True(t, r.Success, "the owner must be able to appoint the operator: %s", r.ErrMsg)
	require.Equal(t, operator, ct.StateGet(contractId, constants.VaultOperatorKey), "operator DID must be persisted")

	// ── Now the operator passes the operational guard; a stranger still does not. ──
	for _, op := range operationalOps {
		ro := callAs(t, &ct, contractId, operator, op, []byte(""))
		require.False(t, isAuthRejection(ro), "%s: the appointed operator must PASS the auth guard (got %q)", op, ro.ErrMsg)

		rs := callAs(t, &ct, contractId, stranger, op, []byte(""))
		require.True(t, isAuthRejection(rs), "%s: a stranger must still be rejected (got %q)", op, rs.ErrMsg)
	}

	// ── Governance ops must remain owner-only — the operator gains NO governance power. ──
	for _, op := range governanceOps {
		ro := callAs(t, &ct, contractId, operator, op, []byte("{}"))
		require.True(t, ro.Success == false && strings.Contains(ro.ErrMsg, "must be performed by the contract owner"),
			"%s: the operator must NOT gain governance power (got success=%v err=%q)", op, ro.Success, ro.ErrMsg)
	}

	// ── The owner can ROTATE the operator (replaceable, unlike registerRouter). ──
	r = callAs(t, &ct, contractId, owner, "setVaultOperator", []byte(operator2))
	require.True(t, r.Success, "the owner must be able to rotate the operator: %s", r.ErrMsg)
	require.Equal(t, operator2, ct.StateGet(contractId, constants.VaultOperatorKey))

	// The OLD operator is now a stranger again.
	for _, op := range operationalOps {
		ro := callAs(t, &ct, contractId, operator, op, []byte(""))
		require.True(t, isAuthRejection(ro), "%s: the rotated-out operator must be rejected (got %q)", op, ro.ErrMsg)
	}

	// ── The owner can CLEAR the operator (empty input). ──
	r = callAs(t, &ct, contractId, owner, "setVaultOperator", []byte(""))
	require.True(t, r.Success, "the owner must be able to clear the operator: %s", r.ErrMsg)
	require.Empty(t, ct.StateGet(contractId, constants.VaultOperatorKey), "operator must be removed from state")

	for _, op := range operationalOps {
		ro := callAs(t, &ct, contractId, operator2, op, []byte(""))
		require.True(t, isAuthRejection(ro), "%s: after clearing, even the last operator must be rejected (got %q)", op, ro.ErrMsg)
	}

	// ── A hive: account is also a valid operator (an ops account, not just the bot's DID). ──
	r = callAs(t, &ct, contractId, owner, "setVaultOperator", []byte("hive:magi.ops"))
	require.True(t, r.Success, "a hive: account must be accepted as operator: %s", r.ErrMsg)
	require.Equal(t, "hive:magi.ops", ct.StateGet(contractId, constants.VaultOperatorKey))

	// ── A prefixless operator value is rejected (guards against a typo locking things). ──
	r = callAs(t, &ct, contractId, owner, "setVaultOperator", []byte("magi.ops"))
	require.False(t, r.Success, "a prefixless operator value must be rejected")
	require.Contains(t, r.ErrMsg, "must be a hive: account or a did: identity")
}
