package current_test

// zz_allow1_fix_test.go - regression test for ALLOW-1 (allowance key collision).
//
// TestWR_* convention: these assert the CORRECT (fixed) behavior, so FAIL = the
// bug is present. They pass on the fixed branch and FAIL on the unfixed base,
// which makes them a true before/after for the fix.
//
// The collision: the allowance state key used to be q-<owner>-<spender> joined by
// the generic "-" delimiter, which is legal inside Hive usernames. So hive:milo
// approving the crafted spender "hpr-hive:milo" wrote the SAME key as
// hive:milo-hpr approving hive:milo, letting milo drain milo-hpr via
// transferFrom / unmapFrom. The fix joins with "|" (illegal in any VSC identity)
// and rejects non-address spenders in approve/increase/decrease.
//
// Assertions are OUTCOME-based (balances, success flags) so the file is portable:
// it compiles and runs unchanged on both the base and the fixed branch.

import (
	"fmt"
	"testing"
	"time"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/require"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
)

// allow1Case: victim holds the funds; attacker owns a name that is a "-"-prefix of
// the victim; crafted is the spender the attacker approves to forge the victim's
// allowance key; puller is the account that then pulls (== attacker here).
type allow1Case struct {
	name, victim, attacker, crafted, puller string
}

func allow1Cases() []allow1Case {
	return []allow1Case{
		// The headline case from the review: milo drains milo-hpr.
		{"milo_vs_milo-hpr", "hive:milo-hpr", "hive:milo", "hpr-hive:milo", "hive:milo"},
		// A second real-shape pair (both are valid Hive usernames).
		{"pal_vs_pal-bot", "hive:pal-bot", "hive:pal", "bot-hive:pal", "hive:pal"},
	}
}

func allow1NewCT(t *testing.T, victim string, bal int64) (*test_utils.ContractTest, string) {
	t.Helper()
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:vault-owner", ContractWasm)
	ct.StateSet(contractId, constants.BalancePrefix+victim, encodeBalance(t, bal))
	return &ct, contractId
}

// TestWR_Allow1_CraftedSpenderRejected: approving a non-address spender must be
// refused outright (approve / increaseAllowance / decreaseAllowance).
func TestWR_Allow1_CraftedSpenderRejected(t *testing.T) {
	for _, c := range allow1Cases() {
		t.Run(c.name, func(t *testing.T) {
			ct, cid := allow1NewCT(t, c.victim, 50000)
			ra := callApprove(t, ct, cid, c.attacker, c.crafted, 50000)
			require.False(t, ra.Success, "approve of non-address spender %q must be refused", c.crafted)
			ri := callIncreaseAllowance(t, ct, cid, c.attacker, c.crafted, 50000)
			require.False(t, ri.Success, "increaseAllowance of non-address spender %q must be refused", c.crafted)
			rd := callDecreaseAllowance(t, ct, cid, c.attacker, c.crafted, 1)
			require.False(t, rd.Success, "decreaseAllowance of non-address spender %q must be refused", c.crafted)
		})
	}
}

// TestWR_Allow1_NoCrossAccountDrain: the full attack - attacker approves the
// crafted spender then pulls from the victim - must leave the victim's balance
// untouched and the pull refused.
func TestWR_Allow1_NoCrossAccountDrain(t *testing.T) {
	for _, c := range allow1Cases() {
		t.Run(c.name, func(t *testing.T) {
			const bal = int64(50000)
			ct, cid := allow1NewCT(t, c.victim, bal)

			// Attacker crafts the colliding approve (ignore whether it is accepted;
			// on the fixed branch it is rejected, on the base branch it succeeds).
			_ = callApprove(t, ct, cid, c.attacker, c.crafted, bal)
			_ = callIncreaseAllowance(t, ct, cid, c.attacker, c.crafted, bal)

			// Attacker pulls the victim's whole balance to itself.
			r := callTransferFrom(t, ct, cid, c.puller, c.victim, c.puller, bal)
			require.False(t, r.Success, "cross-account transferFrom must be refused (victim=%s puller=%s)", c.victim, c.puller)
			require.Equal(t, encodeBalance(t, bal), ct.StateGet(cid, constants.BalancePrefix+c.victim),
				"victim balance must be untouched")
			require.Equal(t, "", ct.StateGet(cid, constants.BalancePrefix+c.puller),
				"puller must not have received anything")
		})
	}
}

// TestWR_Allow1_LegitAllowanceStillWorks: a genuine cross-account allowance (valid
// spender address) must continue to work. This passes on BOTH branches and guards
// against the fix over-restricting legitimate use.
func TestWR_Allow1_LegitAllowanceStillWorks(t *testing.T) {
	const bal = int64(10000)
	owner, spender, target := "hive:milo-hpr", "hive:milo", "hive:bob"
	ct, cid := allow1NewCT(t, owner, bal)

	ar := callApprove(t, ct, cid, owner, spender, 5000)
	require.True(t, ar.Success, "legit approve must succeed: %s %s", ar.Err, ar.ErrMsg)

	r := callTransferFrom(t, ct, cid, spender, owner, target, 3000)
	require.True(t, r.Success, "legit transferFrom must succeed: %s %s", r.Err, r.ErrMsg)
	require.Equal(t, encodeBalance(t, 7000), ct.StateGet(cid, constants.BalancePrefix+owner))
	require.Equal(t, encodeBalance(t, 3000), ct.StateGet(cid, constants.BalancePrefix+target))
}

// TestWR_Allow1_UnmapFromNoCrossDrain: the same collision must not reach the L1
// withdrawal path - a crafted approve must not let the attacker unmap the
// victim's BTC to an L1 address of its choosing.
func TestWR_Allow1_UnmapFromNoCrossDrain(t *testing.T) {
	const victim, attacker, crafted = "hive:milo-hpr", "hive:milo", "hpr-hive:milo"
	const fakeTxId0 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const fakeTxId1 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const bal = int64(10000)

	ct, cid := allow1NewCT(t, victim, bal)
	activateTssKey(ct, cid)
	ct.StateSet(cid, constants.ObservedBlockPrefix+"100", buildObservedList(t,
		observedParam{fakeTxId0, 0}, observedParam{fakeTxId1, 0},
	))
	ct.StateSet(cid, constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(mapping.UtxoRegistry{
		{Id: 1024, Amount: 5000}, {Id: 1025, Amount: 5000},
	})))
	ct.StateSet(cid, constants.UtxoPrefix+"400", depositUtxoBinary(t, fakeTxId0, 0, 5000, "deposit_to="+victim))
	ct.StateSet(cid, constants.UtxoPrefix+"401", changeUtxoBinary(t, fakeTxId1, 0, 5000))
	ct.StateSet(cid, constants.UtxoLastIdKey, encodeUtxoCounters(1026, 0))
	ct.StateSet(cid, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: bal, UserSupply: bal, FeeSupply: 0, BaseFeeRate: 1,
	})))
	ct.StateSet(cid, constants.LastHeightKey, "102")
	ct.StateSet(cid, constants.BlockPrefix+"100", buildSeedHeaderRaw(t, time.Unix(0, 0)))
	ct.StateSet(cid, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(cid, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	// Attacker crafts the colliding approve (rejected on the fixed branch).
	_ = callApprove(t, ct, cid, attacker, crafted, bal)

	payload, err := tinyjson.Marshal(mapping.TransferParams{
		Amount: "7500", To: regtestDestAddress(t), From: victim,
	})
	require.NoError(t, err)
	thisTx := txId
	txId++
	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: fmt.Sprintf("%d", thisTx), BlockId: fmt.Sprintf("%d", thisTx),
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{attacker}, RequiredPostingAuths: []string{},
		},
		ContractId: cid, Action: "unmapFrom", Payload: payload, RcLimit: 20000, Intents: []contracts.Intent{},
	})
	require.False(t, r.Success, "cross-account unmapFrom must be refused")
	require.Equal(t, encodeBalance(t, bal), ct.StateGet(cid, constants.BalancePrefix+victim),
		"victim balance must be untouched")
	require.Equal(t, "", ct.StateGet(cid, constants.TxSpendsRegistryKey),
		"no withdrawal to the attacker's L1 address may be queued")
}
