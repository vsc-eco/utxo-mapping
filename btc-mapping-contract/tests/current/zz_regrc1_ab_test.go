package current_test

// REGISTRY-RC-GROWTH-1 A/B: the same sequence of calls on the contract before
// the change (BTC_AB_BEFORE_WASM, e.g. a build of main) and on this build must
// return the same results and leave the same state, key by key; only RC may
// differ. Skipped unless BTC_AB_BEFORE_WASM names the old dev.wasm.

import (
	"os"
	"reflect"
	"sort"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"vsc-node/lib/test_utils"

	"github.com/stretchr/testify/require"
)

type abStep struct {
	name        string
	success     bool
	ret, errMsg string
	logs        map[string][]string
	keys        []string
	rc          int64
}

// abRun is wqRotationCT on the given wasm (gen 0 retiring with two coins, gen
// 1 active with the reserve coin, the user holding all of UserSupply), then:
// unmap, transfer, migrateVault, the sweep's confirmation, a second unmap,
// writeOffDust and a third unmap.
func abRun(t *testing.T, wasm []byte) (*test_utils.ContractTest, string, []abStep) {
	t.Helper()
	const u = "hive:abuser"
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, wasm)
	ct.StateSet(contractId, constants.LastHeightKey, "102")
	seedActiveGen0(t, &ct, contractId, owner)
	gen0 := []utxoSeed{{1100, 600_000}, {1101, 300_000}}
	seedGenUtxos(t, &ct, contractId, 0, gen0)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: 900_000, UserSupply: 900_000, BaseFeeRate: 1,
	})))
	ct.StateSet(contractId, constants.BalancePrefix+u, encodeBalance(t, 900_000))
	var steps []abStep
	rec := func(name string, r test_utils.ContractTestCallResult) test_utils.ContractTestCallResult {
		s := abStep{name: name, success: r.Success, ret: r.Ret, errMsg: r.ErrMsg, logs: map[string][]string{}, rc: r.RcUsed}
		for k, l := range r.Logs {
			s.logs[k] = l.Logs
		}
		for _, d := range r.StateDiff { // per contract: every key written or deleted
			for k := range d.KeyDiff {
				s.keys = append(s.keys, k)
			}
			for k := range d.Deletions {
				s.keys = append(s.keys, k)
			}
		}
		sort.Strings(s.keys)
		steps = append(steps, s)
		return r
	}
	rec("createKey", callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")))
	rec("registerPublicKey", callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")))
	rec("activateKey", callKeyAction(t, &ct, contractId, owner, "activateKey", []byte("")))
	seedReserve(t, &ct, contractId, 1, h2ReserveId, 20_000)
	rec("unmap 1", wqUnmap(t, &ct, contractId, u, 100_000))
	rec("transfer", callAs(t, &ct, contractId, u, "transfer", []byte(`{"amount":"1000","to":"hive:other"}`)))
	m := rec("migrateVault", callKeyAction(t, &ct, contractId, owner, "migrateVault", []byte("")))
	if m.Success && m.Ret != "" && ct.StateGet(contractId, constants.TxSpendsPrefix+m.Ret) != "" {
		rec("confirm sweep", confirmMigrationSweep(t, &ct, contractId, owner, m.Ret, 103))
	}
	rec("unmap 2", wqUnmap(t, &ct, contractId, u, 50_000))
	rec("writeOffDust", callKeyAction(t, &ct, contractId, owner, "writeOffDust", []byte("")))
	rec("unmap 3", wqUnmap(t, &ct, contractId, u, 30_000))
	return &ct, contractId, steps
}

func abBefore(t *testing.T) []byte {
	t.Helper()
	p := os.Getenv("BTC_AB_BEFORE_WASM")
	if p == "" {
		t.Skip("set BTC_AB_BEFORE_WASM to the dev.wasm built before the change")
	}
	before, err := os.ReadFile(p)
	require.NoError(t, err)
	return before
}

func TestREGRC1_AB_SameResultsAndStateAsBefore(t *testing.T) {
	before := abBefore(t)
	ctOld, idOld, old := abRun(t, before)
	ctNew, idNew, cur := abRun(t, ContractWasm)
	abCompare(t, ctOld, idOld, old, ctNew, idNew, cur)
}

// abLegacy: a contract not folded yet (legacy key pair, no vault list) whose
// first call is writeOffDust, the one call where SaveVaultState (the fold) and
// SaveToState both run; then migrate and an unmap.
func abLegacy(t *testing.T, wasm []byte) (*test_utils.ContractTest, string, []abStep) {
	t.Helper()
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, wasm)
	ct.StateSet(contractId, constants.LastHeightKey, "102")
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	var steps []abStep
	for _, c := range []struct{ name, action string }{{"writeOffDust", "writeOffDust"}, {"migrate", "migrate"}, {"writeOffDust 2", "writeOffDust"}} {
		r := callKeyAction(t, &ct, contractId, owner, c.action, []byte(""))
		st := abStep{name: c.name, success: r.Success, ret: r.Ret, errMsg: r.ErrMsg, logs: map[string][]string{}, rc: r.RcUsed}
		for k, l := range r.Logs {
			st.logs[k] = l.Logs
		}
		for _, d := range r.StateDiff {
			for k := range d.KeyDiff {
				st.keys = append(st.keys, k)
			}
			for k := range d.Deletions {
				st.keys = append(st.keys, k)
			}
		}
		sort.Strings(st.keys)
		steps = append(steps, st)
	}
	return &ct, contractId, steps
}

func TestREGRC1_AB_UnfoldedContractWriteOffDust(t *testing.T) {
	before := abBefore(t)
	ctOld, idOld, old := abLegacy(t, before)
	ctNew, idNew, cur := abLegacy(t, ContractWasm)
	abCompare(t, ctOld, idOld, old, ctNew, idNew, cur)
}

func abCompare(t *testing.T, ctOld *test_utils.ContractTest, idOld string, old []abStep, ctNew *test_utils.ContractTest, idNew string, cur []abStep) {
	t.Helper()
	require.Len(t, cur, len(old))
	keys := map[string]bool{constants.VaultRegistryKey: true, constants.VaultNextGenKey: true, constants.VaultActiveGenKey: true,
		constants.UtxoRegistryKey: true, constants.SupplyKey: true, constants.TxSpendsRegistryKey: true, constants.MigrationSweepRegistryKey: true}
	for i := range old {
		o, n := old[i], cur[i]
		t.Logf("%-18s success %v/%v rc %d -> %d (%+d) keys written %d/%d", o.name, o.success, n.success, o.rc, n.rc, n.rc-o.rc, len(o.keys), len(n.keys))
		require.Equal(t, o.success, n.success, "%s: success", o.name)
		require.Equal(t, o.ret, n.ret, "%s: return value", o.name)
		require.Equal(t, o.errMsg, n.errMsg, "%s: error", o.name)
		require.True(t, reflect.DeepEqual(o.logs, n.logs), "%s: logs differ:\nold %v\nnew %v", o.name, o.logs, n.logs)
		for _, k := range o.keys {
			keys[k] = true
		}
		for _, k := range n.keys {
			keys[k] = true
		}
	}
	for k := range keys {
		require.Equal(t, ctOld.StateGet(idOld, k), ctNew.StateGet(idNew, k), "final state of key %q differs", k)
	}
	t.Logf("%d steps, %d state keys compared: identical", len(old), len(keys))
}
