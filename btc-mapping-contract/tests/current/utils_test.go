package current_test

import (
	"btc-mapping-contract/contract/constants"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"testing"
	"time"
	"vsc-node/lib/test_utils"
	contract_session "vsc-node/modules/contract/session"
	tss_db "vsc-node/modules/db/vsc/tss"
	state_engine "vsc-node/modules/state-processing"
)

var txId int64 = 0

// activateTssKey seeds the contract's TSS signing key as active in the mock
// keys DB. The runtime's tss.sign_key host call returns "fail" when the key is
// absent or not active, which now reverts an unmap (mirroring a deprecated key
// on testnet). Any test that expects an unmap to reach signing and succeed must
// call this after RegisterContract.
func activateTssKey(ct *test_utils.ContractTest, contractId string) {
	ct.Tss.Keys.SetKey(tss_db.TssKey{
		Id:     contractId + "-" + constants.TssKeyName,
		Status: tss_db.TssKeyActive,
	})
}

// deprecateTssKey seeds the contract's TSS signing key in the deprecated state,
// reproducing the on-testnet condition where tss.sign_key returns "fail".
func deprecateTssKey(ct *test_utils.ContractTest, contractId string) {
	ct.Tss.Keys.SetKey(tss_db.TssKey{
		Id:     contractId + "-" + constants.TssKeyName,
		Status: tss_db.TssKeyDeprecated,
	})
}

func dumpLogs(t *testing.T, logs map[string]contract_session.LogOutput) {
	t.Helper()
	for name, output := range logs {
		if len(output.Logs) > 0 {
			log.Println("logs for", name)
		}
		for _, log := range output.Logs {
			fmt.Printf("    %s\n", log)
		}
		if len(output.TssOps) > 0 {
			log.Println("tss ops for", name)
		}
		for _, tssOp := range output.TssOps {
			fmt.Printf("    key id: %s, type: %s, args: %s", tssOp.KeyId, tssOp.Type, tssOp.Args)
		}
	}
}
func dumpStateDiff(t *testing.T, sdm map[string]contract_session.StateDiff) {
	t.Helper()
	for name, sd := range sdm {
		if len(sd.Deletions) > 0 || len(sd.KeyDiff) > 0 {
			t.Log("state diff for", name)
		}
		for del := range sd.Deletions {
			t.Logf("    deleted %s\n", del)
		}
		for key, diff := range sd.KeyDiff {
			t.Logf("    %*s: %s -> %s\n", 16, key, fmtStoredVal(diff.Previous), fmtStoredVal(diff.Current))
		}
	}
}

func fmtStoredVal(s []byte) string {
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return hex.EncodeToString(s)
		}
	}
	return string(s)
}

func printKeys(t *testing.T, ct *test_utils.ContractTest, contractId string, keys []string) {
	t.Helper()
	for _, key := range keys {
		fmt.Printf("%s: %s\n", key, ct.StateGet(contractId, key))
	}
}

func basicSelf(t *testing.T, caller string) *state_engine.TxSelf {
	t.Helper()
	thisTx := txId
	txId++
	return &state_engine.TxSelf{
		TxId:                 strconv.FormatInt(thisTx, 10),
		BlockId:              strconv.FormatInt(thisTx, 10),
		Index:                0,
		OpIndex:              0,
		Timestamp:            time.Now().String(),
		RequiredAuths:        []string{caller},
		RequiredPostingAuths: []string{},
	}
}
