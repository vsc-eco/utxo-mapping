package unused_test

import (
	dexcontracts "btc-mapping-contract"
	"encoding/json"
	"fmt"
	"testing"
	"time"
	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	state_engine "vsc-node/modules/state-processing"

	"github.com/stretchr/testify/assert"
)

func TestSenderCallerIntents(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	contract2Id := "mapping_contract_2"
	owner := "hive:milo-hpr"

	ct.RegisterContract(contractId, owner, dexcontracts.DevWasm)
	ct.RegisterContract(contract2Id, owner, dexcontracts.DevWasm)

	r := ct.Call(state_engine.TxVscCallContract{
		Self: state_engine.TxSelf{
			TxId:                 "0",
			BlockId:              "0",
			BlockHeight:          0,
			Index:                0,
			OpIndex:              0,
			Timestamp:            time.Now().String(),
			RequiredAuths:        []string{owner},
			RequiredPostingAuths: []string{},
		},
		NetId:      "testnet",
		Caller:     owner,
		ContractId: contractId,
		Action:     "test_endpoint",
		Payload:    []byte("a"),
		RcLimit:    1000,
		Intents: []contracts.Intent{{
			Type: "transfer.allow",
			Args: map[string]string{
				"limit": "200.000",
				"token": "hbd",
			},
		}},
	})
	if r.Err != "" {
		t.Errorf("%s: %s", r.Err, r.ErrMsg)
	}
	if r.Success != true {
		t.Error(r)
	}

	dumpLogs(t, r.Logs)
	logStateDiff(t, r.StateDiff)
	t.Log("return value:", r.Ret)
}

func TestLogging(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, "tx_spends", "null")

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "sometxid",
			BlockId:              "block:unmap",
			Index:                69,
			OpIndex:              0,
			Timestamp:            "2025-10-14T00:00:00",
			RequiredAuths:        []string{"hive:milo-hpr"},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "test_log",
		Payload: json.RawMessage(
			[]byte(`{"amount":10000,"recipient_btc_address":"tb1q5dgehs94wf5mgfasnfjsh4dqv6hz8e35w4w7tk"}`),
		),
		RcLimit: 10000,
		Intents: []contracts.Intent{},
	})

	fmt.Println("logs:", r.Logs)

	dumpLogs(t, r.Logs)

	if r.Err != "" {
		fmt.Println("error:", r.Err)
	}
	assert.True(t, r.Success)
	if assert.LessOrEqual(t, r.GasUsed, uint(1000000000)) {
		fmt.Println("gas used:", r.GasUsed)
	}
	assert.GreaterOrEqual(t, len(r.Logs), 1)

	fmt.Println("Return value:", r.Ret)
}
