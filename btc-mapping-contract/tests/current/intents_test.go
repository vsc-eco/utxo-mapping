package current_test

import (
	dexcontracts "btc-mapping-contract"
	"testing"
	"time"
	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	state_engine "vsc-node/modules/state-processing"
)

func TestSenderCallerIntents(t *testing.T) {
	ct := test_utils.NewContractTest()
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
