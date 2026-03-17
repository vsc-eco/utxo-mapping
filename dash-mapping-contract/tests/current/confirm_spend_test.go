package current_test

import (
	"dash-mapping-contract/contract/mapping"
	"testing"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"
)

func callConfirmSpend(
	t *testing.T,
	ct *test_utils.ContractTest,
	contractId, caller, txId string,
) test_utils.ContractTestCallResult {
	t.Helper()
	payload, err := tinyjson.Marshal(mapping.ConfirmSpendParams{TxId: txId})
	if err != nil {
		t.Fatal("marshal confirmSpend payload:", err)
	}
	return ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, caller),
		ContractId: contractId,
		Action:     "confirmSpend",
		Payload:    payload,
		RcLimit:    10000,
		Caller:     caller,
		Intents:    []contracts.Intent{},
	})
}

func TestConfirmSpendNotAdmin(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)
	r := callConfirmSpend(t, ct, contractId, "hive:unauthorized-user", "aaaa")
	assert.False(t, r.Success, "confirmSpend by non-admin should fail")
	assert.NotEmpty(t, r.Err)
}

func TestConfirmSpendEmptyTxId(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)
	r := callConfirmSpend(t, ct, contractId, allowanceOwner, "")
	assert.False(t, r.Success, "confirmSpend with empty txId should fail")
	assert.NotEmpty(t, r.Err)
}
