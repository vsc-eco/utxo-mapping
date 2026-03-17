package current_test

import (
	"ltc-mapping-contract/contract/mapping"
	"testing"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"
)

// callConfirmSpend calls the confirmSpend action as the given caller.
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

// TestConfirmSpendNotAdmin verifies that a non-admin caller is rejected.
func TestConfirmSpendNotAdmin(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, testOwner, ContractWasm)

	fakeTxId := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	r := callConfirmSpend(t, &ct, contractId, "hive:unauthorized-user", fakeTxId)
	assert.False(t, r.Success, "confirmSpend by non-admin should fail")
	assert.NotEmpty(t, r.Err)
}

// TestConfirmSpendEmptyTxId verifies that an empty tx_id is rejected.
func TestConfirmSpendEmptyTxId(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, testOwner, ContractWasm)

	r := callConfirmSpend(t, &ct, contractId, testOwner, "")
	assert.False(t, r.Success, "confirmSpend with empty txId should fail")
	assert.NotEmpty(t, r.Err)
}
