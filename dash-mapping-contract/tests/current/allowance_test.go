package current_test

import (
	"dash-mapping-contract/contract/constants"
	"dash-mapping-contract/contract/mapping"
	"fmt"
	"testing"

	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
)

const (
	allowanceOwner   = "hive:alice"
	allowanceSpender = "spender_contract"
	allowanceTarget  = "hive:bob"
)

func allowanceKey(owner, spender string) string {
	return constants.AllowancePrefix + owner + constants.DirPathDelimiter + spender
}

func setupAllowanceContract(t *testing.T, balance int64) (*test_utils.ContractTest, string) {
	t.Helper()
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, allowanceOwner, ContractWasm)
	if balance > 0 {
		ct.StateSet(contractId, mapping.BalancePrefix+allowanceOwner, encodeBalance(t, balance))
	}
	return &ct, contractId
}

func callApprove(
	t *testing.T,
	ct *test_utils.ContractTest,
	contractId, owner, spender string,
	amount int64,
) test_utils.ContractTestCallResult {
	t.Helper()
	payload, err := tinyjson.Marshal(mapping.AllowanceParams{
		Spender: spender,
		Amount:  fmt.Sprintf("%d", amount),
	})
	if err != nil {
		t.Fatal("marshal approve payload:", err)
	}
	return ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, owner),
		ContractId: contractId,
		Action:     "approve",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     owner,
		Intents:    []contracts.Intent{},
	})
}

func callIncreaseAllowance(
	t *testing.T,
	ct *test_utils.ContractTest,
	contractId, owner, spender string,
	amount int64,
) test_utils.ContractTestCallResult {
	t.Helper()
	payload, err := tinyjson.Marshal(mapping.AllowanceParams{
		Spender: spender,
		Amount:  fmt.Sprintf("%d", amount),
	})
	if err != nil {
		t.Fatal("marshal increaseAllowance payload:", err)
	}
	return ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, owner),
		ContractId: contractId,
		Action:     "increaseAllowance",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     owner,
		Intents:    []contracts.Intent{},
	})
}

func callDecreaseAllowance(
	t *testing.T,
	ct *test_utils.ContractTest,
	contractId, owner, spender string,
	amount int64,
) test_utils.ContractTestCallResult {
	t.Helper()
	payload, err := tinyjson.Marshal(mapping.AllowanceParams{
		Spender: spender,
		Amount:  fmt.Sprintf("%d", amount),
	})
	if err != nil {
		t.Fatal("marshal decreaseAllowance payload:", err)
	}
	return ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, owner),
		ContractId: contractId,
		Action:     "decreaseAllowance",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     owner,
		Intents:    []contracts.Intent{},
	})
}

func callTransferFrom(
	t *testing.T,
	ct *test_utils.ContractTest,
	contractId, spender, from, to string,
	amount int64,
) test_utils.ContractTestCallResult {
	t.Helper()
	payload, err := tinyjson.Marshal(mapping.TransferParams{
		From:   from,
		To:     to,
		Amount: amount,
	})
	if err != nil {
		t.Fatal("marshal transferFrom payload:", err)
	}
	thisTx := txId
	txId++
	return ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 fmt.Sprintf("%d", thisTx),
			BlockId:              fmt.Sprintf("%d", thisTx),
			Index:                0,
			OpIndex:              0,
			Timestamp:            "2025-10-14T00:00:00",
			RequiredAuths:        []string{from},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "transferFrom",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     spender,
		Intents:    []contracts.Intent{},
	})
}

// ==================== Approve Tests ====================

func TestApprove(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)
	r := callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 5000)
	if r.Err != "" {
		t.Fatalf("approve failed: %s: %s", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success)
	key := allowanceKey(allowanceOwner, allowanceSpender)
	assert.Equal(t, encodeBalance(t, 5000), ct.StateGet(contractId, key))
}

func TestApproveOverwrite(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)
	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 5000)
	r := callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 1000)
	assert.True(t, r.Success)
	key := allowanceKey(allowanceOwner, allowanceSpender)
	assert.Equal(t, encodeBalance(t, 1000), ct.StateGet(contractId, key))
}

func TestApproveToZeroClearsKey(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)
	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 5000)
	r := callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 0)
	assert.True(t, r.Success)
	key := allowanceKey(allowanceOwner, allowanceSpender)
	assert.Equal(t, "", ct.StateGet(contractId, key), "allowance key should be deleted when set to 0")
}

func TestApproveNegativeAmountFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)
	r := callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, -100)
	assert.False(t, r.Success, "approve with negative amount should fail")
}

func TestApproveEmptySpenderFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)
	r := callApprove(t, ct, contractId, allowanceOwner, "", 5000)
	assert.False(t, r.Success, "approve with empty spender should fail")
}

func TestApproveSelfAsSpenderFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)
	r := callApprove(t, ct, contractId, allowanceOwner, allowanceOwner, 5000)
	assert.False(t, r.Success, "approve self as spender should fail")
}

// ==================== IncreaseAllowance Tests ====================

func TestIncreaseAllowance(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)
	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 1000)
	r := callIncreaseAllowance(t, ct, contractId, allowanceOwner, allowanceSpender, 500)
	assert.True(t, r.Success)
	key := allowanceKey(allowanceOwner, allowanceSpender)
	assert.Equal(t, encodeBalance(t, 1500), ct.StateGet(contractId, key))
}

func TestIncreaseAllowanceFromZero(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)
	r := callIncreaseAllowance(t, ct, contractId, allowanceOwner, allowanceSpender, 800)
	assert.True(t, r.Success)
	key := allowanceKey(allowanceOwner, allowanceSpender)
	assert.Equal(t, encodeBalance(t, 800), ct.StateGet(contractId, key))
}

func TestIncreaseAllowanceZeroAmountFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)
	r := callIncreaseAllowance(t, ct, contractId, allowanceOwner, allowanceSpender, 0)
	assert.False(t, r.Success, "increaseAllowance with zero amount should fail")
}

func TestIncreaseAllowanceEmptySpenderFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)
	r := callIncreaseAllowance(t, ct, contractId, allowanceOwner, "", 500)
	assert.False(t, r.Success, "increaseAllowance with empty spender should fail")
}

// ==================== DecreaseAllowance Tests ====================

func TestDecreaseAllowance(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)
	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 1000)
	r := callDecreaseAllowance(t, ct, contractId, allowanceOwner, allowanceSpender, 400)
	assert.True(t, r.Success)
	key := allowanceKey(allowanceOwner, allowanceSpender)
	assert.Equal(t, encodeBalance(t, 600), ct.StateGet(contractId, key))
}

func TestDecreaseAllowanceToZeroClearsKey(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)
	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 1000)
	r := callDecreaseAllowance(t, ct, contractId, allowanceOwner, allowanceSpender, 1000)
	assert.True(t, r.Success)
	key := allowanceKey(allowanceOwner, allowanceSpender)
	assert.Equal(t, "", ct.StateGet(contractId, key), "allowance key should be deleted when decreased to 0")
}

func TestDecreaseAllowanceBelowZeroFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)
	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 500)
	r := callDecreaseAllowance(t, ct, contractId, allowanceOwner, allowanceSpender, 1000)
	assert.False(t, r.Success, "decreaseAllowance below zero should fail")
}

func TestDecreaseAllowanceEmptySpenderFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)
	r := callDecreaseAllowance(t, ct, contractId, allowanceOwner, "", 500)
	assert.False(t, r.Success, "decreaseAllowance with empty spender should fail")
}

// ==================== TransferFrom Tests ====================

func TestTransferFrom(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 10000)
	ar := callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 5000)
	if !ar.Success {
		t.Fatalf("approve failed: %s: %s", ar.Err, ar.ErrMsg)
	}
	r := callTransferFrom(t, ct, contractId, allowanceSpender, allowanceOwner, allowanceTarget, 3000)
	if r.Err != "" {
		t.Fatalf("transferFrom failed: %s: %s", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success)
	assert.Equal(t, encodeBalance(t, 7000), ct.StateGet(contractId, mapping.BalancePrefix+allowanceOwner))
	assert.Equal(t, encodeBalance(t, 3000), ct.StateGet(contractId, mapping.BalancePrefix+allowanceTarget))
	assert.Equal(t, encodeBalance(t, 2000), ct.StateGet(contractId, allowanceKey(allowanceOwner, allowanceSpender)))
}

func TestTransferFromExhaustsAllowance(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 10000)
	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 4000)
	r := callTransferFrom(t, ct, contractId, allowanceSpender, allowanceOwner, allowanceTarget, 4000)
	assert.True(t, r.Success)
	assert.Equal(t, "", ct.StateGet(contractId, allowanceKey(allowanceOwner, allowanceSpender)),
		"allowance key should be deleted after full spend")
	assert.Equal(t, encodeBalance(t, 6000), ct.StateGet(contractId, mapping.BalancePrefix+allowanceOwner))
}

func TestTransferFromExceedsAllowanceFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 10000)
	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 1000)
	r := callTransferFrom(t, ct, contractId, allowanceSpender, allowanceOwner, allowanceTarget, 2000)
	assert.False(t, r.Success, "transferFrom exceeding allowance should fail")
	assert.Equal(t, encodeBalance(t, 10000), ct.StateGet(contractId, mapping.BalancePrefix+allowanceOwner))
	assert.Equal(t, encodeBalance(t, 1000), ct.StateGet(contractId, allowanceKey(allowanceOwner, allowanceSpender)))
}

func TestTransferFromNoAllowanceFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 10000)
	r := callTransferFrom(t, ct, contractId, allowanceSpender, allowanceOwner, allowanceTarget, 1000)
	assert.False(t, r.Success, "transferFrom with no allowance should fail")
	assert.Equal(t, encodeBalance(t, 10000), ct.StateGet(contractId, mapping.BalancePrefix+allowanceOwner))
}

func TestTransferFromAllowanceDecrements(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 10000)
	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 6000)

	r1 := callTransferFrom(t, ct, contractId, allowanceSpender, allowanceOwner, allowanceTarget, 2000)
	if !r1.Success {
		t.Fatalf("first transferFrom failed: %s: %s", r1.Err, r1.ErrMsg)
	}
	assert.Equal(t, encodeBalance(t, 4000), ct.StateGet(contractId, allowanceKey(allowanceOwner, allowanceSpender)))

	r2 := callTransferFrom(t, ct, contractId, allowanceSpender, allowanceOwner, allowanceTarget, 3000)
	if !r2.Success {
		t.Fatalf("second transferFrom failed: %s: %s", r2.Err, r2.ErrMsg)
	}
	assert.Equal(t, encodeBalance(t, 1000), ct.StateGet(contractId, allowanceKey(allowanceOwner, allowanceSpender)))

	r3 := callTransferFrom(t, ct, contractId, allowanceSpender, allowanceOwner, allowanceTarget, 2000)
	assert.False(t, r3.Success, "third transferFrom should fail: allowance exhausted")
}

func TestTransferFromInsufficientBalanceFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 500)
	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 5000)
	r := callTransferFrom(t, ct, contractId, allowanceSpender, allowanceOwner, allowanceTarget, 1000)
	assert.False(t, r.Success, "transferFrom exceeding balance should fail even with sufficient allowance")
}

func TestDirectTransferNoAllowanceRequired(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 5000)
	payload, err := tinyjson.Marshal(mapping.TransferParams{
		To:     allowanceTarget,
		Amount: 3000,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, allowanceOwner),
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     allowanceOwner,
		Intents:    []contracts.Intent{},
	})
	assert.True(t, r.Success)
	assert.Equal(t, encodeBalance(t, 2000), ct.StateGet(contractId, mapping.BalancePrefix+allowanceOwner))
	assert.Equal(t, encodeBalance(t, 3000), ct.StateGet(contractId, mapping.BalancePrefix+allowanceTarget))
}
