package current_test

import (
	"dash-mapping-contract/contract/constants"
	"dash-mapping-contract/contract/mapping"
	"fmt"
	"testing"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"
)

const addrTestOwner = "hive:addr-test-user"

func setupAddrContract(t *testing.T, balance int64) (*test_utils.ContractTest, string) {
	t.Helper()
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, addrTestOwner, ContractWasm)
	if balance > 0 {
		ct.StateSet(contractId, constants.BalancePrefix+addrTestOwner, encodeBalance(t, balance))
	}
	return &ct, contractId
}

func callTransfer(
	t *testing.T,
	ct *test_utils.ContractTest,
	contractId, caller, to string,
	amount int64,
) test_utils.ContractTestCallResult {
	t.Helper()
	payload, err := tinyjson.Marshal(mapping.TransferParams{
		To:     to,
		Amount: fmt.Sprintf("%d", amount),
	})
	if err != nil {
		t.Fatal("marshal transfer payload:", err)
	}
	return ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, caller),
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     caller,
		Intents:    []contracts.Intent{},
	})
}

// ==================== Address Format Tests ====================

func TestTransferToHiveAddress(t *testing.T) {
	ct, contractId := setupAddrContract(t, 10000)
	r := callTransfer(t, ct, contractId, addrTestOwner, "hive:recipient", 1000)
	assert.True(t, r.Success, "transfer to hive: address should succeed: %s %s", r.Err, r.ErrMsg)
	assert.Equal(t, encodeBalance(t, 9000), ct.StateGet(contractId, constants.BalancePrefix+addrTestOwner))
	assert.Equal(t, encodeBalance(t, 1000), ct.StateGet(contractId, constants.BalancePrefix+"hive:recipient"))
}

func TestTransferToDidKeyAddress(t *testing.T) {
	ct, contractId := setupAddrContract(t, 10000)
	r := callTransfer(t, ct, contractId, addrTestOwner, "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", 500)
	assert.True(t, r.Success, "transfer to did:key: address should succeed: %s %s", r.Err, r.ErrMsg)
	assert.Equal(t, encodeBalance(t, 9500), ct.StateGet(contractId, constants.BalancePrefix+addrTestOwner))
}

func TestTransferToContractAddress(t *testing.T) {
	ct, contractId := setupAddrContract(t, 10000)
	r := callTransfer(t, ct, contractId, addrTestOwner, "contract:vsc1BemohMM2HKzfQzWquTfMF6LWvb2V9M35c3", 2000)
	assert.True(t, r.Success, "transfer to contract: address should succeed: %s %s", r.Err, r.ErrMsg)
	assert.Equal(t, encodeBalance(t, 8000), ct.StateGet(contractId, constants.BalancePrefix+addrTestOwner))
}

func TestTransferToDidPkhEip155Address(t *testing.T) {
	ct, contractId := setupAddrContract(t, 10000)
	r := callTransfer(t, ct, contractId, addrTestOwner, "did:pkh:eip155:1:0x1234567890abcdef1234567890abcdef12345678", 1500)
	assert.True(t, r.Success, "transfer to did:pkh:eip155 address should succeed: %s %s", r.Err, r.ErrMsg)
	assert.Equal(t, encodeBalance(t, 8500), ct.StateGet(contractId, constants.BalancePrefix+addrTestOwner))
}

// ==================== Invalid Address Tests ====================

func TestTransferToInvalidAddressFails(t *testing.T) {
	ct, contractId := setupAddrContract(t, 10000)
	r := callTransfer(t, ct, contractId, addrTestOwner, "invalid-address", 1000)
	assert.False(t, r.Success, "transfer to invalid address should fail")
}

func TestTransferToEmptyAddressFails(t *testing.T) {
	ct, contractId := setupAddrContract(t, 10000)
	r := callTransfer(t, ct, contractId, addrTestOwner, "", 1000)
	assert.False(t, r.Success, "transfer to empty address should fail")
}

// ==================== Amount Validation Tests ====================

func TestTransferZeroAmountFails(t *testing.T) {
	ct, contractId := setupAddrContract(t, 10000)
	r := callTransfer(t, ct, contractId, addrTestOwner, "hive:recipient", 0)
	assert.False(t, r.Success, "transfer with zero amount should fail")
}

func TestTransferNegativeAmountFails(t *testing.T) {
	ct, contractId := setupAddrContract(t, 10000)
	r := callTransfer(t, ct, contractId, addrTestOwner, "hive:recipient", -100)
	assert.False(t, r.Success, "transfer with negative amount should fail")
}

func TestTransferInsufficientBalanceFails(t *testing.T) {
	ct, contractId := setupAddrContract(t, 500)
	r := callTransfer(t, ct, contractId, addrTestOwner, "hive:recipient", 1000)
	assert.False(t, r.Success, "transfer with insufficient balance should fail")
	assert.Equal(t, encodeBalance(t, 500), ct.StateGet(contractId, constants.BalancePrefix+addrTestOwner))
}
