package current_test

import (
	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"
	"fmt"
	"testing"

	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"
)

// TestTransferToHiveAddress verifies transfer to a hive: address succeeds.
func TestTransferToHiveAddress(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 5000)

	payload, _ := tinyjson.Marshal(mapping.TransferParams{To: "hive:recipient", Amount: "1000"})
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, allowanceOwner),
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     allowanceOwner,
		Intents:    []contracts.Intent{},
	})
	assert.True(t, r.Success, "transfer to hive: address should succeed")
	assert.Equal(t, encodeBalance(t, 4000), ct.StateGet(contractId, constants.BalancePrefix+allowanceOwner))
	assert.Equal(t, encodeBalance(t, 1000), ct.StateGet(contractId, constants.BalancePrefix+"hive:recipient"))
}

// TestTransferToDidKeyAddress verifies transfer to a did:key: address succeeds.
func TestTransferToDidKeyAddress(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 5000)

	payload, _ := tinyjson.Marshal(mapping.TransferParams{To: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", Amount: "1000"})
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, allowanceOwner),
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     allowanceOwner,
		Intents:    []contracts.Intent{},
	})
	assert.True(t, r.Success, "transfer to did:key: address should succeed")
}

// TestTransferToContractAddress verifies transfer to a contract: address succeeds
// (newly supported via SDK validation).
func TestTransferToContractAddress(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 5000)

	payload, _ := tinyjson.Marshal(mapping.TransferParams{To: "contract:some_dex_contract", Amount: "1000"})
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, allowanceOwner),
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     allowanceOwner,
		Intents:    []contracts.Intent{},
	})
	assert.True(t, r.Success, "transfer to contract: address should succeed")
}

// TestTransferToEVMAddress verifies transfer to a did:pkh:eip155 address succeeds.
func TestTransferToEVMAddress(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 5000)

	payload, _ := tinyjson.Marshal(mapping.TransferParams{To: "did:pkh:eip155:1:0x1234567890abcdef1234567890abcdef12345678", Amount: "1000"})
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, allowanceOwner),
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     allowanceOwner,
		Intents:    []contracts.Intent{},
	})
	assert.True(t, r.Success, "transfer to EVM address should succeed")
}

// TestTransferToInvalidAddress verifies that transfer to an unknown address format is rejected.
func TestTransferToInvalidAddress(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 5000)

	payload, _ := tinyjson.Marshal(mapping.TransferParams{To: "invalid_address_no_prefix", Amount: "1000"})
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, allowanceOwner),
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     allowanceOwner,
		Intents:    []contracts.Intent{},
	})
	if r.Err != "" {
		fmt.Printf("Expected error: %s: %s\n", r.Err, r.ErrMsg)
	}
	assert.False(t, r.Success, "transfer to invalid address should fail")
	// Balance should be unchanged
	assert.Equal(t, encodeBalance(t, 5000), ct.StateGet(contractId, constants.BalancePrefix+allowanceOwner))
}

// TestTransferToEmptyAddress verifies that transfer to an empty address is rejected.
func TestTransferToEmptyAddress(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 5000)

	payload, _ := tinyjson.Marshal(mapping.TransferParams{To: "", Amount: "1000"})
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, allowanceOwner),
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     allowanceOwner,
		Intents:    []contracts.Intent{},
	})
	assert.False(t, r.Success, "transfer to empty address should fail")
}

// TestTransferZeroAmount verifies that transferring zero is rejected.
func TestTransferZeroAmount(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 5000)

	payload, _ := tinyjson.Marshal(mapping.TransferParams{To: "hive:bob", Amount: "0"})
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, allowanceOwner),
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     allowanceOwner,
		Intents:    []contracts.Intent{},
	})
	assert.False(t, r.Success, "transfer of zero should fail")
}

// TestTransferNegativeAmount verifies that negative amount is rejected.
func TestTransferNegativeAmount(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 5000)

	payload, _ := tinyjson.Marshal(mapping.TransferParams{To: "hive:bob", Amount: "-100"})
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, allowanceOwner),
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     allowanceOwner,
		Intents:    []contracts.Intent{},
	})
	assert.False(t, r.Success, "transfer of negative amount should fail")
}

// TestTransferInsufficientBalance verifies that transferring more than balance is rejected.
func TestTransferInsufficientBalance(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 1000)

	payload, _ := tinyjson.Marshal(mapping.TransferParams{To: "hive:bob", Amount: "5000"})
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, allowanceOwner),
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     allowanceOwner,
		Intents:    []contracts.Intent{},
	})
	assert.False(t, r.Success, "transfer exceeding balance should fail")
	// Balance unchanged
	assert.Equal(t, encodeBalance(t, 1000), ct.StateGet(contractId, constants.BalancePrefix+allowanceOwner))
}
