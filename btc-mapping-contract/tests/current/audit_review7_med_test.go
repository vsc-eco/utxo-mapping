package current_test

// review7 btc-mapping MED fixes — runtime tests against the rebuilt dev.wasm.

import (
	"testing"
	"time"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"

	"vsc-node/modules/db/vsc/contracts"
)

// MED-1 (D13): `approve` (and increase/decreaseAllowance) must require ACTIVE
// auth. A posting-key-only call previously succeeded, letting an attacker set an
// allowance and drain via transferFrom.
func TestAuditReview7_MED1_AllowanceRequiresActiveAuth(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 100000)

	payload, err := tinyjson.Marshal(mapping.AllowanceParams{Spender: allowanceSpender, Amount: "5000"})
	if err != nil {
		t.Fatal(err)
	}

	// Posting-auth ONLY (no active auth) → must be rejected.
	postingSelf := stateEngine.TxSelf{
		TxId:                 "med1-posting",
		BlockId:              "med1-posting",
		Index:                0,
		OpIndex:              0,
		Timestamp:            time.Now().String(),
		RequiredAuths:        []string{},
		RequiredPostingAuths: []string{allowanceOwner},
	}
	for _, action := range []string{"approve", "increaseAllowance", "decreaseAllowance"} {
		r := ct.Call(stateEngine.TxVscCallContract{
			Self:       postingSelf,
			ContractId: contractId,
			Action:     action,
			Payload:    payload,
			RcLimit:    1000,
			Caller:     allowanceOwner,
			Intents:    []contracts.Intent{},
		})
		assert.Falsef(t, r.Success, "%s with posting-only auth must be rejected (MED-1)", action)
	}

	// No allowance must have been written by any of the rejected posting calls.
	key := constants.AllowancePrefix + allowanceOwner + constants.DirPathDelimiter + allowanceSpender
	assert.Equal(t, "", ct.StateGet(contractId, key),
		"a rejected posting-auth approve must not write an allowance")

	// Control: active auth succeeds and writes the allowance.
	r := callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 5000)
	assert.True(t, r.Success, "approve with active auth should succeed")
	assert.Equal(t, encodeBalance(t, 5000), ct.StateGet(contractId, key),
		"active-auth approve should write the allowance")
}
