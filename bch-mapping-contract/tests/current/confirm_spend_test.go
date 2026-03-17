package current_test

import (
	"bch-mapping-contract/contract/constants"
	"bch-mapping-contract/contract/mapping"
	"fmt"
	"testing"
	"time"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"
)

// setupConfirmSpendContract creates a contract with an unmap state:
// two confirmed UTXOs, a pending spend that consumed one and produced an unconfirmed change.
func setupConfirmSpendContract(t *testing.T) (*test_utils.ContractTest, string, string) {
	t.Helper()
	const instruction = "deposit_to=hive:milo-hpr"
	const fakeTxId0 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// spendTxId is the txId of the withdrawal transaction (what the bot broadcasts)
	const spendTxId = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.BalancePrefix+"hive:milo-hpr", encodeBalance(t, 5000))

	// One confirmed UTXO (id=64) still in pool
	ct.StateSet(contractId, constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(mapping.UtxoRegistry{
		{Id: 64, Amount: 5000},
		{Id: 0, Amount: 2000}, // unconfirmed change from the spend
	})))
	ct.StateSet(contractId, constants.UtxoPrefix+"40", depositUtxoBinary(t, fakeTxId0, 0, 5000, instruction))
	ct.StateSet(contractId, constants.UtxoPrefix+"0", changeUtxoBinary(t, spendTxId, 1, 2000))
	ct.StateSet(contractId, constants.UtxoLastIdKey, string([]byte{65, 1}))

	// Create signing data for the pending spend so updateUtxoSpends can find it.
	// The signing data contains UnsignedSigHashes with the spend tx's change output index.
	sigData := mapping.SigningData{
		Tx: []byte{0x01}, // dummy tx bytes
		UnsignedSigHashes: []mapping.UnsignedSigHash{
			{Index: 1, SigHash: []byte{0x00}, WitnessScript: []byte{0x00}},
		},
	}
	sigDataBytes, err := mapping.MarshalSigningData(&sigData)
	if err != nil {
		t.Fatal("error marshalling signing data:", err)
	}
	ct.StateSet(contractId, constants.TxSpendsPrefix+spendTxId, string(sigDataBytes))

	// Tx spends registry with the pending spend
	ct.StateSet(contractId, constants.TxSpendsRegistryKey, string(mapping.MarshalTxSpendsRegistry(mapping.TxSpendsRegistry{spendTxId})))

	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: 5000,
		UserSupply:   5000,
		BaseFeeRate:  1,
	})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", buildSeedHeaderRaw(t, time.Unix(0, 0)))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	return &ct, contractId, spendTxId
}

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

// TestConfirmSpend verifies that calling confirmSpend with a known pending
// spend txId promotes unconfirmed change UTXOs to the confirmed pool and
// removes the spend from the pending registry.
func TestConfirmSpend(t *testing.T) {
	ct, contractId, spendTxId := setupConfirmSpendContract(t)

	r := callConfirmSpend(t, ct, contractId, "hive:milo-hpr", spendTxId)
	if r.Err != "" {
		fmt.Printf("%s: %s\n", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success, "confirmSpend should succeed")

	dumpStateDiff(t, r.StateDiff)

	// The pending spend entry should be removed
	assert.Equal(t, "", ct.StateGet(contractId, constants.TxSpendsPrefix+spendTxId),
		"signing data for confirmed spend should be deleted")

	// The tx spends registry should be empty (no more pending spends)
	registryRaw := ct.StateGet(contractId, constants.TxSpendsRegistryKey)
	if registryRaw != "" {
		txSpends, err := mapping.UnmarshalTxSpendsRegistry([]byte(registryRaw))
		assert.NoError(t, err)
		assert.NotContains(t, txSpends, spendTxId, "spendTxId should be removed from registry")
	}
}

// TestConfirmSpendUnknownTxId verifies that calling confirmSpend with a
// non-existent txId is a successful no-op.
func TestConfirmSpendUnknownTxId(t *testing.T) {
	ct, contractId, _ := setupConfirmSpendContract(t)

	unknownTxId := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	r := callConfirmSpend(t, ct, contractId, "hive:milo-hpr", unknownTxId)
	assert.True(t, r.Success, "confirmSpend with unknown txId should succeed (no-op)")
}

// TestConfirmSpendNotAdmin verifies that a non-admin caller is rejected.
func TestConfirmSpendNotAdmin(t *testing.T) {
	ct, contractId, spendTxId := setupConfirmSpendContract(t)

	r := callConfirmSpend(t, ct, contractId, "hive:unauthorized-user", spendTxId)
	assert.False(t, r.Success, "confirmSpend by non-admin should fail")
	assert.NotEmpty(t, r.Err)
}

// TestConfirmSpendEmptyTxId verifies that an empty tx_id is rejected.
func TestConfirmSpendEmptyTxId(t *testing.T) {
	ct, contractId, _ := setupConfirmSpendContract(t)

	r := callConfirmSpend(t, ct, contractId, "hive:milo-hpr", "")
	assert.False(t, r.Success, "confirmSpend with empty txId should fail")
	assert.NotEmpty(t, r.Err)
}
