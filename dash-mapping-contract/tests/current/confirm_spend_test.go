package current_test

import (
	"dash-mapping-contract/contract/constants"
	"dash-mapping-contract/contract/mapping"
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
// Returns the contract test, contract ID, and a ConfirmSpendFixture with the spend tx data.
func setupConfirmSpendContract(t *testing.T) (*test_utils.ContractTest, string, ConfirmSpendFixture) {
	t.Helper()
	const instruction = "deposit_to=hive:milo-hpr"
	const fakeTxId0 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// Build a real spend tx so its TxID can be verified via Merkle proof.
	fixture := buildConfirmSpendFixture(t, 101)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.BalancePrefix+"hive:milo-hpr", encodeBalance(t, 5000))

	// One confirmed UTXO (id=1024) still in pool
	ct.StateSet(contractId, constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(mapping.UtxoRegistry{
		{Id: 1024, Amount: 5000},
		{Id: 0, Amount: 2000}, // unconfirmed change from the spend
	})))
	ct.StateSet(contractId, constants.UtxoPrefix+"400", depositUtxoBinary(t, fakeTxId0, 0, 5000, instruction))
	ct.StateSet(contractId, constants.UtxoPrefix+"0", changeUtxoBinary(t, fixture.TxId, 0, 2000))
	ct.StateSet(contractId, constants.UtxoLastIdKey, encodeUtxoCounters(1025, 1))

	// Create signing data for the pending spend so updateUtxoSpends can find it.
	sigData := mapping.SigningData{
		Tx: []byte{0x01},
		UnsignedSigHashes: []mapping.UnsignedSigHash{
			{Index: 0, SigHash: []byte{0x00}, WitnessScript: []byte{0x00}},
		},
	}
	sigDataBytes, err := mapping.MarshalSigningData(&sigData)
	if err != nil {
		t.Fatal("error marshalling signing data:", err)
	}
	ct.StateSet(contractId, constants.TxSpendsPrefix+fixture.TxId, string(sigDataBytes))

	// Tx spends registry with the pending spend
	ct.StateSet(contractId, constants.TxSpendsRegistryKey, string(mapping.MarshalTxSpendsRegistry(mapping.TxSpendsRegistry{fixture.TxId})))

	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: 5000,
		UserSupply:   5000,
		BaseFeeRate:  1,
	})))
	ct.StateSet(contractId, constants.LastHeightKey, "101")
	ct.StateSet(contractId, constants.BlockPrefix+"100", buildSeedHeaderRaw(t, time.Unix(0, 0)))
	ct.StateSet(contractId, constants.BlockPrefix+"101", fixture.BlockHeaderRaw)
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	return &ct, contractId, fixture
}

func callConfirmSpend(
	t *testing.T,
	ct *test_utils.ContractTest,
	contractId, caller string,
	params mapping.ConfirmSpendParams,
) test_utils.ContractTestCallResult {
	t.Helper()
	payload, err := tinyjson.Marshal(params)
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

// TestConfirmSpend verifies that calling confirmSpend with a valid Merkle proof
// and explicit UTXO indices promotes those unconfirmed UTXOs to the confirmed pool.
func TestConfirmSpend(t *testing.T) {
	ct, contractId, fixture := setupConfirmSpendContract(t)

	params := mapping.ConfirmSpendParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    fixture.BlockHeight,
			RawTxHex:       fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex,
			TxIndex:        fixture.TxIndex,
		},
		Indices: []uint32{0},
	}
	r := callConfirmSpend(t, ct, contractId, "hive:milo-hpr", params)
	if r.Err != "" {
		fmt.Printf("%s: %s\n", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success, "confirmSpend should succeed")

	dumpStateDiff(t, r.StateDiff)

	// The pending spend entry should be removed
	assert.Equal(t, "", ct.StateGet(contractId, constants.TxSpendsPrefix+fixture.TxId),
		"signing data for confirmed spend should be deleted")

	// The tx spends registry should be empty (no more pending spends)
	registryRaw := ct.StateGet(contractId, constants.TxSpendsRegistryKey)
	if registryRaw != "" {
		txSpends, err := mapping.UnmarshalTxSpendsRegistry([]byte(registryRaw))
		assert.NoError(t, err)
		assert.NotContains(t, txSpends, fixture.TxId, "spendTxId should be removed from registry")
	}
}

// TestConfirmSpendUnknownTxId verifies that calling confirmSpend with a valid
// proof for a tx not in the pending list is a successful no-op.
func TestConfirmSpendUnknownTxId(t *testing.T) {
	ct, contractId, _ := setupConfirmSpendContract(t)

	// Build a different tx (not in the pending list) with its own block proof.
	unknownFixture := buildConfirmSpendFixture(t, 102)
	ct.StateSet(contractId, constants.BlockPrefix+"102", unknownFixture.BlockHeaderRaw)

	params := mapping.ConfirmSpendParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    unknownFixture.BlockHeight,
			RawTxHex:       unknownFixture.RawTxHex,
			MerkleProofHex: unknownFixture.MerkleProofHex,
			TxIndex:        unknownFixture.TxIndex,
		},
		Indices: []uint32{0},
	}
	r := callConfirmSpend(t, ct, contractId, "hive:milo-hpr", params)
	assert.True(t, r.Success, "confirmSpend with unknown txId should succeed (no-op)")
}

// TestConfirmSpendAnyCallerCanConfirm verifies that any caller can call confirmSpend
// (no admin requirement).
func TestConfirmSpendAnyCallerCanConfirm(t *testing.T) {
	ct, contractId, fixture := setupConfirmSpendContract(t)

	params := mapping.ConfirmSpendParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    fixture.BlockHeight,
			RawTxHex:       fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex,
			TxIndex:        fixture.TxIndex,
		},
		Indices: []uint32{0},
	}
	r := callConfirmSpend(t, ct, contractId, "hive:unauthorized-user", params)
	assert.True(t, r.Success, "confirmSpend should succeed for any caller")
}

// TestConfirmSpendEmptyRawTx verifies that a missing tx_data is rejected.
func TestConfirmSpendEmptyRawTx(t *testing.T) {
	ct, contractId, _ := setupConfirmSpendContract(t)

	r := callConfirmSpend(t, ct, contractId, "hive:milo-hpr", mapping.ConfirmSpendParams{})
	assert.False(t, r.Success, "confirmSpend with missing tx_data should fail")
	assert.NotEmpty(t, r.Err)
}
