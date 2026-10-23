package current_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CON-MAP-1 (testnet 2026-10-22): a map whose outputs match no deposit-matchable
// address (there: a deposit to a PURGED generation) succeeded with no log at all,
// indistinguishable from a credited map. It must still succeed (a map also
// reconciles the vault's own pending spends), and now says it credited nothing.

func runMapForInstruction(t *testing.T, fixtureInstr, mapInstr string) (bool, []string, string) {
	ok, logs, txid, _ := runMapWith(t, fixtureInstr, mapInstr, false)
	return ok, logs, txid
}

// runMapWith maps the fixture tx; pendingSpend registers that tx as a pending vault
// spend first (a "d-" record), the case a credit-less map exists to reconcile. The
// returned state getter reads the contract's state after the call.
func runMapWith(t *testing.T, fixtureInstr, mapInstr string, pendingSpend bool) (bool, []string, string, func(string) string) {
	t.Helper()
	const blockHeight = uint32(100)
	fixture := buildMapFixture(t, fixtureInstr, 10000, blockHeight)
	raw, err := hex.DecodeString(fixture.RawTxHex)
	require.NoError(t, err)
	var tx wire.MsgTx
	require.NoError(t, tx.Deserialize(bytes.NewReader(raw)))

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "102")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	txid := tx.TxHash().String()
	if pendingSpend {
		sd, err := mapping.MarshalSigningData(&mapping.SigningData{Tx: []byte{0x01},
			UnsignedSigHashes: []mapping.UnsignedSigHash{{Index: 7, SigHash: []byte{0x00}, WitnessScript: []byte{0x00}}}})
		require.NoError(t, err)
		ct.StateSet(contractId, constants.TxSpendsPrefix+txid, string(sd))
		ct.StateSet(contractId, constants.TxSpendsRegistryKey, string(mapping.MarshalTxSpendsRegistry(mapping.TxSpendsRegistry{txid})))
	}

	payload, err := tinyjson.Marshal(mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight: blockHeight, RawTxHex: fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex, TxIndex: fixture.TxIndex,
		},
		Instructions: []string{mapInstr},
	})
	require.NoError(t, err)
	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: "sometxid", BlockId: "block:map", Index: 69, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{"hive:milo-hpr"},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId, Action: "map", Payload: payload, RcLimit: 10000,
		Intents: []contracts.Intent{}, Caller: "hive:milo-hpr",
	})
	dumpLogs(t, r.Logs)
	return r.Success, r.Logs[contractId].Logs, txid, func(k string) string { return ct.StateGet(contractId, k) }
}

// The reason a credit-less map must keep succeeding: it reconciles the vault's own
// pending spend. It still does, and now says what it was ("s=1").
func TestMapCreditingNothingStillReconcilesAVaultSpend(t *testing.T) {
	ok, logs, txid, state := runMapWith(t, "deposit_to=hive:milo-hpr", "deposit_to=hive:someone-else", true)
	assert.True(t, ok, "the reconcile path must not be refused")
	assert.Contains(t, logs, "mapnone|tx="+txid+"|s=1")
	assert.Empty(t, state(constants.TxSpendsPrefix+txid), "the pending spend record was reconciled (cleared)")
}

func TestMapCreditingNothingSucceedsAndSaysSo(t *testing.T) {
	ok, logs, txid := runMapForInstruction(t, "deposit_to=hive:milo-hpr", "deposit_to=hive:someone-else")
	assert.True(t, ok, "a map that credits nothing must still succeed (it also reconciles vault spends)")
	assert.Contains(t, logs, "mapnone|tx="+txid+"|s=0", "it reports that it credited nothing")
	for _, l := range logs {
		assert.False(t, strings.HasPrefix(l, "map|"), "no deposit log for a non-matching output: %s", l)
	}
}

func TestMapCreditingADepositDoesNotLogMapNone(t *testing.T) {
	ok, logs, _ := runMapForInstruction(t, "deposit_to=hive:milo-hpr", "deposit_to=hive:milo-hpr")
	assert.True(t, ok)
	found := false
	for _, l := range logs {
		assert.False(t, strings.HasPrefix(l, "mapnone|"), "a credited map must not say it credited nothing: %s", l)
		found = found || strings.HasPrefix(l, "map|")
	}
	assert.True(t, found, "the credited deposit is logged as before")
}
