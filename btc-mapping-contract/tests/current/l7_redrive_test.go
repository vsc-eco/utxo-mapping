package current_test

import (
	"strconv"
	"strings"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/require"
)

// parseRedriveNewTxId pulls the new txid out of "redrive: old=<a> new=<b> fee=<c>".
func parseRedriveNewTxId(t *testing.T, ret string) string {
	t.Helper()
	i := strings.Index(ret, "new=")
	require.GreaterOrEqual(t, i, 0, "redrive result must carry new=")
	rest := ret[i+len("new="):]
	j := strings.Index(rest, " ")
	require.GreaterOrEqual(t, j, 0)
	return rest[:j]
}

func readSweepRecord(t *testing.T, ct *test_utils.ContractTest, contractId, txId string) *mapping.MigrationSweep {
	t.Helper()
	raw := ct.StateGet(contractId, constants.MigrationSweepPrefix+txId)
	require.NotEmpty(t, raw)
	rec, err := mapping.UnmarshalMigrationSweep([]byte(raw))
	require.NoError(t, err)
	return rec
}

// TestRedriveSweep_BumpsFeeAndSettlesEither is the L7-01 end-to-end proof: a stuck migration
// sweep is re-driven into a higher-fee RBF replacement over the SAME inputs; both records stay
// live (only one can ever confirm on L1); confirming the REPLACEMENT settles it AND clears the
// whole spend group (the stuck original's "ms-" record + the group object) so rotation unwedges.
func TestRedriveSweep_BumpsFeeAndSettlesEither(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const amount = int64(100000)
	const blockHeight = uint32(100)
	fixture := buildMapFixture(t, instruction, amount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1, FeeSupply: 100000})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	seedActiveGen0(t, &ct, contractId, owner)

	// Deposit to gen-0 → one confirmed gen-0 UTXO.
	params := mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight: blockHeight, RawTxHex: fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex, TxIndex: fixture.TxIndex,
		},
		Instructions: []string{instruction},
	}
	payload, err := tinyjson.Marshal(params)
	require.NoError(t, err)
	require.True(t, ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "map-dep", BlockId: "block:map", Index: 70, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "map", Payload: payload,
		RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: owner,
	}).Success)

	// Rotate gen-0 → retiring, gen-1 → active, then build the sweep (the "original").
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "activateKey", []byte("")).Err)
	r := callKeyAction(t, &ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	sweepTxId := r.Ret
	require.NotEmpty(t, sweepTxId)

	origRec := readSweepRecord(t, &ct, contractId, sweepTxId)
	require.Len(t, origRec.InputIds, 1)
	inputId := origRec.InputIds[0]
	origFee := origRec.BtcFee
	groupKey := constants.SpendGroupPrefix + strconv.FormatUint(uint64(inputId), 10)

	// Too-early re-drive is refused (staleness gate: LastHeight still 100 == BuildHeight).
	early := callKeyAction(t, &ct, contractId, owner, "redriveSpend", []byte(sweepTxId))
	require.NotEmpty(t, early.Err, "re-drive must be refused before the staleness window")
	require.Empty(t, ct.StateGet(contractId, groupKey), "no group object created by a refused re-drive")

	// Advance past the staleness window (BuildHeight 100 + RedriveStaleBlocks 12).
	ct.StateSet(contractId, constants.LastHeightKey, "120")

	rd := callKeyAction(t, &ct, contractId, owner, "redriveSpend", []byte(sweepTxId))
	require.Empty(t, rd.Err, rd.ErrMsg)
	newTxId := parseRedriveNewTxId(t, rd.Ret)
	require.NotEqual(t, sweepTxId, newTxId, "re-drive must produce a distinct txid")

	// Both records live (only one can ever confirm); the replacement out-fees the original.
	require.NotEmpty(t, ct.StateGet(contractId, constants.MigrationSweepPrefix+sweepTxId), "original stays live until one confirms")
	newRec := readSweepRecord(t, &ct, contractId, newTxId)
	require.Greater(t, newRec.BtcFee, origFee, "re-drive bumps the fee (BIP-125)")
	require.Equal(t, origRec.InputIds, newRec.InputIds, "replacement spends the IDENTICAL inputs")

	// The spend group holds both members + the highest fee.
	graw := ct.StateGet(contractId, groupKey)
	require.NotEmpty(t, graw, "re-drive creates the spend group object")
	group, err := mapping.UnmarshalSpendGroup([]byte(graw))
	require.NoError(t, err)
	require.ElementsMatch(t, []string{sweepTxId, newTxId}, group.Members)
	require.Equal(t, newRec.BtcFee, group.HighestFee)

	// Confirm the REPLACEMENT → its settle clears the WHOLE group (H2): both "ms-" records,
	// both "d-" records, the group object — gone; the retiring gen drains.
	cr := confirmMigrationSweep(t, &ct, contractId, owner, newTxId, 121)
	require.True(t, cr.Success, cr.ErrMsg)
	require.Empty(t, ct.StateGet(contractId, constants.MigrationSweepPrefix+sweepTxId), "original ms- cleared by the group settle")
	require.Empty(t, ct.StateGet(contractId, constants.MigrationSweepPrefix+newTxId), "replacement ms- cleared")
	require.Empty(t, ct.StateGet(contractId, constants.TxSpendsPrefix+sweepTxId), "original d- cleared")
	require.Empty(t, ct.StateGet(contractId, constants.TxSpendsPrefix+newTxId), "replacement d- cleared")
	require.Empty(t, ct.StateGet(contractId, groupKey), "group object cleared")
}
