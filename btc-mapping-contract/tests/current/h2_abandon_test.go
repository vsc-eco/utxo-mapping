package current_test

// H-2 (VR2-27): a legacy unconfirmed-pool entry that does not exist on Bitcoin must not
// block rotation forever. Legacy tranches spend one input; a legacy sweep still
// unconfirmed SweepAbandonBlocks after a re-drive can be abandoned by anyone, writing its
// input off against the fee reserve; a late confirmation of an abandoned sweep settles
// and reverses the write-off net of the miner fee. The contract cannot tell an entry
// that does not exist from one that does, so these tests use seeded legacy entries and
// only ever confirm what the contract itself built.

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"vsc-node/lib/test_utils"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

const h2ReserveId = uint16(2000) // a confirmed-pool id for the reserve UTXO on gen-1

// newH2CT rotates gen-0 (holding exactly `gen0`) to RETIRING with gen-1 ACTIVE, then
// funds the fee reserve on gen-1. ActiveSupply/UserSupply equal the gen-0 total, so
// Sigma(UTXO) == ActiveSupply + FeeSupply holds from the start.
func newH2CT(t *testing.T, gen0 []utxoSeed, reserve int64) (*test_utils.ContractTest, string, string) {
	t.Helper()
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "102")
	seedActiveGen0(t, &ct, contractId, owner)
	// After the fold, so its id remap cannot touch the seeded ids.
	seedGenUtxos(t, &ct, contractId, 0, gen0)
	var total int64
	for _, s := range gen0 {
		total += s.amount
	}
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: total, UserSupply: total, BaseFeeRate: 1,
	})))
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "activateKey", []byte("")).Err)
	_, _, activeGen := loadVaults(t, &ct, contractId)
	require.Equal(t, uint32(1), activeGen)
	if reserve > 0 {
		seedReserve(t, &ct, contractId, 1, h2ReserveId, reserve)
	}
	return &ct, contractId, owner
}

func setHeight(ct *test_utils.ContractTest, contractId string, h uint32) {
	ct.StateSet(contractId, constants.LastHeightKey, strconv.FormatUint(uint64(h), 10))
}

func registryIds(t *testing.T, ct *test_utils.ContractTest, contractId string) map[uint16]int64 {
	t.Helper()
	out := map[uint16]int64{}
	raw := ct.StateGet(contractId, constants.UtxoRegistryKey)
	if raw == "" {
		return out
	}
	reg, err := mapping.UnmarshalUtxoRegistry([]byte(raw))
	require.NoError(t, err)
	for _, e := range reg {
		out[e.Id] = e.Amount
	}
	return out
}

func i1Holds(t *testing.T, ct *test_utils.ContractTest, contractId string) {
	t.Helper()
	var sum int64
	for _, a := range registryIds(t, ct, contractId) {
		sum += a
	}
	s := loadSupply(t, ct, contractId)
	require.Equal(t, sum, s.ActiveSupply+s.FeeSupply, "I1: Sigma(UTXO) == ActiveSupply + FeeSupply")
	require.Equal(t, s.ActiveSupply, s.UserSupply, "I2: ActiveSupply == UserSupply")
}

// confirmTxBytes confirms a tx the contract built, from its serialized bytes, in a
// single-tx regtest block (same shape as confirmMigrationSweep, which needs the "d-"
// record an abandon deletes).
func confirmTxBytes(t *testing.T, ct *test_utils.ContractTest, contractId, caller string, txBytes []byte, blockHeight uint32) test_utils.ContractTestCallResult {
	t.Helper()
	var tx wire.MsgTx
	require.NoError(t, tx.Deserialize(bytes.NewReader(txBytes)))
	header := buildRegtestHeader(chainhash.Hash{}, tx.TxHash(), time.Date(2025, 1, 3, 0, 0, 0, 0, time.UTC))
	ct.StateSet(contractId, constants.BlockPrefix+strconv.FormatUint(uint64(blockHeight), 10), serializeHeaderRaw(t, header))
	setHeight(ct, contractId, blockHeight+2)
	payload, err := tinyjson.Marshal(mapping.ConfirmSpendParams{
		TxData:  &mapping.VerificationRequest{BlockHeight: blockHeight, RawTxHex: hex.EncodeToString(txBytes), TxIndex: 0},
		Indices: []uint32{0},
	})
	require.NoError(t, err)
	return callAs(t, ct, contractId, caller, "confirmSpend", payload)
}

func signingTx(t *testing.T, ct *test_utils.ContractTest, contractId, txId string) []byte {
	t.Helper()
	raw := ct.StateGet(contractId, constants.TxSpendsPrefix+txId)
	require.NotEmpty(t, raw)
	sd, err := mapping.UnmarshalSigningData([]byte(raw))
	require.NoError(t, err)
	return sd.Tx
}

// migrateAndRedrive builds the sweep of the single legacy entry and re-drives it once.
func migrateAndRedrive(t *testing.T, ct *test_utils.ContractTest, contractId, owner string) (orig, repl string, replBuild uint32) {
	t.Helper()
	r := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	orig = r.Ret
	setHeight(ct, contractId, 102+constants.RedriveStaleBlocks)
	rd := callKeyAction(t, ct, contractId, owner, "redriveSpend", []byte(orig))
	require.Empty(t, rd.Err, rd.ErrMsg)
	repl = parseRedriveNewTxId(t, rd.Ret)
	return orig, repl, readSweepRecord(t, ct, contractId, repl).BuildHeight
}

func TestH2_LegacyTrancheSpendsOneInput(t *testing.T) {
	ct, contractId, owner := newH2CT(t, []utxoSeed{{5, 50_000}, {6, 60_000}, {7, 70_000}}, 100_000)
	r := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	rec := readSweepRecord(t, ct, contractId, r.Ret)
	require.Len(t, rec.InputIds, 1, "a legacy tranche spends exactly one input")
}

func TestH2_AbandonStuckLegacySweep(t *testing.T) {
	const amount = int64(40_000)
	const reserve = int64(100_000)
	ct, contractId, owner := newH2CT(t, []utxoSeed{{10, amount}}, reserve)
	stranger := "hive:some-random-account"

	r := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	orig := r.Ret
	noRedrive := callAs(t, ct, contractId, stranger, "abandonSweep", []byte(orig))
	require.False(t, noRedrive.Success, "refused before any re-drive")
	require.Contains(t, noRedrive.ErrMsg, "re-drive the sweep first")

	setHeight(ct, contractId, 102+constants.RedriveStaleBlocks)
	rd := callKeyAction(t, ct, contractId, owner, "redriveSpend", []byte(orig))
	require.Empty(t, rd.Err, rd.ErrMsg)
	repl := parseRedriveNewTxId(t, rd.Ret)
	build := readSweepRecord(t, ct, contractId, repl).BuildHeight

	setHeight(ct, contractId, build+constants.SweepAbandonBlocks-1)
	early := callAs(t, ct, contractId, stranger, "abandonSweep", []byte(orig))
	require.False(t, early.Success, "refused one block before the window")
	require.Contains(t, early.ErrMsg, "not unconfirmed long enough")
	require.Contains(t, registryIds(t, ct, contractId), uint16(10), "a refusal changes nothing")

	setHeight(ct, contractId, build+constants.SweepAbandonBlocks)
	ok := callAs(t, ct, contractId, stranger, "abandonSweep", []byte(orig))
	require.True(t, ok.Success, "anyone may abandon once the window has passed: %s", ok.ErrMsg)

	require.NotContains(t, registryIds(t, ct, contractId), uint16(10), "the input is written off")
	require.Equal(t, reserve-amount, loadSupply(t, ct, contractId).FeeSupply, "charged to the fee reserve")
	require.Equal(t, amount, loadSupply(t, ct, contractId).UserSupply, "user principal untouched")
	for _, tx := range []string{orig, repl} {
		require.Empty(t, ct.StateGet(contractId, constants.MigrationSweepPrefix+tx), "sweep record cleared")
		require.Empty(t, ct.StateGet(contractId, constants.TxSpendsPrefix+tx), "signing record cleared, nodes stop broadcasting")
		require.NotEmpty(t, ct.StateGet(contractId, constants.AbandonedSweepPrefix+tx), "kept for a late confirmation")
	}
	require.Empty(t, ct.StateGet(contractId, constants.SpendGroupPrefix+"10"), "spend group cleared")
	i1Holds(t, ct, contractId)
	require.Empty(t, callKeyAction(t, ct, contractId, owner, "createKey", []byte("")).Err,
		"with gen-0 drained, NN#3 releases and the next rotation can start")
}

func TestH2_LateConfirmationOfAbandonedSweepSettles(t *testing.T) {
	const amount = int64(40_000)
	const reserve = int64(100_000)
	ct, contractId, owner := newH2CT(t, []utxoSeed{{10, amount}}, reserve)
	orig, repl, build := migrateAndRedrive(t, ct, contractId, owner)
	replTx := signingTx(t, ct, contractId, repl)
	replFee := readSweepRecord(t, ct, contractId, repl).BtcFee
	setHeight(ct, contractId, build+constants.SweepAbandonBlocks)
	require.True(t, callAs(t, ct, contractId, owner, "abandonSweep", []byte(orig)).Success)
	before := registryIds(t, ct, contractId)

	cr := confirmTxBytes(t, ct, contractId, owner, replTx, build+constants.SweepAbandonBlocks+5)
	require.True(t, cr.Success, "a late confirmation of an abandoned sweep settles: %s", cr.ErrMsg)

	after := registryIds(t, ct, contractId)
	require.Len(t, after, len(before)+1, "the swept output is indexed")
	for id, a := range after {
		if _, had := before[id]; !had {
			require.Equal(t, amount-replFee, a, "the successor output is the input minus the miner fee")
			require.Equal(t, uint32(1), utxoGenerationForId(t, ct, contractId, id), "indexed on the successor generation")
		}
	}
	require.Equal(t, reserve-replFee, loadSupply(t, ct, contractId).FeeSupply,
		"the write-off is reversed net of the miner fee, as a normal settle would leave it")
	for _, tx := range []string{orig, repl} {
		require.Empty(t, ct.StateGet(contractId, constants.AbandonedSweepPrefix+tx), "every member's record cleared")
	}
	i1Holds(t, ct, contractId)
}

func TestH2_AbandonRefusesConfirmedInputSweep(t *testing.T) {
	ct, contractId, owner := newH2CT(t, []utxoSeed{{1500, 40_000}}, 100_000)
	orig, _, build := migrateAndRedrive(t, ct, contractId, owner)
	setHeight(ct, contractId, build+constants.SweepAbandonBlocks)
	r := callAs(t, ct, contractId, owner, "abandonSweep", []byte(orig))
	require.False(t, r.Success, "a confirmed-pool input was SPV-proven to exist; its sweep is only ever slow")
	require.Contains(t, r.ErrMsg, "single legacy input")
	require.Contains(t, registryIds(t, ct, contractId), uint16(1500))
}

func TestH2_AbandonRefusedWhenReserveShort(t *testing.T) {
	const amount = int64(40_000)
	ct, contractId, owner := newH2CT(t, []utxoSeed{{10, amount}}, 5_000)
	orig, _, build := migrateAndRedrive(t, ct, contractId, owner)
	setHeight(ct, contractId, build+constants.SweepAbandonBlocks)
	r := callAs(t, ct, contractId, owner, "abandonSweep", []byte(orig))
	require.False(t, r.Success, "the write-off must be covered by the reserve")
	require.Contains(t, r.ErrMsg, "insufficient fee reserve")
	require.Contains(t, registryIds(t, ct, contractId), uint16(10), "nothing written off")
}

// Two legacy entries that can only be swept together: with one input per tranche
// migration cannot sweep either, so the dust write-off must treat them as stuck,
// or the generation would wedge.
func TestH2_WriteOffLegacyEntriesSweepableOnlyTogether(t *testing.T) {
	// A one-input sweep of an untagged legacy entry costs about 134 sats at 1 sat/vbyte,
	// leaving 466, under the 546 dust floor; two together clear it easily.
	const small = int64(600)
	ct, contractId, owner := newH2CT(t, []utxoSeed{{11, small}, {12, small}}, 10_000)
	m := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.NotEmpty(t, m.Err, "a single small legacy entry cannot be swept on its own")
	w := callKeyAction(t, ct, contractId, owner, "writeOffDust", []byte(""))
	require.Empty(t, w.Err, w.ErrMsg)
	ids := registryIds(t, ct, contractId)
	require.NotContains(t, ids, uint16(11))
	require.NotContains(t, ids, uint16(12))
	require.Equal(t, int64(10_000-2*small), loadSupply(t, ct, contractId).FeeSupply)
	i1Holds(t, ct, contractId)
	require.Empty(t, callKeyAction(t, ct, contractId, owner, "createKey", []byte("")).Err, "NN#3 releases")
}

// Confirmed dust that cannot be swept at any rate must not keep migration from
// reaching a sweepable legacy entry behind it.
func TestH2_UnbuildableConfirmedDustDoesNotBlockLegacy(t *testing.T) {
	ct, contractId, owner := newH2CT(t, []utxoSeed{{1500, 300}, {13, 50_000}}, 100_000)
	r := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	rec := readSweepRecord(t, ct, contractId, r.Ret)
	require.Equal(t, []uint16{13}, rec.InputIds, "the legacy entry is swept, not the unbuildable dust")
}
