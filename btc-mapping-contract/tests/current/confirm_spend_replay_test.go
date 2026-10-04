package current_test

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// TestConfirmSpendReplayRefused is the adversarial guard on the confirmSpend fix
// (commit 5176bb9: the empty-promotedVouts guard now yields to the ms-/us- settle
// record). The fix makes an already-settled record's promotion legitimately empty,
// so the danger is a REPLAY: settling the same confirmed tx twice must NOT
// double-index the successor output or double-debit the fee reserve. It must be
// refused, because clearSpendGroup deletes the ms-/us-/d- records at settle, so the
// second call sees no record AND no unconfirmed output to promote.
func TestConfirmSpendReplayRefused(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1, FeeSupply: 100000})))

	// gen-0 active + one confirmed deposit, then rotate so gen-0 is retiring.
	const amount = int64(5_000_000)
	seedActiveGen0(t, &ct, contractId, owner)
	fx := buildMapFixture(t, "deposit_to=hive:milo-hpr", amount, 100)
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fx.BlockHeaderHex))
	mapParams := mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight: 100, RawTxHex: fx.RawTxHex, MerkleProofHex: fx.MerkleProofHex, TxIndex: fx.TxIndex,
		},
		Instructions: []string{"deposit_to=hive:milo-hpr"},
	}
	mapPayload, err := tinyjson.Marshal(mapParams)
	require.NoError(t, err)
	// VR2-07: a deposit is refused until its block is MinConfirmationDepth below the
	// contract's tip, so the tip must sit above the deposit's block. Only the header
	// at 100 is needed for the proof; the margin just has to exist.
	ct.StateSet(contractId, constants.LastHeightKey, "102")
	require.True(t, ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "map-dep", BlockId: "block:map", Index: 70, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "map", Payload: mapPayload,
		RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: owner,
	}).Success)

	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "activateKey", []byte("")).Err)

	// Build the sweep.
	mig := callKeyAction(t, &ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, mig.Err, mig.ErrMsg)
	sweepTxId := mig.Ret
	require.NotEmpty(t, sweepTxId)

	// Capture the EXACT confirmSpend payload now, BEFORE settling — after settle the
	// d-/ms- records are gone, so we could not rebuild it (that is the whole point).
	const confirmHeight = uint32(101)
	sigRaw := ct.StateGet(contractId, constants.TxSpendsPrefix+sweepTxId)
	require.NotEmpty(t, sigRaw)
	sd, err := mapping.UnmarshalSigningData([]byte(sigRaw))
	require.NoError(t, err)
	var sweepTx wire.MsgTx
	require.NoError(t, sweepTx.Deserialize(bytes.NewReader(sd.Tx)))
	header := buildRegtestHeader(chainhash.Hash{}, sweepTx.TxHash(), time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC))
	ct.StateSet(contractId, constants.BlockPrefix+strconv.FormatUint(uint64(confirmHeight), 10), serializeHeaderRaw(t, header))
	// VR2-06: a settle waits the same depth as a credit, so the tip must clear the
	// spend's block by the same margin.
	ct.StateSet(contractId, constants.LastHeightKey, strconv.FormatUint(uint64(confirmHeight)+2, 10))
	confirmPayload, err := tinyjson.Marshal(mapping.ConfirmSpendParams{
		TxData:  &mapping.VerificationRequest{BlockHeight: confirmHeight, RawTxHex: hex.EncodeToString(sd.Tx), MerkleProofHex: "", TxIndex: 0},
		Indices: []uint32{0},
	})
	require.NoError(t, err)

	submitConfirm := func(txTag string) test_utils.ContractTestCallResult {
		return ct.Call(stateEngine.TxVscCallContract{
			Self: stateEngine.TxSelf{TxId: txTag, BlockId: "block:confirm", Index: 72, OpIndex: 0,
				Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
			ContractId: contractId, Action: "confirmSpend", Payload: confirmPayload,
			RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: owner,
		})
	}

	// FIRST settle — succeeds, indexes the successor output, debits the fee.
	first := submitConfirm("confirm-1")
	require.True(t, first.Success, first.ErrMsg)

	regAfter1, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	supAfter1, err := mapping.UnmarshalSupply([]byte(ct.StateGet(contractId, constants.SupplyKey)))
	require.NoError(t, err)
	require.Len(t, regAfter1, 1, "one UTXO after the first settle (the successor output)")

	// SECOND settle — REPLAY of the identical payload. Must be REFUSED.
	second := submitConfirm("confirm-2-replay")
	require.False(t, second.Success,
		"a replayed confirmSpend of an already-settled sweep MUST be refused (no double-index / double-debit)")

	// And crucially: state is UNCHANGED by the refused replay — no second successor
	// output, no second fee debit.
	regAfter2, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	supAfter2, err := mapping.UnmarshalSupply([]byte(ct.StateGet(contractId, constants.SupplyKey)))
	require.NoError(t, err)
	require.Equal(t, len(regAfter1), len(regAfter2), "the refused replay must not add a second successor output")
	require.Equal(t, regAfter1[0].Amount, regAfter2[0].Amount, "the successor output amount is unchanged by the replay")
	require.Equal(t, supAfter1.FeeSupply, supAfter2.FeeSupply, "the refused replay must not debit the fee reserve twice")
	require.Equal(t, supAfter1.ActiveSupply, supAfter2.ActiveSupply, "ActiveSupply unchanged by the replay")
}
