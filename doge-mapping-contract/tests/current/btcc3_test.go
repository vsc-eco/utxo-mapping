package current_test

import (
	"doge-mapping-contract/contract/constants"
	"doge-mapping-contract/contract/mapping"
	"encoding/binary"
	"strconv"
	"testing"
	"time"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Pentest finding BTC-C3: HandleUnmap previously had no aggregate
// rate limit. A TSS-quorum compromise (12 of 19 colluding witnesses)
// could drain the entire bridge in a single Hive block since they
// signed every unmap that arrived. The fix introduces a per-Hive-
// block accumulator at constants.BlockUnmapAccKey and rejects any
// unmap that would push the accumulator above getMaxUnmapPerBlock().
//
// This test stages enough balance for two unmaps that together
// exceed a deliberately-low cap. The first succeeds; the second
// (same Hive block) is rejected. After we advance the Hive block
// height, a third unmap of the same size succeeds — proving the
// accumulator resets per block.

const btcc3Instruction = "deposit_to=hive:milo-hpr"

// Match TestUnmap's seed pattern but with the test contract and
// distinct UTXO IDs so we don't collide if other tests run in
// parallel against shared state.
func btcc3SetupContract(t *testing.T, ct *test_utils.ContractTest, contractId string, balance int64, utxoSlots ...int64) {
	t.Helper()
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.BalancePrefix+"hive:milo-hpr", encodeBalance(t, balance))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	// Stage UTXOs: each input is a separate confirmed UTXO with a
	// unique txid so the BTC tx builder doesn't collide.
	registry := mapping.UtxoRegistry{}
	idBase := uint16(2048)
	for i, amount := range utxoSlots {
		txId := make([]byte, 32)
		txId[0] = byte(0xc3)
		txId[1] = byte(i + 1)
		txIdHex := ""
		for _, b := range txId {
			txIdHex += strconv.FormatInt(int64(b/16), 16) + strconv.FormatInt(int64(b%16), 16)
		}
		registry = append(registry, mapping.UtxoRegistryEntry{Id: idBase + uint16(i), Amount: amount})
		// 0x...stem of internal id in lowercase hex
		key := constants.UtxoPrefix + strconv.FormatInt(int64(idBase+uint16(i)), 16)
		ct.StateSet(contractId, key, depositUtxoBinary(t, txIdHex, uint32(i), amount, btcc3Instruction))
	}
	ct.StateSet(contractId, constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(registry)))
	ct.StateSet(contractId, constants.UtxoLastIdKey, encodeUtxoCounters(idBase+uint16(len(utxoSlots)+1), 0))

	totalSupply := int64(0)
	for _, a := range utxoSlots {
		totalSupply += a
	}
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: totalSupply,
		UserSupply:   totalSupply,
		FeeSupply:    0,
		BaseFeeRate:  1,
	})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", buildSeedHeaderRaw(t, time.Unix(0, 0)))
}

func btcc3Unmap(t *testing.T, ct *test_utils.ContractTest, contractId string, amountSats int64, blockId string) test_utils.ContractTestCallResult {
	t.Helper()
	payload, err := tinyjson.Marshal(mapping.TransferParams{
		Amount: strconv.FormatInt(amountSats, 10),
		To:     regtestDestAddress(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	return ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "btcc3-" + blockId,
			BlockId:              "block:" + blockId,
			Index:                0,
			OpIndex:              0,
			Timestamp:            "2026-05-07T00:00:00",
			RequiredAuths:        []string{"hive:milo-hpr"},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "unmap",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})
}

// decodeAccumulator reads the 16-byte BTC-C3 accumulator off state.
func decodeAccumulator(raw string) (height uint64, accum int64) {
	if len(raw) != 16 {
		return 0, 0
	}
	b := []byte(raw)
	height = binary.BigEndian.Uint64(b[0:8])
	accum = int64(binary.BigEndian.Uint64(b[8:16]))
	return
}

func TestBTCC3_PerBlockUnmapCapEnforced(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })

	const contractId = "btcc3_cap"
	// Balance + UTXOs sized so two ~4500-sat unmaps would together
	// breach a 6000-sat cap. Each UTXO is 5000 sats so each unmap
	// can stand alone.
	btcc3SetupContract(t, &ct, contractId, 20000, 5000, 5000, 5000, 5000)

	// Set the cap deliberately low so the second unmap in the same
	// Hive block trips the limit. 6000 sats < amount (4500) + amount (4500).
	w := &ctWrapper{ct: &ct}
	r := callActionOnContract(t, w, contractId, "setMaxUnmapPerBlock", "6000", "hive:milo-hpr")
	require.True(t, r.Success, "setMaxUnmapPerBlock should succeed: %s %s", r.Err, r.ErrMsg)
	assert.Equal(t, "6000", ct.StateGet(contractId, constants.MaxUnmapPerBlockKey))

	// First unmap in block A — within the cap (finalAmt ≈ 4500 + small fees).
	r1 := btcc3Unmap(t, &ct, contractId, 4500, "blockA")
	require.True(t, r1.Success, "first unmap (within cap) should succeed: %s %s", r1.Err, r1.ErrMsg)

	// Second unmap in the same Hive block — accumulator + finalAmt2 > cap.
	r2 := btcc3Unmap(t, &ct, contractId, 4500, "blockA")
	if r2.Success {
		t.Fatalf("BTC-C3 leak: second unmap in same Hive block was not rejected by the rate limit. ret=%q", r2.Ret)
	}
	assert.Contains(t, r2.ErrMsg, "rate limit",
		"expected rate-limit rejection, got: %s %s", r2.Err, r2.ErrMsg)

	// Verify the on-state accumulator reflects only the first unmap
	// (the second unmap was rejected before saveUnmapAccumulator).
	rawAcc := ct.StateGet(contractId, constants.BlockUnmapAccKey)
	_, accum := decodeAccumulator(rawAcc)
	assert.Greater(t, accum, int64(0), "accumulator must be positive after successful unmap")
	assert.LessOrEqual(t, accum, int64(6000), "accumulator must not exceed the cap")

	// Advance the Hive block height — accumulator should reset for the
	// next unmap.
	ct.IncrementBlocks(1)
	r3 := btcc3Unmap(t, &ct, contractId, 4500, "blockB")
	require.True(t, r3.Success, "unmap in NEXT Hive block should succeed (accumulator reset): %s %s", r3.Err, r3.ErrMsg)
}

func TestBTCC3_DisabledByZeroCap(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })

	const contractId = "btcc3_disabled"
	btcc3SetupContract(t, &ct, contractId, 20000, 5000, 5000, 5000)

	// Explicitly disable the rate limit. Two big unmaps in the same
	// Hive block should both succeed.
	w := &ctWrapper{ct: &ct}
	r := callActionOnContract(t, w, contractId, "setMaxUnmapPerBlock", "0", "hive:milo-hpr")
	require.True(t, r.Success, "setMaxUnmapPerBlock(0) should succeed: %s %s", r.Err, r.ErrMsg)
	assert.Equal(t, "0", ct.StateGet(contractId, constants.MaxUnmapPerBlockKey))

	r1 := btcc3Unmap(t, &ct, contractId, 4500, "blockA")
	require.True(t, r1.Success, "first unmap with cap=0 should succeed: %s %s", r1.Err, r1.ErrMsg)
	r2 := btcc3Unmap(t, &ct, contractId, 4500, "blockA2")
	require.True(t, r2.Success, "second unmap with cap=0 should succeed: %s %s", r2.Err, r2.ErrMsg)
}

func TestBTCC3_SetMaxUnmapPerBlockRejectsNonAdmin(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })

	const contractId = "btcc3_auth"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)

	w := &ctWrapper{ct: &ct}
	r := callActionOnContract(t, w, contractId, "setMaxUnmapPerBlock", "1000000", "hive:attacker")
	assert.False(t, r.Success, "setMaxUnmapPerBlock by non-admin must be rejected")
}

func TestBTCC3_SetMaxUnmapPerBlockRejectsNegative(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })

	const contractId = "btcc3_negative"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)

	w := &ctWrapper{ct: &ct}
	r := callActionOnContract(t, w, contractId, "setMaxUnmapPerBlock", "-1", "hive:milo-hpr")
	assert.False(t, r.Success, "negative cap must be rejected")
}
