package current_test

// Two mainnet faults found 11-05 (user report, audiohive-me), both in the real wasm:
//
// MAP-SIZE-1: a deposit inside a batched exchange withdrawal (Uphold, 122 outputs,
// 4,100 bytes) could never be mapped: the node refuses a contract call whose payload
// passes 8,192 bytes (state-processing MAX_CONTRACT_PAYLOAD_SIZE) and raw_tx_hex
// doubles the transaction (9,040-byte map). raw_tx_b64 of the transaction without
// its witness maps it.
//
// DUST-DEDUCT-1: a deduct_fee unmap whose coin left sub-dust change burned it and
// charged it on top of `amount`, so a caller holding exactly `amount` (the DEX
// router settling a swap output: 'balance 1468 insufficient needs 1883') could not
// pay. Coins are now selected so the leftover is a change output.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/common/params"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"
)

// batchedDepositTx pays `amount` to depositAddr among `others` outputs to unrelated
// P2WPKH scripts (an exchange's batched withdrawal), from one segwit input.
func batchedDepositTx(t *testing.T, depositAddr string, amount int64, others int) *wire.MsgTx {
	t.Helper()
	tx := buildTestTx(t, depositAddr, amount)
	tx.TxIn[0].SignatureScript = nil
	tx.TxIn[0].Witness = wire.TxWitness{bytes.Repeat([]byte{0x30}, 72), bytes.Repeat([]byte{0x02}, 33)}
	for i := 0; i < others; i++ {
		script := append([]byte{0x00, 0x14}, bytes.Repeat([]byte{byte(i)}, 20)...)
		tx.AddTxOut(&wire.TxOut{Value: 10_000 + int64(i), PkScript: script})
	}
	return tx
}

func noWitnessBytes(t *testing.T, tx *wire.MsgTx) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, tx.SerializeNoWitness(&buf))
	return buf.Bytes()
}

func mapsize1Contract(t *testing.T, header *wire.BlockHeader) (*test_utils.ContractTest, string) {
	t.Helper()
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "102")
	ct.StateSet(contractId, constants.BlockPrefix+"100", serializeHeaderRaw(t, header))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	return &ct, contractId
}

func mapsize1Call(ct *test_utils.ContractTest, contractId string, payload []byte, txId string) test_utils.ContractTestCallResult {
	return ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: txId, BlockId: "block:" + txId, Timestamp: "2025-10-14T00:00:00",
			RequiredAuths: []string{"hive:milo-hpr"}, RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "map",
		Payload:    payload,
		RcLimit:    100_000,
		Intents:    []contracts.Intent{},
		Caller:     "hive:milo-hpr",
	})
}

// MAP-SIZE-1: the batched deposit whose hex map passes the node's payload cap maps
// in base64 without its witness, and credits the depositor once.
func TestMAPSIZE1_ABatchedExchangeDepositMapsInBase64(t *testing.T) {
	const instruction = "deposit_to=hive:audiohive-me"
	const user = "hive:audiohive-me"
	const amount = int64(25_000)
	addr, _, err := mapping.DepositAddress(TestPrimaryPubKeyHex, TestBackupPubKeyHex, instruction, regtestParams())
	require.NoError(t, err)
	tx := batchedDepositTx(t, addr, amount, 140)
	header := buildRegtestHeader(chainhash.Hash{}, tx.TxHash(), time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))

	hexPayload, err := tinyjson.Marshal(mapping.MapParams{
		TxData:       &mapping.VerificationRequest{BlockHeight: 100, RawTxHex: serializeTx(t, tx)},
		Instructions: []string{instruction},
	})
	require.NoError(t, err)
	b64Payload, err := tinyjson.Marshal(mapping.MapParams{
		TxData:       &mapping.VerificationRequest{BlockHeight: 100, RawTxB64: base64.StdEncoding.EncodeToString(noWitnessBytes(t, tx))},
		Instructions: []string{instruction},
	})
	require.NoError(t, err)
	t.Logf("map payload: hex %d bytes, base64 without witness %d bytes (node cap %d)", len(hexPayload), len(b64Payload), params.MAX_CONTRACT_PAYLOAD_SIZE)
	require.Greater(t, len(hexPayload), params.MAX_CONTRACT_PAYLOAD_SIZE, "the fixture must reproduce the mainnet shape: its hex map passes the cap")
	require.LessOrEqual(t, len(b64Payload), params.MAX_CONTRACT_PAYLOAD_SIZE, "the base64 map must fit the cap")

	// The node refuses the hex map before execution (state-processing ExecuteTx); this
	// harness calls the contract directly and does not, so the sizes above carry that.
	ct, contractId := mapsize1Contract(t, header)
	r := mapsize1Call(ct, contractId, b64Payload, "mapsize1b64")
	dumpLogs(t, r.Logs)
	require.True(t, r.Success, "base64 map failed: %s: %s", r.Err, r.ErrMsg)
	assert.Equal(t, encodeBalance(t, amount), ct.StateGet(contractId, constants.BalancePrefix+user), "the depositor is credited")

	r = mapsize1Call(ct, contractId, b64Payload, "mapsize1again")
	assert.Equal(t, encodeBalance(t, amount), ct.StateGet(contractId, constants.BalancePrefix+user), "a second map does not credit again")
}

// MAP-SIZE-1: the witness serialization in base64 maps too (the txid ignores it), and
// a request with both encodings, or neither, is refused.
func TestMAPSIZE1_EncodingsAndRefusals(t *testing.T) {
	const instruction = "deposit_to=hive:alice"
	addr, _, err := mapping.DepositAddress(TestPrimaryPubKeyHex, TestBackupPubKeyHex, instruction, regtestParams())
	require.NoError(t, err)
	tx := batchedDepositTx(t, addr, 7_000, 3)
	header := buildRegtestHeader(chainhash.Hash{}, tx.TxHash(), time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	var withWitness bytes.Buffer
	require.NoError(t, tx.Serialize(&withWitness))

	for _, c := range []struct {
		name    string
		req     mapping.VerificationRequest
		wantErr string
	}{
		{"both encodings", mapping.VerificationRequest{BlockHeight: 100, RawTxHex: serializeTx(t, tx), RawTxB64: base64.StdEncoding.EncodeToString(withWitness.Bytes())}, "not both"},
		{"neither", mapping.VerificationRequest{BlockHeight: 100}, "required"},
		{"not base64", mapping.VerificationRequest{BlockHeight: 100, RawTxB64: "%%%"}, "decoding"},
	} {
		ct, contractId := mapsize1Contract(t, header)
		payload, _ := tinyjson.Marshal(mapping.MapParams{TxData: &c.req, Instructions: []string{instruction}})
		r := mapsize1Call(ct, contractId, payload, "refuse")
		assert.False(t, r.Success, "%s: accepted", c.name)
		assert.Contains(t, strings.ToLower(r.ErrMsg), c.wantErr, "%s", c.name)
	}

	ct, contractId := mapsize1Contract(t, header)
	payload, _ := tinyjson.Marshal(mapping.MapParams{
		TxData:       &mapping.VerificationRequest{BlockHeight: 100, RawTxB64: base64.StdEncoding.EncodeToString(withWitness.Bytes())},
		Instructions: []string{instruction},
	})
	r := mapsize1Call(ct, contractId, payload, "witnessb64")
	require.True(t, r.Success, "witness serialization in base64: %s: %s", r.Err, r.ErrMsg)
	assert.Equal(t, encodeBalance(t, 7_000), ct.StateGet(contractId, constants.BalancePrefix+"hive:alice"))
}

// DUST-DEDUCT-1: the vault's first coin would leave sub-dust change for this
// withdrawal (the mainnet shape: a 1,883-sat coin for a 1,468-sat swap output).
//   - a larger single coin exists: a deduct_fee unmap by a caller holding exactly
//     `amount` succeeds with one input and a change output, debits at most `amount`,
//     and the vault stays exactly backed (ACCT-1);
//   - only a second coin would avoid the burn: the withdrawal is built as before (no
//     extra input, so no extra RC), the burned leftover is charged (ACCT-1), and a
//     caller holding exactly `amount` is refused, as before. The known residual.
func TestDUSTDEDUCT1_DeductFeeNeverChargesAboveTheAmount(t *testing.T) {
	t.Run("a larger coin keeps change", func(t *testing.T) { dustDeduct1(t, 80_000, true) })
	t.Run("only a second coin would", func(t *testing.T) { dustDeduct1(t, 30_000, false) })
	t.Run("never past max_fee", dustDeduct1MaxFee)
}

// dustDeduct1Unmap runs one deduct_fee unmap of `amount` by a user holding `held`,
// against a vault of `coins` (in registry order) at `rate` sat/vB.
func dustDeduct1Unmap(t *testing.T, coins []int64, held, amount, rate int64, maxFee *int64) (test_utils.ContractTestCallResult, *test_utils.ContractTest, int64) {
	return dustDeduct1UnmapRc(t, coins, held, amount, rate, maxFee, 10000)
}

func dustDeduct1UnmapRc(t *testing.T, coins []int64, held, amount, rate int64, maxFee *int64, rcLimit uint64) (test_utils.ContractTestCallResult, *test_utils.ContractTest, int64) {
	const instruction = "deposit_to=hive:milo-hpr"
	const user = "hive:milo-hpr"
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, user, ContractWasm)
	activateTssKey(&ct, contractId)
	var vault int64
	reg := mapping.UtxoRegistry{}
	for i, c := range coins {
		id := uint16(1024 + i)
		reg = append(reg, mapping.UtxoRegistryEntry{Id: id, Amount: c})
		ct.StateSet(contractId, constants.UtxoPrefix+fmt.Sprintf("%x", id),
			depositUtxoBinary(t, strings.Repeat(fmt.Sprintf("%x", 0xa+i%6), 64), 0, c, instruction))
		vault += c
	}
	ct.StateSet(contractId, constants.BalancePrefix+user, encodeBalance(t, held))
	ct.StateSet(contractId, constants.BalancePrefix+"hive:someone-else", encodeBalance(t, vault-held))
	ct.StateSet(contractId, constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(reg)))
	ct.StateSet(contractId, constants.UtxoLastIdKey, encodeUtxoCounters(uint16(1024+len(coins)), 0))
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: vault, UserSupply: vault, BaseFeeRate: rate,
	})))
	ct.StateSet(contractId, constants.LastHeightKey, "102")
	ct.StateSet(contractId, constants.BlockPrefix+"100", buildSeedHeaderRaw(t, time.Unix(0, 0)))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	payload, _ := tinyjson.Marshal(mapping.TransferParams{Amount: fmt.Sprintf("%d", amount), To: regtestDestAddress(t), DeductFee: true, MaxFee: maxFee})
	r := ct.Call(stateEngine.TxVscCallContract{
		Self: *basicSelf(t, user), ContractId: contractId, Action: "unmap",
		Payload: payload, RcLimit: rcLimit, Intents: []contracts.Intent{},
	})
	dumpLogs(t, r.Logs)
	t.Logf("gas used %d", r.GasUsed)
	return r, &ct, vault
}

func dustDeduct1(t *testing.T, otherCoin int64, wantPaid bool) {
	const user = "hive:milo-hpr"
	const contractId = "mapping_contract"
	const amount = int64(50_000)
	const nearCoin = int64(50_300) // alone it leaves sub-dust change for this withdrawal

	// The caller holds exactly the amount, as the router does.
	r, ct, vault := dustDeduct1Unmap(t, []int64{nearCoin, otherCoin}, amount, amount, 2, nil)
	if !wantPaid {
		require.False(t, r.Success, "no larger coin: built as before, the burned leftover is charged and the balance does not cover it")
		require.Contains(t, r.ErrMsg, "insufficient")
		return
	}
	require.True(t, r.Success, "a deduct_fee unmap of exactly the caller's balance failed: %s: %s", r.Err, r.ErrMsg)

	sent, ok1 := logField(r, "unmap", "s")
	debited, ok2 := logField(r, "unmap", "d")
	btcFee, ok3 := logField(r, "fee", "b")
	require.True(t, ok1 && ok2 && ok3, "unmap and fee logs must be present")
	supply, err := mapping.UnmarshalSupply([]byte(ct.StateGet(contractId, constants.SupplyKey)))
	require.NoError(t, err)
	t.Logf("amount %d: sent %d, btc fee %d, debited %d, active %d -> %d", amount, sent, btcFee, debited, vault, supply.ActiveSupply)
	assert.LessOrEqual(t, debited, amount, "deduct_fee takes the fee from the amount, never on top")
	assert.Equal(t, sent+btcFee, debited, "the debit is exactly what leaves the vault (ACCT-1)")
	assert.Less(t, sent+btcFee, otherCoin, "one input (the larger coin) and a change output: the leftover stays in the vault")
	assert.Equal(t, vault-debited, supply.ActiveSupply, "active supply drops by the debit")
	assert.Equal(t, encodeBalance(t, amount-debited), ct.StateGet(contractId, constants.BalancePrefix+user))
}

// The second build adds change outputs (up to four on a large coin), so its size fee
// can pass a max_fee the first build met. It is then not used: a withdrawal that
// passed its max_fee before still passes, built as before.
func dustDeduct1MaxFee(t *testing.T) {
	const amount = int64(50_000)
	// At 1 sat/vB the estimate for one input and no change is 144, so this coin is the
	// first that covers the selection (amount + 144) and leaves sub-dust change; the
	// first build's true fee is 2 x 144 = 288 (the leftover is burned). The large coin
	// takes four change outputs.
	coins := []int64{amount + 144, 5_000_000}
	const held = int64(60_000) // enough for the first build's whole-coin debit

	// Four change outputs are new coins on the vault: 100,000 RC so the cost of the
	// build is not what this subtest measures.
	free, _, _ := dustDeduct1UnmapRc(t, coins, held, amount, 1, nil, 100_000)
	require.True(t, free.Success, "%s: %s", free.Err, free.ErrMsg)
	altFee, ok := logField(free, "fee", "b")
	require.True(t, ok)
	altDebit, _ := logField(free, "unmap", "d")
	require.Greater(t, altFee, int64(288), "the fixture needs a second build dearer than the first")
	require.LessOrEqual(t, altDebit, amount)

	maxFee := altFee - 1
	r, _, _ := dustDeduct1UnmapRc(t, coins, held, amount, 1, &maxFee, 100_000)
	require.True(t, r.Success, "a max_fee the first build meets must still pass: %s: %s", r.Err, r.ErrMsg)
	fee, _ := logField(r, "fee", "b")
	debited, _ := logField(r, "unmap", "d")
	t.Logf("max_fee %d: without it the second build (fee %d, debit %d); with it the first (fee %d, debit %d)", maxFee, altFee, altDebit, fee, debited)
	assert.LessOrEqual(t, fee, maxFee)
	assert.Equal(t, coins[0], debited, "the first build: the whole first coin, as before")
}

// callTxData calls an action whose params are ConfirmSpendParams (confirmSpend,
// reportUnauthorizedSpend, topUpFeeReserve).
func callTxData(t *testing.T, ct *test_utils.ContractTest, contractId, caller, action string, td *mapping.VerificationRequest, indices []uint32) test_utils.ContractTestCallResult {
	t.Helper()
	payload, err := tinyjson.Marshal(mapping.ConfirmSpendParams{TxData: td, Indices: indices})
	require.NoError(t, err)
	return ct.Call(stateEngine.TxVscCallContract{
		Self: *basicSelf(t, caller), ContractId: contractId, Action: action,
		Payload: payload, RcLimit: 100000, Intents: []contracts.Intent{}, Caller: caller,
	})
}

func hexToB64(t *testing.T, h string) string {
	t.Helper()
	raw, err := hex.DecodeString(h)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(raw)
}

// MAP-SIZE-1 for vault spends: confirmSpend, reportUnauthorizedSpend and topUpFeeReserve
// take raw_tx_b64 too. A vault spend's witnesses are ~230 bytes per input in hex, so a
// sweep of more than ~15 coins (MaxMigrationInputs allows 100; mainnet's vault holds 45,
// 11-05) passes the node's 8 KB payload cap and could be neither settled nor, as a theft,
// reported. The witness is optional: these checks read the txid, inputs and outputs only.
func TestMAPSIZE1_VaultSpendCallsTakeBase64(t *testing.T) {
	t.Run("confirmSpend settles from base64", func(t *testing.T) {
		ct, contractId, fx := setupConfirmSpendContract(t)
		r := callTxData(t, ct, contractId, "hive:milo-hpr", "confirmSpend", &mapping.VerificationRequest{
			BlockHeight: fx.BlockHeight, RawTxB64: hexToB64(t, fx.RawTxHex), MerkleProofHex: fx.MerkleProofHex, TxIndex: fx.TxIndex,
		}, []uint32{0})
		require.True(t, r.Success, "%s: %s", r.Err, r.ErrMsg)
		assert.Empty(t, ct.StateGet(contractId, constants.TxSpendsPrefix+fx.TxId), "the spend settled")
	})
	t.Run("confirmSpend refuses both encodings or neither", func(t *testing.T) {
		ct, contractId, fx := setupConfirmSpendContract(t)
		both := callTxData(t, ct, contractId, "hive:milo-hpr", "confirmSpend", &mapping.VerificationRequest{
			BlockHeight: fx.BlockHeight, RawTxHex: fx.RawTxHex, RawTxB64: hexToB64(t, fx.RawTxHex), MerkleProofHex: fx.MerkleProofHex, TxIndex: fx.TxIndex,
		}, []uint32{0})
		require.False(t, both.Success)
		assert.Contains(t, both.ErrMsg, "not both")
		neither := callTxData(t, ct, contractId, "hive:milo-hpr", "confirmSpend", &mapping.VerificationRequest{
			BlockHeight: fx.BlockHeight, MerkleProofHex: fx.MerkleProofHex, TxIndex: fx.TxIndex,
		}, []uint32{0})
		require.False(t, neither.Success)
		assert.Contains(t, neither.ErrMsg, "raw_tx_b64 required")
		assert.NotEmpty(t, ct.StateGet(contractId, constants.TxSpendsPrefix+fx.TxId), "nothing settled")
	})
	t.Run("topUpFeeReserve credits from base64", func(t *testing.T) {
		const amount = int64(250000)
		fx := buildFeeReserveFixture(t, amount, 100)
		ct, contractId, _ := newFeeReserveCT(t, fx, 3)
		r := callTxData(t, ct, contractId, "hive:some-random-funder", "topUpFeeReserve", &mapping.VerificationRequest{
			BlockHeight: fx.BlockHeight, RawTxB64: hexToB64(t, fx.RawTxHex), MerkleProofHex: fx.MerkleProofHex, TxIndex: fx.TxIndex,
		}, nil)
		require.True(t, r.Success, "%s: %s", r.Err, r.ErrMsg)
		assert.Equal(t, amount, loadSupply(t, ct, contractId).FeeSupply)
	})
	t.Run("a theft reported in base64 without its witness trips the halt", func(t *testing.T) {
		ct, contractId, _ := setupConfirmSpendContract(t)
		// A spend of the registered vault coin (aaaa..:0, setupConfirmSpendContract) that
		// the contract never authorised, with a witness as a real vault spend has.
		prev, err := chainhash.NewHashFromStr(strings.Repeat("a", 64))
		require.NoError(t, err)
		rogue := wire.NewMsgTx(wire.TxVersion)
		rogue.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: *prev, Index: 0},
			Witness: wire.TxWitness{bytes.Repeat([]byte{0x30}, 72), {0x01}, bytes.Repeat([]byte{0x51}, 112)}, Sequence: 0xffffffff})
		rogue.AddTxOut(&wire.TxOut{Value: 4_000, PkScript: []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}})
		header := buildRegtestHeader(chainhash.Hash{}, rogue.TxHash(), time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
		ct.StateSet(contractId, constants.BlockPrefix+"102", serializeHeaderRaw(t, header))
		var bare bytes.Buffer
		require.NoError(t, rogue.SerializeNoWitness(&bare))
		r := callTxData(t, ct, contractId, "hive:anyone", "reportUnauthorizedSpend", &mapping.VerificationRequest{
			BlockHeight: 102, RawTxB64: base64.StdEncoding.EncodeToString(bare.Bytes()), MerkleProofHex: "", TxIndex: 0,
		}, nil)
		require.True(t, r.Success, "%s: %s", r.Err, r.ErrMsg)
		assert.Equal(t, "1", ct.StateGet(contractId, constants.BtcTheftHaltKey), "the theft halt is tripped")
	})
}

func logString(r test_utils.ContractTestCallResult, prefix, k string) (string, bool) {
	for _, out := range r.Logs {
		for _, l := range out.Logs {
			if !strings.HasPrefix(l, prefix+constants.LogDelimiter) {
				continue
			}
			for _, kv := range strings.Split(l, constants.LogDelimiter) {
				if v, ok := strings.CutPrefix(kv, k+constants.LogKeyDelimiter); ok {
					return v, true
				}
			}
		}
	}
	return "", false
}

// MAP-SIZE-1: the map log names the deposit's sender from the input witness (senderLabel),
// which indexers read. base64 WITH the witness keeps it exactly as the hex map did, so the
// bot sends the witness whenever it fits; only without it does the sender read "many".
func TestMAPSIZE1_MapLogKeepsTheSenderWithTheWitness(t *testing.T) {
	const instruction = "deposit_to=hive:alice"
	addr, _, err := mapping.DepositAddress(TestPrimaryPubKeyHex, TestBackupPubKeyHex, instruction, regtestParams())
	require.NoError(t, err)
	tx := batchedDepositTx(t, addr, 7_000, 3)
	header := buildRegtestHeader(chainhash.Hash{}, tx.TxHash(), time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	var withWitness bytes.Buffer
	require.NoError(t, tx.Serialize(&withWitness))

	senderOf := func(req mapping.VerificationRequest) string {
		ct, contractId := mapsize1Contract(t, header)
		payload, _ := tinyjson.Marshal(mapping.MapParams{TxData: &req, Instructions: []string{instruction}})
		r := mapsize1Call(ct, contractId, payload, "sender")
		require.True(t, r.Success, "%s: %s", r.Err, r.ErrMsg)
		f, ok := logString(r, "map", "f")
		require.True(t, ok, "map log present")
		return f
	}
	viaHex := senderOf(mapping.VerificationRequest{BlockHeight: 100, RawTxHex: serializeTx(t, tx)})
	require.NotEqual(t, "many", viaHex, "the fixture's single segwit input names one sender")
	assert.Equal(t, viaHex, senderOf(mapping.VerificationRequest{BlockHeight: 100, RawTxB64: base64.StdEncoding.EncodeToString(withWitness.Bytes())}),
		"base64 with the witness logs the same sender as hex")
	assert.Equal(t, "many", senderOf(mapping.VerificationRequest{BlockHeight: 100, RawTxB64: base64.StdEncoding.EncodeToString(noWitnessBytes(t, tx))}),
		"without the witness the sender cannot be named")
	t.Logf("sender via hex and base64 with witness: %s", viaHex)
}

// DUST-DEDUCT-1, the whole cycle: the second build (a different, larger coin than the
// first build picked) is signed, confirmed and settled like any withdrawal: confirmSpend
// removes exactly the coin it spent, indexes its change, clears the spend records, and the
// vault's books stay exact (I1: the coins equal ActiveSupply + FeeSupply).
func TestDUSTDEDUCT1_TheSecondBuildSettles(t *testing.T) {
	const contractId = "mapping_contract"
	const amount = int64(50_000)
	r, ct, _ := dustDeduct1Unmap(t, []int64{50_300, 80_000}, amount, amount, 2, nil)
	require.True(t, r.Success, "%s: %s", r.Err, r.ErrMsg)
	txId, ok := logString(r, "unmap", "id")
	require.True(t, ok)
	sd, err := mapping.UnmarshalSigningData([]byte(ct.StateGet(contractId, constants.TxSpendsPrefix+txId)))
	require.NoError(t, err)
	var spend wire.MsgTx
	require.NoError(t, spend.Deserialize(bytes.NewReader(sd.Tx)))
	require.Equal(t, txId, spend.TxID())
	require.Len(t, spend.TxIn, 1)
	assert.Equal(t, strings.Repeat("b", 64), spend.TxIn[0].PreviousOutPoint.Hash.String(), "the second build spends the larger coin (id 1025)")
	require.GreaterOrEqual(t, len(spend.TxOut), 2, "it keeps change")

	header := buildRegtestHeader(chainhash.Hash{}, spend.TxHash(), time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	ct.StateSet(contractId, constants.BlockPrefix+"103", serializeHeaderRaw(t, header))
	ct.StateSet(contractId, constants.LastHeightKey, "106")
	vouts := make([]uint32, len(spend.TxOut))
	for i := range vouts {
		vouts[i] = uint32(i)
	}
	var raw bytes.Buffer
	require.NoError(t, spend.Serialize(&raw))
	c := callTxData(t, ct, contractId, "hive:anyone", "confirmSpend", &mapping.VerificationRequest{
		BlockHeight: 103, RawTxHex: hex.EncodeToString(raw.Bytes()), MerkleProofHex: "", TxIndex: 0,
	}, vouts)
	require.True(t, c.Success, "%s: %s", c.Err, c.ErrMsg)

	assert.Empty(t, ct.StateGet(contractId, constants.TxSpendsPrefix+txId), "signing record cleared")
	assert.Empty(t, ct.StateGet(contractId, constants.PendingUnmapPrefix+txId), "settle record cleared")
	reg, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	var total int64
	ids := map[uint16]int64{}
	for _, e := range reg {
		total += e.Amount
		ids[e.Id] = e.Amount
	}
	assert.Equal(t, int64(50_300), ids[1024], "the coin the first build would have burned is still in the vault")
	_, spent := ids[1025]
	assert.False(t, spent, "the spent coin left the registry")
	var change int64
	for _, o := range spend.TxOut[1:] {
		change += o.Value
	}
	assert.Equal(t, int64(50_300)+change, total, "the vault holds the untouched coin plus the change")
	s := loadSupply(t, ct, contractId)
	assert.Equal(t, total, s.ActiveSupply+s.FeeSupply, "I1: coins == ActiveSupply + FeeSupply, exact")
	t.Logf("settled: change %d, vault %d, active %d, fee %d", change, total, s.ActiveSupply, s.FeeSupply)
}
