package current_test

import (
	"strconv"
	"testing"
	"time"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/require"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"
)

// topUpFeeReserve (HandleTopUpFeeReserve) — the operator-funded migration fee reserve.
//
// This action had NO test coverage of any kind before this file, despite being a
// PERMISSIONLESS, NOT-pause-gated path that credits FeeSupply and indexes a new confirmed
// UTXO straight off an SPV proof. It is the reserve every rotation draws its miner fees
// from, and (since VR2-15) the reserve the dust write-off is charged against, so its
// arithmetic is now load-bearing for solvency in two places rather than one.
//
// Proves: (a) a real top-up credits FeeSupply by exactly the deposited value and indexes
// the output as an ACTIVE-generation UTXO, holding conservation I1 (Σ(UTXO) ==
// ActiveSupply + FeeSupply) exact while leaving user principal untouched (I2/I3);
// (b) VR2-25 — an immature proof is REFUSED, and the IDENTICAL proof is accepted once the
// depth accrues (positive control, so the refusal cannot be passing for the wrong reason);
// (c) the same output can never be credited twice.

// buildFeeReserveFixture creates a transaction paying the ACTIVE vault's untagged P2WSH
// address — the exact address HandleTopUpFeeReserve derives and matches — wrapped in a
// single-tx block so Merkle verification trivially passes. Same shape as
// buildConfirmSpendFixture, with a caller-controlled amount.
func buildFeeReserveFixture(t *testing.T, amount int64, blockHeight uint32) ConfirmSpendFixture {
	t.Helper()
	reserveAddr, _, err := mapping.AddressWithBackup(TestPrimaryPubKeyHex, TestBackupPubKeyHex, nil, regtestParams())
	if err != nil {
		t.Fatal("failed to derive fee-reserve vault address:", err)
	}
	tx := buildTestTx(t, reserveAddr, amount)
	txHash := tx.TxHash()
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	header := buildRegtestHeader(chainhash.Hash{}, txHash, ts)
	return ConfirmSpendFixture{
		TxId:           tx.TxID(),
		RawTxHex:       serializeTx(t, tx),
		MerkleProofHex: "",
		TxIndex:        0,
		BlockHeight:    blockHeight,
		BlockHeaderRaw: serializeHeaderRaw(t, header),
	}
}

// callTopUpFeeReserve invokes topUpFeeReserve with the given fixture. The action reuses the
// confirmSpend params shape (tx_data + unused indices), so no new marshaler is needed.
func callTopUpFeeReserve(t *testing.T, ct *test_utils.ContractTest, contractId, caller string,
	fx ConfirmSpendFixture, txId string) test_utils.ContractTestCallResult {
	t.Helper()
	payload, err := tinyjson.Marshal(mapping.ConfirmSpendParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    fx.BlockHeight,
			RawTxHex:       fx.RawTxHex,
			MerkleProofHex: fx.MerkleProofHex,
			TxIndex:        fx.TxIndex,
		},
	})
	require.NoError(t, err)
	return ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: txId, BlockId: "block:" + txId, Index: 1, OpIndex: 0,
			Timestamp:     "2025-10-14T00:00:00",
			RequiredAuths: []string{caller}, RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "topUpFeeReserve",
		Payload:    payload,
		RcLimit:    100000000,
		Intents:    []contracts.Intent{},
		Caller:     caller,
	})
}

// newFeeReserveCT puts the contract in the post-fold gen-0 ACTIVE state with an empty
// Supply and the fixture's block header seeded, tip set `depth` blocks above it.
func newFeeReserveCT(t *testing.T, fx ConfirmSpendFixture, depth uint32) (*test_utils.ContractTest, string, string) {
	t.Helper()
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.BlockPrefix+strconv.FormatUint(uint64(fx.BlockHeight), 10), fx.BlockHeaderRaw)
	ct.StateSet(contractId, constants.LastHeightKey, strconv.FormatUint(uint64(fx.BlockHeight)+uint64(depth), 10))
	seedActiveGen0(t, &ct, contractId, owner)
	return &ct, contractId, owner
}

// (a) A real top-up credits FeeSupply by exactly the deposited value, indexes the output as
// a normal ACTIVE-gen UTXO, and never touches user principal.
func TestTopUpFeeReserve_CreditsReserveAndConserves(t *testing.T) {
	const amount = int64(250000)
	const blockHeight = uint32(100)
	fx := buildFeeReserveFixture(t, amount, blockHeight)
	// Mature by the regtest gate (MinConfirmationDepth = 2) with a block to spare.
	ct, contractId, _ := newFeeReserveCT(t, fx, 3)

	// PERMISSIONLESS: funded by an account that is neither owner nor admin.
	res := callTopUpFeeReserve(t, ct, contractId, "hive:some-random-funder", fx, "tx-topup-1")
	require.True(t, res.Success, res.ErrMsg)

	supply := loadSupply(t, ct, contractId)
	require.Equal(t, amount, supply.FeeSupply, "FeeSupply credited by exactly the deposited value")
	require.Equal(t, int64(0), supply.ActiveSupply, "a top-up is not user principal — ActiveSupply untouched")
	require.Equal(t, int64(0), supply.UserSupply, "a top-up is not user principal — UserSupply untouched")

	reg, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, reg, 1, "the reserve deposit is indexed as a spendable UTXO")
	require.Equal(t, amount, reg[0].Amount)

	// The UTXO must carry the ACTIVE generation, or a later sweep would sign it with the
	// wrong generation's key and the reserve would be unspendable.
	blob := ct.StateGet(contractId, constants.UtxoPrefix+strconv.FormatUint(uint64(reg[0].Id), 16))
	u, err := mapping.UnmarshalUtxo([]byte(blob))
	require.NoError(t, err)
	require.Equal(t, uint32(0), u.Generation, "reserve deposit is tagged with the active generation")
	require.Empty(t, u.Tag, "reserve deposit pays the untagged vault address, like an unmap change output")

	// I1: Σ(UTXO) == ActiveSupply + FeeSupply, exact.
	require.Equal(t, reg[0].Amount, supply.ActiveSupply+supply.FeeSupply, "I1 holds exact after a top-up")
	// The depositor gets NO L2 credit — they are donating to the reserve.
	require.Empty(t, ct.StateGet(contractId, constants.BalancePrefix+"hive:some-random-funder"),
		"a reserve top-up credits no L2 balance to the funder")
}

// (b) VR2-25 — the maturity gate. topUpFeeReserve is the THIRD permissionless SPV-crediting
// path (after map and confirmSpend) and had no confirmation-depth gate, so a reorg that
// orphaned the top-up's block would leave a phantom UTXO in the registry and an inflated
// reserve: Σ(UTXO) claiming coins Bitcoin does not hold, the migration reserve gate passing
// on backing that does not exist, and any sweep selecting the phantom input building a
// transaction L1 will not accept.
//
// Merkle inclusion proves the tx was in A block; it never proves the block survived.
//
// The identical proof is replayed after the depth accrues as a POSITIVE CONTROL, so the
// refusal cannot be passing because the fixture was malformed.
func TestTopUpFeeReserve_RefusesImmatureBlock(t *testing.T) {
	const amount = int64(250000)
	const blockHeight = uint32(100)
	fx := buildFeeReserveFixture(t, amount, blockHeight)
	// depth 0: the top-up's block IS the contract's tip — a single-block reorg reverses it.
	ct, contractId, _ := newFeeReserveCT(t, fx, 0)

	res := callTopUpFeeReserve(t, ct, contractId, "hive:some-random-funder", fx, "tx-topup-immature")
	require.False(t, res.Success, "an unmatured fee-reserve deposit must be refused")
	require.Contains(t, res.ErrMsg, "not confirmed deeply enough",
		"refused by the maturity gate specifically, not by some unrelated error")
	require.Contains(t, res.ErrMsg, "fee-reserve deposit",
		"the refusal names this path, so the three gates stay distinguishable in logs")

	// Nothing was written: no reserve credit, no phantom UTXO.
	supply := loadSupply(t, ct, contractId)
	require.Equal(t, int64(0), supply.FeeSupply, "a refused top-up credits nothing")
	require.Empty(t, ct.StateGet(contractId, constants.UtxoRegistryKey), "a refused top-up indexes no UTXO")

	// POSITIVE CONTROL: the SAME proof, once the block is buried deeply enough, is accepted.
	ct.StateSet(contractId, constants.LastHeightKey, strconv.FormatUint(uint64(blockHeight)+2, 10))
	matured := callTopUpFeeReserve(t, ct, contractId, "hive:some-random-funder", fx, "tx-topup-matured")
	require.True(t, matured.Success, matured.ErrMsg)
	require.Equal(t, amount, loadSupply(t, ct, contractId).FeeSupply,
		"the identical proof credits the reserve once it matures — the gate is about depth, nothing else")
}

// (c) The same output can never be credited twice, so a replayed top-up cannot inflate the
// reserve against a single real deposit.
func TestTopUpFeeReserve_NoDoubleCredit(t *testing.T) {
	const amount = int64(250000)
	const blockHeight = uint32(100)
	fx := buildFeeReserveFixture(t, amount, blockHeight)
	ct, contractId, _ := newFeeReserveCT(t, fx, 3)

	require.True(t, callTopUpFeeReserve(t, ct, contractId, "hive:funder", fx, "tx-topup-a").Success)
	require.Equal(t, amount, loadSupply(t, ct, contractId).FeeSupply)

	replay := callTopUpFeeReserve(t, ct, contractId, "hive:funder", fx, "tx-topup-b")
	require.False(t, replay.Success, "replaying the same top-up proof must not credit the reserve again")

	supply := loadSupply(t, ct, contractId)
	require.Equal(t, amount, supply.FeeSupply, "FeeSupply still reflects exactly one real deposit")
	reg, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, reg, 1, "the outpoint is indexed exactly once")
}
