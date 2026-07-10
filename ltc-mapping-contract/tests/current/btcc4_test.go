package current_test

import (
	"ltc-mapping-contract/contract/constants"
	"ltc-mapping-contract/contract/mapping"
	"ltc-mapping-contract/tests/mocks"
	"encoding/binary"
	"fmt"
	"testing"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeBalance reverses encodeBalance / setAccBal's compact big-endian
// binary format so we can read the depositor's balance back out of state.
func decodeBalance(t *testing.T, raw string) int64 {
	t.Helper()
	if raw == "" {
		return 0
	}
	var buf [8]byte
	copy(buf[8-len(raw):], raw)
	return int64(binary.BigEndian.Uint64(buf[:]))
}

// Pentest finding BTC-C4: when the DEX router fails or returns
// `amount_out == "0"`, mapping.go:processUtxos previously returned an
// error → entire map reverted → user's BTC sat in the contract vault
// with no L2 credit until the backup CSV timelock (~1 month) let them
// reclaim. Fix: when the router didn't actually pull the contract's
// allowance, refund the depositor with raw BTC-equivalent L2 tokens
// instead of reverting.
//
// This test uses a mock router contract (tests/mocks/mockrouter/) that
// always returns `{"amount_out":"0", "pool_state":...}` to drive the
// btc-mapping contract into the failure branch deterministically.
// Pre-fix: map errors with "swap returned zero amount out" and the
// recipient balance stays 0. Post-fix: map succeeds and the recipient
// is credited with utxo.Amount sats.

func TestBTCC4_RouterFailureRefundsDepositor(t *testing.T) {
	const swapRecipient = "hive:milo-receiver"
	const instruction = "swap_to=" + swapRecipient + "&swap_asset_out=HBD&destination_chain=hive"
	const blockHeight = uint32(100)
	const utxoAmount int64 = 10_000

	fixture := buildMapFixture(t, instruction, utxoAmount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })

	const (
		btcContractId   = "btc_mapping_for_btcc4"
		routerContractId = "mock_router_for_btcc4"
	)

	// Register both contracts: the BTC mapping under test, and the
	// mock router that always returns AmountOut="0".
	ct.RegisterContract(btcContractId, "hive:milo-hpr", ContractWasm)
	ct.RegisterContract(routerContractId, "hive:milo-hpr", mocks.MockRouterWasm)

	// Wire the mapping contract to the mock router.
	ct.StateSet(btcContractId, constants.RouterContractIdKey, routerContractId)

	// Standard mapping-contract state seed (mirrors TestMap).
	ct.StateSet(btcContractId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(btcContractId, constants.LastHeightKey, "100")
	ct.StateSet(btcContractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	ct.StateSet(btcContractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(btcContractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	// Pre-conditions: depositor has zero balance.
	preBal := ct.StateGet(btcContractId, constants.BalancePrefix+swapRecipient)
	require.Empty(t, preBal, "depositor should start with zero balance")

	params := mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    blockHeight,
			RawTxHex:       fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex,
			TxIndex:        fixture.TxIndex,
		},
		Instructions: []string{instruction},
	}
	payload, err := tinyjson.Marshal(params)
	if err != nil {
		t.Fatal("error marshalling params:", err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "btcc4-test-tx",
			BlockId:              "block:btcc4",
			Index:                0,
			OpIndex:              0,
			Timestamp:            "2026-05-07T00:00:00",
			RequiredAuths:        []string{"hive:milo-hpr"},
			RequiredPostingAuths: []string{},
		},
		ContractId: btcContractId,
		Action:     "map",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
		Caller:     "hive:milo-hpr",
	})

	if !r.Success {
		// Pre-fix: the test fails here with "swap returned zero amount out".
		// Post-fix: success — the refund branch routed BTC to the depositor.
		t.Fatalf("BTC-C4 leak: map reverted on router AmountOut=0 instead of refunding depositor. err=%q msg=%q",
			r.Err, r.ErrMsg)
	}

	// Post-fix invariant: the swap recipient was credited with utxo.Amount
	// raw BTC-equivalent L2 tokens.
	postBalRaw := ct.StateGet(btcContractId, constants.BalancePrefix+swapRecipient)
	postBal := decodeBalance(t, postBalRaw)
	assert.Equal(t, utxoAmount, postBal,
		"BTC-C4 fix: depositor must be credited with utxo amount when router fails; got %d, want %d",
		postBal, utxoAmount)

	// And the contract's self-credit was drained back out (no double-mint).
	selfAddr := "contract:" + btcContractId
	selfBalRaw := ct.StateGet(btcContractId, constants.BalancePrefix+selfAddr)
	selfBal := decodeBalance(t, selfBalRaw)
	assert.Zero(t, selfBal,
		"BTC-C4 fix: contract self-credit must be cleared after refund; got %d",
		selfBal)

	fmt.Printf("btc-c4 refund verified: recipient=%s credited=%d\n", swapRecipient, postBal)
}
