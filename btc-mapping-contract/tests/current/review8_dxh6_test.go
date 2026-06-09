package current_test

// DX-H6 — a BTC deposit-swap that REVERTS must refund the depositor wrapped BTC
// rather than strand their (already irreversible) L1 coins.
//
// The deposit address is derived from the swap instruction, so a permanently
// failing swap (slippage / no pool / zero output) could never be processed — the
// whole `map` aborted and the UTXO was bound to that one doomed swap forever.
//
// The fix runs the ingress swap through the new try/catch primitive
// (sdk.TryContractCall). When the router reverts, its effects are rolled back to a
// savepoint and the mapping contract is NOT trapped — it credits the depositor
// wrapped BTC instead of reverting the whole deposit.
//
// This test drives the real wasm: it registers a "router" with no `execute`
// export (so the swap call reverts), fires a deposit-swap, and asserts the map
// SUCCEEDS and the depositor is credited the full amount.
//
// Two run-time requirements (hence the env-var guard — by default it skips so it
// never breaks a normal `make test` against the pinned upstream node):
//
//  1. A try/catch-enabled go-vsc-node. The feature activates at consensus version
//     0.2.0; NewContractTest enables it in-process. The node pinned in go.mod does
//     NOT have it, so point vsc-node at the feat/trycatch-icc tree via a go.work:
//
//	go 1.25.7
//	use .
//	use /abs/path/to/go-vsc-node      // the feat/trycatch-icc tree
//
//  2. A dev.wasm built for the REGTEST network (NetworkMode=regtest), matching the
//     regtest fixtures — `make dev`. A default/MainNet build derives a different
//     deposit address, so the fixture UTXO is never matched and the swap branch
//     never runs (this is why the other balance-asserting map tests need it too).
//
//	make dev   # builds bin/dev.wasm with -X main.NetworkMode=regtest
//	UTXO_TRYCATCH=1 go test ./tests/current/ -run TestReview8_DXH6 -v

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"
)

func TestReview8_DXH6_DepositSwapRefund(t *testing.T) {
	if os.Getenv("UTXO_TRYCATCH") == "" {
		t.Skip("DX-H6 refund requires a try/catch-enabled go-vsc-node (consensus 0.2.0). " +
			"Point vsc-node at the feat/trycatch-icc tree via go.work and set UTXO_TRYCATCH=1.")
	}

	// swap_to a hive address (VerifyAddress -> user:hive, accepted by the swap
	// path); an unreachable min_amount_out doesn't matter — the router reverts
	// regardless because it has no `execute` entrypoint.
	const instruction = "swap_to=hive:milo-hpr&swap_asset_out=hbd&min_amount_out=99999999"
	const blockHeight = uint32(100)
	const amount = int64(10000)
	const depositor = "hive:milo-hpr"

	fixture := buildMapFixture(t, instruction, amount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })

	contractId := "mapping_contract"
	routerId := "router_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	// The "router": the same wasm registered under a second id. It has no
	// `execute` export, so the mapping's swap call to it reverts — standing in for
	// any failing swap (slippage, missing pool, zero output).
	ct.RegisterContract(routerId, "hive:milo-hpr", ContractWasm)

	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	ct.StateSet(contractId, constants.RouterContractIdKey, routerId)

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
	require.NoError(t, err, "marshalling map params")

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "dxh6-deposit-swap",
			BlockId:              "block:map",
			Index:                69,
			OpIndex:              0,
			Timestamp:            "2025-10-14T00:00:00",
			RequiredAuths:        []string{"hive:milo-hpr"},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "map",
		Payload:    payload,
		RcLimit:    1000000,
		Intents:    []contracts.Intent{},
		Caller:     "hive:milo-hpr",
	})
	dumpLogs(t, r.Logs)
	if r.Err != "" {
		fmt.Printf("%s: %s\n", r.Err, r.ErrMsg)
	}

	// 1. The map is NOT trapped by the reverting swap — try/catch caught it.
	require.True(t, r.Success,
		"a deposit-swap whose router reverts must be CAUGHT (not trap the whole map): %s %s", r.Err, r.ErrMsg)

	// 2. The depositor is credited the full wrapped-BTC amount (refund), so the
	//    coins are never stranded.
	got := ct.StateGet(contractId, constants.BalancePrefix+depositor)
	assert.Equal(t, encodeBalance(t, amount), got,
		"depositor must be refunded the full wrapped-BTC amount after the swap reverts")

	// 3. The contract's own intermediary balance was handed off (not left holding
	//    the refunded coins).
	self := ct.StateGet(contractId, constants.BalancePrefix+"contract:"+contractId)
	assert.Equal(t, "", self, "contract must not retain the refunded coins")

	// 4. The refund is recorded in the logs.
	var refundLogged bool
	for _, out := range r.Logs {
		for _, l := range out.Logs {
			if strings.Contains(l, "refunded depositor") {
				refundLogged = true
			}
		}
	}
	assert.True(t, refundLogged, "the refund must be logged")
}
