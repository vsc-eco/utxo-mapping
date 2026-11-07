package current_test

import (
	"strconv"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"
	"btc-mapping-contract/tests/mocks"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MAP-CEI (15a) regression: a router cannot re-enter a blob-writing export
// while the mapping contract's ingress-swap call is outstanding.
//
// The window. On a swap-tagged deposit, processUtxos registers the deposit's
// UTXO, credits supply, appends to the observed list, and THEN calls the router
// — with none of it persisted. The observed list used to be written after the
// loop, and the eight whole-state blobs (UTXO registry, pool counters, tx
// spends, migration sweeps, supply, vault registry, next/active gen) are
// written by SaveToState only after the handler returns. The router is
// therefore invoked at the one moment when persisted state disagrees with
// in-memory state, and it is reached through an owner-registered contract that
// this contract does not otherwise trust.
//
// What that bought an attacker, without the guard:
//
//   - re-enter `map` with the SAME output: the dedup check reads the observed
//     list from STATE, which does not yet contain the entry, so the same real
//     BTC is credited twice — unbacked wrapped BTC;
//   - re-enter any other blob-writing export: its writes are erased moments
//     later when the outer frame's SaveToState overwrites all eight blobs from
//     its stale snapshot, while the account credits it made survive (those go
//     straight to "a-" keys, not through SaveToState) — breaking
//     Σ(UTXO) == ActiveSupply + FeeSupply in the mint direction.
//
// The fix is selective, not a blanket lock: the router is SUPPOSED to re-enter
// via transferFrom to pull the allowance it was just granted, and HandleTransfer
// touches no blob. Only the exports that call SaveToState are gated.
func TestMapCEI_RouterCannotReenterBlobWritingExport(t *testing.T) {
	// Must match the id compiled into tests/mocks/mockreentrantrouter/main.go.
	const btcContractId = "btc_map_reentrant_test"
	const routerContractId = "mock_reentrant_router"

	const swapRecipient = "hive:milo-receiver"
	const instruction = "swap_to=" + swapRecipient + "&swap_asset_out=HBD&destination_chain=hive"
	const blockHeight = uint32(100)
	const utxoAmount int64 = 250_000

	fixture := buildMapFixture(t, instruction, utxoAmount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })

	ct.RegisterContract(btcContractId, "hive:milo-hpr", ContractWasm)
	ct.RegisterContract(routerContractId, "hive:milo-hpr", mocks.MockReentrantRouterWasm)
	ct.StateSet(btcContractId, constants.RouterContractIdKey, routerContractId)

	ct.StateSet(btcContractId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(btcContractId, constants.LastHeightKey, "102")
	ct.StateSet(btcContractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	ct.StateSet(btcContractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(btcContractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

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
	require.NoError(t, err)

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: "map-cei-reentrant-tx", BlockId: "block:mapcei", Index: 0, OpIndex: 0,
			Timestamp: "2026-11-05T00:00:00", RequiredAuths: []string{"hive:milo-hpr"},
			RequiredPostingAuths: []string{},
		},
		ContractId: btcContractId, Action: "map", Payload: payload,
		RcLimit: 10000, Intents: []contracts.Intent{}, Caller: "hive:milo-hpr",
	})

	// The outer map must still SUCCEED. The deposit is already irreversible on
	// L1, so refusing the whole call would strand real BTC — the mapping
	// contract absorbs a router failure rather than reverting (DX-H6/STRAND-2).
	require.True(t, r.Success, "map should succeed; err=%q msg=%q", r.Err, r.ErrMsg)

	// THE LOAD-BEARING ASSERTION.
	//
	// The mock re-enters drainUnmapQueue, which ignores its payload and calls
	// SaveToState unconditionally — so the call cannot fail for an input reason.
	// It reports the outcome through amount_out, which decides which path the
	// mapping contract then takes:
	//
	//   guard HELD    -> re-entry refused -> amount_out "0" -> router treated as
	//                    failed -> allowance unspent -> depositor REFUNDED in full
	//   guard MISSING -> re-entry SUCCEEDS -> amount_out "1" -> router treated as
	//                    successful -> no refund -> depositor gets NOTHING
	//
	// So the depositor's balance is what distinguishes the two, and this
	// assertion is the one that goes red if the guard is removed. That was
	// verified by actually neutering InExternalCallGuard and re-running: an
	// earlier version of this test re-entered topUpFeeReserve with an empty
	// payload, which failed on input validation either way, so it passed with
	// the guard gone and proved nothing.
	depositorBal := decodeBalance(t, ct.StateGet(btcContractId, constants.BalancePrefix+swapRecipient))
	assert.Equal(t, utxoAmount, depositorBal,
		"re-entry into a blob-writing export must be refused; the depositor balance of %d "+
			"means the router's re-entrant drainUnmapQueue SUCCEEDED and the guard did not hold",
		depositorBal)

	// The deposit is credited exactly ONCE. This is the double-credit assertion:
	// one real output, one registry entry, one output's worth of supply.
	reg, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(btcContractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	assert.Len(t, reg, 1, "the deposit must be indexed exactly once; %d entries means it was double-credited", len(reg))

	// No reserve was credited either — nothing in this flow should touch FeeSupply.
	supply := loadSupply(t, &ct, btcContractId)
	assert.Zero(t, supply.FeeSupply, "no path in this flow credits the fee reserve")

	// Conservation: Σ(UTXO) == ActiveSupply + FeeSupply, exact. This is the
	// invariant a double-credit or a clobbered blob would break.
	var sum int64
	for _, e := range reg {
		sum += e.Amount
	}
	assert.Equal(t, sum, supply.ActiveSupply+supply.FeeSupply,
		"I1 must hold exactly: Σ(UTXO)=%d vs Active+Fee=%d",
		sum, supply.ActiveSupply+supply.FeeSupply)

	// The guard must not be left latched on, or every later blob-writing call
	// would be refused for the rest of the contract's life.
	assert.NotEqual(t, "1", ct.StateGet(btcContractId, constants.ExternalCallGuardKey),
		"the external-call guard must be cleared after the call returns")
}

// The provenance floor (15b / TOPUP-REPLAY-1).
//
// An unset floor is permissive on purpose — see topUpProvenanceFloor's comment:
// it cannot be pinned lazily on first use, because a legitimate deposit always
// sits some confirmations BELOW the tip, so a floor pinned at that moment would
// reject the very deposit that triggered it. It is pinned instead to the tip as
// of activation, by the first addBlocks.
func TestTopUpProvenanceFloor_RejectsDepositBelowFloorAndAllowsAbove(t *testing.T) {
	const amount = int64(250000)
	const blockHeight = uint32(100)
	fx := buildFeeReserveFixture(t, amount, blockHeight)

	// REVERSED 2026-11-07. This subtest used to assert that an unset floor
	// "behaves exactly as before the upgrade", i.e. credits the top-up. It no
	// longer does, and the reversal is the point: replaying a real spent coin
	// during the unset window produces a phantom coin and trips the theft halt,
	// and the window is not the sliver the original argument assumed -- mainnet
	// addBlocks gaps run a 10-minute median and a 74-minute maximum, at a
	// publicly known activation height. constants.go always documented the
	// refusal; the code disagreed with it. See topUpProvenanceFloor's comment.
	t.Run("an unset floor refuses the top-up", func(t *testing.T) {
		ct, contractId, _ := newFeeReserveCT(t, fx, 3)
		// The shared helper pins a floor, so clear it to reach the unset state.
		ct.StateSet(contractId, constants.V2TopUpFeeReserveFloorKey, "")
		require.Empty(t, ct.StateGet(contractId, constants.V2TopUpFeeReserveFloorKey),
			"fixture precondition: no floor pinned")
		res := callTopUpFeeReserve(t, ct, contractId, "hive:some-random-funder", fx, "tx-floor-unset")
		require.False(t, res.Success, "an unset floor must refuse, not credit")
		assert.Contains(t, res.ErrMsg, "not pinned yet")

		supply := loadSupply(t, ct, contractId)
		assert.Zero(t, supply.FeeSupply, "a refused top-up must move no reserve")
	})

	t.Run("a deposit below the pinned floor is refused", func(t *testing.T) {
		ct, contractId, _ := newFeeReserveCT(t, fx, 3)
		// Pinned one block above the deposit: the deposit predates activation.
		ct.StateSet(contractId, constants.V2TopUpFeeReserveFloorKey,
			strconv.FormatUint(uint64(blockHeight)+1, 10))
		res := callTopUpFeeReserve(t, ct, contractId, "hive:replayer", fx, "tx-floor-below")
		require.False(t, res.Success, "a pre-floor deposit must not credit the reserve")
		assert.Contains(t, res.ErrMsg, "predates the provenance floor")

		supply := loadSupply(t, ct, contractId)
		assert.Zero(t, supply.FeeSupply, "a refused replay must move no reserve")
	})

	t.Run("a deposit at the floor is accepted", func(t *testing.T) {
		ct, contractId, _ := newFeeReserveCT(t, fx, 3)
		// Boundary: >= is allowed, so the deposit's own height must pass.
		ct.StateSet(contractId, constants.V2TopUpFeeReserveFloorKey,
			strconv.FormatUint(uint64(blockHeight), 10))
		res := callTopUpFeeReserve(t, ct, contractId, "hive:funder", fx, "tx-floor-at")
		require.True(t, res.Success, res.ErrMsg)

		supply := loadSupply(t, ct, contractId)
		assert.Equal(t, amount, supply.FeeSupply)
	})
}
