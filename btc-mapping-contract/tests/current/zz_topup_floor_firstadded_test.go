package current_test

import (
	"strconv"
	"testing"

	btcMapping "btc-mapping-contract"
	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TOPUP-REPLAY-1: the provenance floor is pinned at the FIRST height the relay
// adds, not at the batch tip.
//
// Pinning at the tip stranded a deposit mined AFTER activation whenever the
// first relay after activation carried more than one header. lordbutterfly's
// scenario, reviewing #39: tip 1000, a deposit confirmed at 1001, and the next
// relay carries 1001-1003. The floor was pinned at 1003, so the deposit at 1001
// was refused as "predating the provenance floor" — permanently, because
// nothing else credits a fee-reserve top-up. The deposit was mined after
// activation and was never replayable; it was simply below a floor that had no
// business being that high.
//
// The first added height is the earliest height this code could not already
// have seen, which is exactly the bound TOPUP-REPLAY-1 wants.
//
// Real BTC testnet3 headers, the same 3-block chain blocklist_test.go uses:
//
//	4888515 -> 4888516 -> 4888517
const (
	floorHdr4888515 = "000000209bfa65ae0af2ba13fd4403312a44554123c4b972374fd1995adce62c0000000081af5bae21b11430df381ee109e51181f5ff4164f744f0747ce980cf43c6c73797b4bc69ffff001d28ffa61f"
	floorHdr4888516 = "000000201545504338162312b9911c44c17ab259f312b850a915e192665870f500000000d2684baebc7ac8401ac29754247d1091bd3c6604bb4b26aeff107b6cfde0787648b9bc69ffff001d176c1809"
	floorHdr4888517 = "000000201cdc5538b560cd512fac6147b235c1be8fb6429296698b4065f22309000000000061c5ef9468eb91177b04aabf349991b9000774ac4f87f747f07935d4ad9e3ffbbdbc69ffff001d89201fc7"
)

func TestTopUpFloor_PinnedAtFirstAddedHeightNotBatchTip(t *testing.T) {
	const id = "topup_floor_firstadded"
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	ct.RegisterContract(id, "hive:milo-hpr", btcMapping.Testnet3Wasm)
	ct.StateSet(id, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))

	// The chain as it stands when the update goes live: tip 4888515, no floor.
	ct.StateSet(id, constants.LastHeightKey, "4888515")
	ct.StateSet(id, constants.BlockPrefix+"4888515", decodeHex(t, floorHdr4888515))
	require.Empty(t, ct.StateGet(id, constants.V2TopUpFeeReserveFloorKey),
		"precondition: the floor is unset until the first relay after activation")

	// The first relay after activation carries TWO headers — this is the whole
	// point of the fixture. One header would make the two behaviours identical.
	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: "topup-floor-relay", BlockId: "block:floor", Index: 0, OpIndex: 0,
			Timestamp: "2026-11-07T00:00:00", RequiredAuths: []string{constants.OracleAddress},
			RequiredPostingAuths: []string{},
		},
		ContractId: id, Action: "addBlocks",
		Payload: []byte(`{"blocks":"` + floorHdr4888516 + floorHdr4888517 + `","latest_fee":1}`),
		RcLimit: 10000, Intents: []contracts.Intent{}, Caller: constants.OracleAddress,
	})
	require.True(t, r.Success, "the two-header relay must land; err=%q msg=%q", r.Err, r.ErrMsg)
	require.Equal(t, "4888517", ct.StateGet(id, constants.LastHeightKey), "the tip advanced to the batch tip")

	// THE ASSERTION. 4888516 is the first height this relay added; 4888517 is
	// the batch tip and is what the old code pinned. A deposit mined at 4888516
	// — after activation — must still be creditable.
	got := ct.StateGet(id, constants.V2TopUpFeeReserveFloorKey)
	assert.Equal(t, strconv.Itoa(4888516), got,
		"the floor must be the FIRST height the relay added (4888516), not the batch tip (4888517); "+
			"pinning at the tip strands a deposit mined at 4888516 permanently")

	// And it is a one-shot: a later relay must not move it.
	r2 := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: "topup-floor-relay-2", BlockId: "block:floor2", Index: 0, OpIndex: 0,
			Timestamp: "2026-11-07T00:01:00", RequiredAuths: []string{constants.OracleAddress},
			RequiredPostingAuths: []string{},
		},
		ContractId: id, Action: "addBlocks",
		Payload: []byte(`{"blocks":"","latest_fee":1}`),
		RcLimit: 10000, Intents: []contracts.Intent{}, Caller: constants.OracleAddress,
	})
	_ = r2 // an empty relay may legitimately be refused; the floor is what matters
	assert.Equal(t, got, ct.StateGet(id, constants.V2TopUpFeeReserveFloorKey),
		"InitTopUpProvenanceFloor is a no-op once set")
}
