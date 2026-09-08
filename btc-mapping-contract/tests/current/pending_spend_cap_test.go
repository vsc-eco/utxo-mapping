package current_test

import (
	"fmt"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/require"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"
)

// VR2-03 — the pending-spend concurrency cap, ENFORCED.
//
// The retention clamp (MaxRetentionWithPendingSpend) keeps block headers alive back to the
// oldest live spend, and refreshPendingSpendFloor walks every live spend record on each
// settle. Both were documented as "bounded by MaxConcurrentPendingSpends" while nothing in
// the contract enforced that bound. unmap is permissionless and limited only by a per-block
// SATOSHI cap — never by count or duration — so N was whoever called it the most: an
// attacker could hold open an unbounded number of cheap never-confirming unmaps, each
// pinning header retention at its own build height, stalling pruning and making the
// settle-time recompute scale with their spend.
//
// The companion unit test (contract/mapping/vr2_03_retention_test.go) checks the constant's
// VALUE. It cannot see whether the value is used, and it passed for as long as the cap was
// dead. This test drives the contract and is the one that fails if the cap goes dormant
// again: it asserts the refusal AT the cap, and then — same fixture, one entry fewer — that
// an ordinary withdrawal still goes through. Without that second half, a contract that
// refused every unmap for any reason would score as a pass.
func TestVR203_PendingSpendCapIsEnforced(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const amount = int64(100000)
	const blockHeight = uint32(100)
	fixture := buildMapFixture(t, instruction, amount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "102")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	seedActiveGen0(t, &ct, contractId, owner)

	// Fund the ACTIVE generation so the only thing that can refuse the unmap below is the
	// cap itself — not an empty vault, not a superseded-gen filter.
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
	require.Equal(t, encodeBalance(t, amount), ct.StateGet(contractId, constants.BalancePrefix+owner))

	seedPendingSpends := func(n int) {
		reg := make(mapping.TxSpendsRegistry, 0, n)
		for i := 0; i < n; i++ {
			reg = append(reg, fmt.Sprintf("%064x", i+1))
		}
		ct.StateSet(contractId, constants.TxSpendsRegistryKey, string(mapping.MarshalTxSpendsRegistry(reg)))
	}
	unmapPayload, err := tinyjson.Marshal(mapping.TransferParams{Amount: "50000", To: regtestDestAddress(t)})
	require.NoError(t, err)
	callUnmap := func(txid string) test_utils.ContractTestCallResult {
		return ct.Call(stateEngine.TxVscCallContract{
			Self: stateEngine.TxSelf{TxId: txid, BlockId: "block:" + txid, Index: 71, OpIndex: 0,
				Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
			ContractId: contractId, Action: "unmap", Payload: unmapPayload,
			RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: owner,
		})
	}

	// AT the cap: refused, by the cap specifically, with no debit.
	seedPendingSpends(constants.MaxConcurrentPendingSpends)
	atCap := callUnmap("unmap-at-cap")
	require.False(t, atCap.Success, "unmap must be refused once the pending-spend cap is reached")
	require.Contains(t, atCap.ErrMsg, "too many pending spends in flight",
		"refused by the cap specifically, not by some unrelated guard")
	require.Equal(t, encodeBalance(t, amount), ct.StateGet(contractId, constants.BalancePrefix+owner),
		"a refused unmap must not debit the caller")

	// ONE BELOW the cap: an ordinary withdrawal still goes through. This is what makes the
	// assertion above mean something — a contract refusing everything would fail here.
	seedPendingSpends(constants.MaxConcurrentPendingSpends - 1)
	underCap := callUnmap("unmap-under-cap")
	require.True(t, underCap.Success,
		"the cap must not refuse legitimate withdrawal traffic below it: "+underCap.ErrMsg)
	require.NotEqual(t, encodeBalance(t, amount), ct.StateGet(contractId, constants.BalancePrefix+owner),
		"the accepted unmap debited the caller, so the positive control really exercised the path")

	// The accepted spend is now itself on the list, so the very next unmap is at the cap
	// again — the bound holds continuously, not just at the moment it is seeded.
	require.False(t, callUnmap("unmap-refilled").Success,
		"the accepted spend refills the last slot, so the next unmap is refused again")
}
