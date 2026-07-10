package current_test

import (
	"dash-mapping-contract/contract/constants"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"vsc-node/lib/test_utils"
)

// seedViaAction calls the actual seedBlocks contract action to properly
// initialize all state (supply, height, block header, seed height).
func seedViaAction(t *testing.T, w *ctWrapper, id string) {
	t.Helper()
	payload := `{"block_header":"` + lastBlockHeader + `","block_height":` + lastBlockHeight + `}`
	r := callActionOnContract(t, w, id, "seedBlocks", payload, testOwner)
	require.True(t, r.Success, "seedBlocks should succeed: %s %s", r.Err, r.ErrMsg)
}

// TestPruning tests the block header pruning logic added to HandleAddBlocks.
func TestPruning(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	w := &ctWrapper{ct: &ct}

	oracleCaller := "did:vsc:oracle:dash"
	seedHeight, _ := strconv.Atoi(lastBlockHeight) // 116087

	// ========== initPruning ==========

	t.Run("InitPruning_OwnerSucceeds", func(t *testing.T) {
		ct.RegisterContract("prune_init", testOwner, ContractWasm)
		r := callActionOnContract(t, w, "prune_init", "initPruning", `100000`, testOwner)
		require.True(t, r.Success, "initPruning should succeed: %s %s", r.Err, r.ErrMsg)
		assert.Contains(t, r.Ret, "prune floor set to 100000")

		pf := w.ct.StateGet("prune_init", constants.PruneFloorKey)
		assert.Equal(t, "100000", pf)
		sh := w.ct.StateGet("prune_init", constants.SeedHeightKey)
		assert.Equal(t, "100000", sh)
	})

	t.Run("InitPruning_DoubleCallFails", func(t *testing.T) {
		r := callActionOnContract(t, w, "prune_init", "initPruning", `100001`, testOwner)
		assert.False(t, r.Success, "initPruning should fail when floor already set")
		assert.Contains(t, r.ErrMsg, "already set")
	})

	t.Run("InitPruning_NonOwnerFails", func(t *testing.T) {
		ct.RegisterContract("prune_auth", testOwner, ContractWasm)
		r := callActionOnContract(t, w, "prune_auth", "initPruning", `100000`, "hive:attacker")
		assert.False(t, r.Success, "initPruning by non-owner should fail")
	})

	t.Run("InitPruning_InvalidInputFails", func(t *testing.T) {
		ct.RegisterContract("prune_bad", testOwner, ContractWasm)
		r := callActionOnContract(t, w, "prune_bad", "initPruning", `not_a_number`, testOwner)
		assert.False(t, r.Success, "initPruning with non-numeric input should fail")
	})

	// ========== SeedBlocks sets seed height ==========

	t.Run("SeedBlocks_SetsSeedHeight", func(t *testing.T) {
		ct.RegisterContract("seed_height", testOwner, ContractWasm)
		seedViaAction(t, w, "seed_height")

		sh := w.ct.StateGet("seed_height", constants.SeedHeightKey)
		assert.Equal(t, lastBlockHeight, sh)
	})

	// ========== Pruning during addBlocks ==========

	t.Run("AddBlocks_PrunesOldHeaders", func(t *testing.T) {
		id := "prune_add"
		ct.RegisterContract(id, testOwner, ContractWasm)
		seedViaAction(t, w, id)

		// tip after addBlocks = seedHeight + 2 = 116089
		// retainFrom = tip - MaxBlockRetention + 1
		tip := seedHeight + 2
		retainFrom := tip - constants.MaxBlockRetention + 1

		// Pre-populate fake block keys below retainFrom to simulate accumulated state.
		startHeight := retainFrom - 10
		for h := startHeight; h < seedHeight; h++ {
			w.ct.StateSet(id, constants.BlockPrefix+strconv.Itoa(h), "fake_header")
		}
		w.ct.StateSet(id, constants.PruneFloorKey, strconv.Itoa(startHeight))

		r := callActionOnContract(t, w, id, "addBlocks", twoBlocksPayload, oracleCaller)
		require.True(t, r.Success, "addBlocks should succeed: %s %s", r.Err, r.ErrMsg)

		pf := w.ct.StateGet(id, constants.PruneFloorKey)
		pfInt, _ := strconv.Atoi(pf)
		t.Logf("Prune floor after addBlocks: %s", pf)
		assert.Greater(t, pfInt, startHeight, "prune floor should advance")

		// Oldest blocks pruned
		assert.Empty(t, w.ct.StateGet(id, constants.BlockPrefix+strconv.Itoa(startHeight)),
			"block at startHeight should be pruned")
		// Recent blocks preserved
		assert.NotEmpty(t, w.ct.StateGet(id, constants.BlockPrefix+lastBlockHeight), "seed block should be preserved")
	})

	t.Run("AddBlocks_NoPruningWithoutFloor", func(t *testing.T) {
		id := "prune_nofloor"
		ct.RegisterContract(id, testOwner, ContractWasm)

		// Seed via state directly WITHOUT seed height key (simulate legacy contract)
		seedBlocksViaStateForContract(w, id)
		// Also need proper supply — call seedBlocks first then remove seed height
		// Actually, use the real seedBlocks but then delete the seed height key
		// to simulate a legacy contract that was deployed before pruning.
		// But seedBlocksViaState uses old supply key. Let's just seed properly
		// and then manually clear the seed height and prune floor.

		// Actually, the issue is seedBlocksViaState doesn't set supply at "s".
		// Let's seed via action then clear the pruning keys.
		ct.RegisterContract("prune_nofloor2", testOwner, ContractWasm)
		seedViaAction(t, w, "prune_nofloor2")
		// Clear seed height and prune floor to simulate legacy
		w.ct.StateSet("prune_nofloor2", constants.SeedHeightKey, "")
		w.ct.StateSet("prune_nofloor2", constants.PruneFloorKey, "")

		for h := 115980; h < seedHeight; h++ {
			w.ct.StateSet("prune_nofloor2", constants.BlockPrefix+strconv.Itoa(h), "fake_header")
		}

		r := callActionOnContract(t, w, "prune_nofloor2", "addBlocks", twoBlocksPayload, oracleCaller)
		require.True(t, r.Success, "addBlocks should succeed: %s %s", r.Err, r.ErrMsg)

		// Without floor, no pruning should occur
		kept := w.ct.StateGet("prune_nofloor2", constants.BlockPrefix+"115980")
		assert.NotEmpty(t, kept, "block 115980 should NOT be pruned without floor")
	})

	t.Run("AddBlocks_PruneRespectsBatchLimit", func(t *testing.T) {
		id := "prune_batch"
		ct.RegisterContract(id, testOwner, ContractWasm)
		seedViaAction(t, w, id)

		// tip after addBlocks = seedHeight + 2 = 116089
		// retainFrom = tip - MaxBlockRetention + 1
		tip := seedHeight + 2
		retainFrom := tip - constants.MaxBlockRetention + 1

		// Place blocks far enough below retainFrom that more than MaxPrunePerCall
		// are eligible, so the batch limit is exercised.
		startHeight := retainFrom - 2*constants.MaxPrunePerCall
		for h := startHeight; h < seedHeight; h++ {
			w.ct.StateSet(id, constants.BlockPrefix+strconv.Itoa(h), "fake_header")
		}
		w.ct.StateSet(id, constants.PruneFloorKey, strconv.Itoa(startHeight))

		r := callActionOnContract(t, w, id, "addBlocks", twoBlocksPayload, oracleCaller)
		require.True(t, r.Success, "addBlocks should succeed: %s %s", r.Err, r.ErrMsg)

		pf := w.ct.StateGet(id, constants.PruneFloorKey)
		pfInt, _ := strconv.Atoi(pf)
		t.Logf("Prune floor after first call: %s", pf)

		assert.Equal(t, startHeight+constants.MaxPrunePerCall, pfInt,
			"prune floor should advance by MaxPrunePerCall")

		// Block at startHeight should be pruned
		assert.Empty(t, w.ct.StateGet(id, constants.BlockPrefix+strconv.Itoa(startHeight)),
			"block at start should be pruned")

		// Block beyond the batch limit should still exist
		assert.NotEmpty(t, w.ct.StateGet(id, constants.BlockPrefix+strconv.Itoa(startHeight+constants.MaxPrunePerCall)),
			"block at start+MaxPrunePerCall should not yet be pruned")
	})
}
