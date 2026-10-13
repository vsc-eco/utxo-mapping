package current_test

// F1 fix: a user unmap whose TSS signature has not yet been issued must NOT be
// strandable by a key rotation. HandleUnmap debits the user and builds the spend
// synchronously, but the node produces the signature asynchronously and output-scopes
// a retiring key's keysign to its successor. So if activateKey retires the gen while
// such an unmap is in flight, the unmap can never be signed afterward - redriveSpend
// refuses the rotated inputs, migrateVault skips the reserved input, and NN#3 then
// blocks every later createKey. The user stays debited forever and the whole rotation
// wedges (proven in the prove phase: TestProofF1a_UnsignedUnmapStrandedByActivation).
//
// The fix (ActivatePendingGeneration -> pendingUnmapOnGeneration) refuses activation
// while the active, about-to-retire generation still carries an in-flight unmap, forcing
// the clean, proven settle-before-activate path. It is fail-closed and introduces no new
// brick: before rotation the unmap is always rescuable (confirmSpend, or redriveSpend then
// confirm), as the prove-phase control TestProofF1b showed.
//
// A/B: BEFORE = TestProofF1a (activateKey succeeded, unmap stranded) against the unfixed
// wasm. AFTER = these tests against the rebuilt wasm.

import (
	"fmt"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/require"
)

// f1SetupWithPendingUnmap seeds an active gen-0 vault, deposits one UTXO (crediting the
// owner), then builds a user unmap so a live "us-" record + reserved input ride gen-0 with
// its TSS signature NOT yet issued. Returns the harness and the pending unmap's txid.
func f1SetupWithPendingUnmap(t *testing.T) (ct *test_utils.ContractTest, contractId, owner, unmapTxId string) {
	t.Helper()
	const instruction = "deposit_to=hive:milo-hpr"
	const deposit = int64(100_000)
	const blockHeight = uint32(100)
	const withdraw = int64(40_000)

	fixture := buildMapFixture(t, instruction, deposit, blockHeight)
	c := test_utils.NewContractTest()
	t.Cleanup(func() { c.DataLayer.Stop() })
	ct = &c
	contractId, owner = "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1, FeeSupply: 100_000})))
	ct.StateSet(contractId, constants.LastHeightKey, "102")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	seedActiveGen0(t, ct, contractId, owner)

	// Deposit -> one confirmed gen-0 UTXO + a credited balance.
	mp, err := tinyjson.Marshal(mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight: blockHeight, RawTxHex: fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex, TxIndex: fixture.TxIndex,
		},
		Instructions: []string{instruction},
	})
	require.NoError(t, err)
	require.True(t, ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "map-dep", BlockId: "block:map", Index: 70, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "map", Payload: mp,
		RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: owner}).Success)

	// Withdraw a portion -> builds the spend, writes "us-" on gen-0, reserves the input.
	up, err := tinyjson.Marshal(mapping.TransferParams{
		Amount: fmt.Sprintf("%d", withdraw),
		To:     regtestDestAddress(t),
	})
	require.NoError(t, err)
	require.True(t, ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "unmap-1", BlockId: "block:unmap", Index: 71, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "unmap", Payload: up,
		RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: owner}).Success)

	txids, err := mapping.UnmarshalTxSpendsRegistry([]byte(ct.StateGet(contractId, constants.TxSpendsRegistryKey)))
	require.NoError(t, err)
	require.Len(t, txids, 1, "exactly one pending withdrawal expected")
	unmapTxId = txids[0]
	require.NotEmpty(t, ct.StateGet(contractId, constants.PendingUnmapPrefix+unmapTxId),
		"precondition: the unmap wrote its live \"us-\" record on gen-0")
	return ct, contractId, owner, unmapTxId
}

// TestWR_F1_ActivateRefusedWhilePendingUnmap: the fix. Activation is refused while gen-0
// carries the in-flight unmap, and nothing is lost - gen-0 stays ACTIVE, gen-1 stays
// PENDING, and the unmap record is untouched (still rescuable).
func TestWR_F1_ActivateRefusedWhilePendingUnmap(t *testing.T) {
	ct, contractId, owner, unmapTxId := f1SetupWithPendingUnmap(t)

	// Mint + key the successor (NN#3 permits createKey - gen-0 is active, not superseded).
	require.Empty(t, callKeyAction(t, ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)

	// THE FIX: activateKey must refuse while the pending unmap rides the active gen.
	// Before the fix this SUCCEEDED and stranded the user's debited balance forever.
	res := callKeyAction(t, ct, contractId, owner, "activateKey", []byte(""))
	require.False(t, res.Success, "activateKey must be refused while a pending unmap rides the active gen")
	require.Contains(t, res.ErrMsg, "in-flight unmap", "refusal must name the F1 cause; got %q", res.ErrMsg)

	// Fail-closed, not stranded: gen-0 still ACTIVE, gen-1 still PENDING, unmap still live.
	vaults, _, activeGen := loadVaults(t, ct, contractId)
	require.Equal(t, uint32(0), activeGen, "gen-0 must still be the active gen after the refusal")
	require.Equal(t, mapping.VaultStatusActive, vaultByGen(t, vaults, 0).Status, "gen-0 stays ACTIVE (never retired)")
	require.Equal(t, mapping.VaultStatusPending, vaultByGen(t, vaults, 1).Status, "gen-1 stays PENDING (never activated)")
	require.NotEmpty(t, ct.StateGet(contractId, constants.PendingUnmapPrefix+unmapTxId),
		"the unmap record is untouched and still rescuable (confirmSpend / redriveSpend-then-confirm)")
}

// TestWR_F1_SettleThenActivateSucceeds: the proven-clean path. Once the pending unmap is
// settled, the guard sees nothing in flight and rotation proceeds normally. This also
// exercises the guard's empty-registry branch (no spurious over-blocking).
func TestWR_F1_SettleThenActivateSucceeds(t *testing.T) {
	ct, contractId, owner, unmapTxId := f1SetupWithPendingUnmap(t)

	// Settle the unmap BEFORE rotating (confirmSpend reaches settleUnmap; see VR2-22).
	require.True(t, confirmMigrationSweep(t, ct, contractId, owner, unmapTxId, 101).Success,
		"the pending unmap must settle on confirm")
	require.Empty(t, ct.StateGet(contractId, constants.PendingUnmapPrefix+unmapTxId),
		"the unmap settled: its \"us-\" record is consumed")

	// Now rotation proceeds cleanly - the F1 guard finds no pending unmap and allows it.
	require.Empty(t, callKeyAction(t, ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	res := callKeyAction(t, ct, contractId, owner, "activateKey", []byte(""))
	require.True(t, res.Success, "activate must succeed once the pending unmap is settled; msg=%q", res.ErrMsg)

	vaults, _, activeGen := loadVaults(t, ct, contractId)
	require.Equal(t, uint32(1), activeGen, "gen-1 must be active after the clean rotation")
	require.Equal(t, mapping.VaultStatusRetiring, vaultByGen(t, vaults, 0).Status, "gen-0 retires cleanly after settle")
	require.Equal(t, mapping.VaultStatusActive, vaultByGen(t, vaults, 1).Status, "gen-1 is active")
}
