package current_test

import (
	"testing"
	"time"

	"btc-mapping-contract/contract/blocklist"
	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/require"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
)

// ---------------------------------------------------------------------------
// U-4 Ragnarök — governance return-to-depositors.
//
// Coverage map (build-map §5 test list, RAGNAROK-U4-BUILD-MAP.md):
//  1. Inertness (rg absent -> byte-identical behavior): proven primarily by the
//     FULL pre-existing suite (97 tests, none of which ever set "rg") continuing
//     to pass unmodified, PLUS the baseline pass inside
//     TestRagnarokFreezesUserAndRotationOps below, which asserts none of the
//     newly-gated ops fail on the ragnarok gate while it is unset.
//  2. Flag auth + monotonicity: TestRagnarokSetAuthAndMonotonic.
//  3/4. Freeze set vs stays-live set: TestRagnarokFreezesUserAndRotationOps,
//     TestRagnarokStaysLiveDuringWindDown, TestRagnarokOracleHeaderPathStaysLive.
//  5/8. Claim gate (before/without rg): TestClaimRagnarokGatedOnFlag.
//  6/7. Claim happy path + settle + dust floor: TestClaimRagnarokDrainsAndSettles,
//     TestClaimRagnarokDustFloor.
//  9. Claim during rotation / residual: TestClaimRagnarokRequiresActiveGenBacking.
// 10. In-flight unmap survives a Ragnarök trip: NOT re-tested here — it is the
//     exact code path already proven by TestConfirmSpendPendingExemptFromPause
//     (confirm_spend_test.go); claimRagnarok introduces no new confirm-time
//     behavior for "us-" records (settleUnmap is unchanged).
// 11. Pause + Ragnarök coexist: TestClaimRagnarokExemptFromPause.
//
// NOT independently runtime-tested here (tracked, not silently claimed): the
// build-map's aspirational stays-live list also includes topUpFeeReserve and
// reportUnauthorizedSpend. Neither main.go export was touched by this slice (no
// checkNotRagnarok call was added to either — verified by inspection), but no
// dedicated fixture exists yet in this suite to drive either op end-to-end
// (both need a real SPV-provable BTC tx fixture that isn't reused elsewhere), so
// their "stays live under ragnarok" claim rests on code-inspection, not a
// runtime assertion. Flagged explicitly rather than glossed over.
// ---------------------------------------------------------------------------

// callRagnarokAction is a small generic dispatcher shared by every test in this
// file — same shape as callKeyAction (vault_lifecycle_test.go) but with a
// caller-supplied RcLimit, since claim-shaped ops cost like unmap (mapping_test.go
// TestUnmap: delete-at-confirm raised unmap build cost — 20000 is a safe budget)
// while pure gate-checks are far cheaper.
func callRagnarokAction(
	t *testing.T, ct *test_utils.ContractTest, contractId, caller, action string, payload []byte, rcLimit uint,
) test_utils.ContractTestCallResult {
	t.Helper()
	return ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: "tx-" + action, BlockId: "block:" + action, Index: 1, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{caller}, RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     action,
		Payload:    payload,
		RcLimit:    rcLimit,
		Intents:    []contracts.Intent{},
		Caller:     caller,
	})
}

// seedClaimFixture builds a minimal flat-balance contract (no vault list — the
// pre-S1 legacy gen-0-only shape) with a balance and enough confirmed UTXO
// headroom for claimRagnarok to select inputs covering the FULL balance plus the
// miner fee (getInputUtxoIds always requires inputs to cover amount+fee on top,
// regardless of DeductFee — see handlers.go/unmapping.go). RagnarokModeKey is
// pre-set ("1") since every test using this fixture wants ragnarok already engaged.
func seedClaimFixture(t *testing.T, balance int64) (*test_utils.ContractTest, string, string) {
	t.Helper()
	const fakeTxId0 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const fakeTxId1 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const instruction = "deposit_to=hive:milo-hpr"
	utxoEach := balance/2 + 2000 // headroom above the balance for the miner fee

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.BalancePrefix+owner, encodeBalance(t, balance))
	ct.StateSet(contractId, constants.ObservedBlockPrefix+"100", buildObservedList(t,
		observedParam{fakeTxId0, 0}, observedParam{fakeTxId1, 0},
	))
	ct.StateSet(contractId, constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(mapping.UtxoRegistry{
		{Id: 1024, Amount: utxoEach},
		{Id: 1025, Amount: utxoEach},
	})))
	ct.StateSet(contractId, constants.UtxoPrefix+"400", depositUtxoBinary(t, fakeTxId0, 0, utxoEach, instruction))
	ct.StateSet(contractId, constants.UtxoPrefix+"401", changeUtxoBinary(t, fakeTxId1, 0, utxoEach))
	ct.StateSet(contractId, constants.UtxoLastIdKey, encodeUtxoCounters(1026, 0))
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: balance,
		UserSupply:   balance,
		FeeSupply:    0,
		BaseFeeRate:  1,
	})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", buildSeedHeaderRaw(t, time.Unix(0, 0)))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	ct.StateSet(contractId, constants.RagnarokModeKey, "1")
	return &ct, contractId, owner
}

// TestRagnarokSetAuthAndMonotonic — checkOwner-gated (the SAME authority as
// pause/unpause). Once set, the flag persists across an unrelated pause/unpause
// cycle (build-map D-1: rg and paused are orthogonal axes — ragnarok does NOT
// auto-unpause), and a second ragnarok() call is idempotent. There is no
// "unRagnarok" export anywhere in the diff (structural monotonicity — no code
// path calls StateDeleteObject(RagnarokModeKey)), so that guarantee is not
// separately runtime-tested (there is no action to call).
func TestRagnarokSetAuthAndMonotonic(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)

	// Non-owner refused; flag stays absent.
	r := callRagnarokAction(t, &ct, contractId, "hive:attacker", "ragnarok", []byte(""), 100000)
	require.False(t, r.Success, "non-owner must not be able to engage ragnarok")
	require.Equal(t, "", ct.StateGet(contractId, constants.RagnarokModeKey))

	// Owner engages it.
	r = callRagnarokAction(t, &ct, contractId, owner, "ragnarok", []byte(""), 100000)
	require.True(t, r.Success, r.ErrMsg)
	require.Equal(t, "1", ct.StateGet(contractId, constants.RagnarokModeKey))

	// Orthogonal to pause: a pause/unpause cycle must not touch "rg".
	require.True(t, callRagnarokAction(t, &ct, contractId, owner, "pause", []byte(""), 100000).Success)
	require.True(t, callRagnarokAction(t, &ct, contractId, owner, "unpause", []byte(""), 100000).Success)
	require.Equal(t, "1", ct.StateGet(contractId, constants.RagnarokModeKey),
		"unpause must not clear ragnarok (D-1: orthogonal axes)")

	// Idempotent second call.
	r = callRagnarokAction(t, &ct, contractId, owner, "ragnarok", []byte(""), 100000)
	require.True(t, r.Success, r.ErrMsg)
	require.Equal(t, "1", ct.StateGet(contractId, constants.RagnarokModeKey))
}

// TestRagnarokFreezesUserAndRotationOps — build-map §3a: every listed op is
// refused with the ragnarok-specific error once governance has engaged
// Ragnarök. The FIRST pass (rg unset) asserts none of these calls are ever
// refused BECAUSE of ragnarok — i.e. the gate is inert — regardless of whatever
// else the (deliberately minimal/garbage) payload causes to happen; the SECOND
// pass (rg engaged) asserts every one of them now fails specifically on the
// ragnarok gate, proving checkNotRagnarok fires before any parsing/business
// logic for each op (so no crafted payload can route around it).
func TestRagnarokFreezesUserAndRotationOps(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)

	unmapPayload, err := tinyjson.Marshal(mapping.TransferParams{Amount: "1000", To: regtestDestAddress(t)})
	require.NoError(t, err)
	transferPayload, err := tinyjson.Marshal(mapping.TransferParams{Amount: "1", To: "hive:someone-else"})
	require.NoError(t, err)
	allowancePayload, err := tinyjson.Marshal(mapping.AllowanceParams{Spender: "hive:someone-else", Amount: "1"})
	require.NoError(t, err)
	regKeyPay := regKeyPayload(t, Gen1PrimaryHex, "")

	type gatedCall struct {
		action  string
		payload []byte
	}
	calls := []gatedCall{
		{"map", []byte("")}, // checkNotRagnarok fires before JSON parsing
		{"unmap", unmapPayload},
		{"unmapFrom", unmapPayload},
		{"transfer", transferPayload},
		{"transferFrom", transferPayload},
		{"approve", allowancePayload},
		{"increaseAllowance", allowancePayload},
		{"decreaseAllowance", allowancePayload},
		{"registerPublicKey", regKeyPay},
		{"createKey", []byte("")},
		{"activateKey", []byte("")},
		{"discardPendingKey", []byte("")},
		{"registerRouter", []byte("")},
	}

	// Pass 1: rg unset. Whatever else happens (many of these will fail on their
	// own unrelated preconditions — no pubkeys registered, no pending keygen,
	// empty JSON, etc.) the failure must NEVER be the ragnarok message.
	for _, c := range calls {
		r := callRagnarokAction(t, &ct, contractId, owner, c.action, c.payload, 1000000)
		if !r.Success {
			require.NotContains(t, r.ErrMsg, "ragnarok",
				"%s must not be refused on the ragnarok gate while rg is unset (got: %s)", c.action, r.ErrMsg)
		}
	}

	// Engage ragnarok.
	require.True(t, callRagnarokAction(t, &ct, contractId, owner, "ragnarok", []byte(""), 100000).Success)

	// Pass 2: every op now aborts specifically on the ragnarok gate.
	for _, c := range calls {
		r := callRagnarokAction(t, &ct, contractId, owner, c.action, c.payload, 1000000)
		require.False(t, r.Success, "%s must be refused once ragnarok is engaged", c.action)
		require.Contains(t, r.ErrMsg, "ragnarok",
			"%s must fail specifically on the ragnarok gate (got: %s)", c.action, r.ErrMsg)
	}
}

// TestRagnarokStaysLiveDuringWindDown — build-map §3b/§4b: migrateVault,
// confirmSpend, and renewKey all stay LIVE (no ragnarok gate) so an in-progress
// rotation can be consolidated and its sweep can settle, and a long wind-down
// can't let a fund-holding generation's key expire out from under it. Rotation
// itself completes BEFORE ragnarok is engaged (createKey/registerPublicKey/
// activateKey are themselves frozen once ragnarok is set — see the freeze test),
// matching the real operational sequence: governance trips Ragnarök on an
// already-rotating vault, then drives it to completion with the ops that stay
// live.
func TestRagnarokStaysLiveDuringWindDown(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const amount = int64(100000)
	const blockHeight = uint32(100)
	fixture := buildMapFixture(t, instruction, amount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1, FeeSupply: 100000})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	seedActiveGen0(t, &ct, contractId, owner)

	// Deposit to gen-0, then rotate to gen-1 — BEFORE ragnarok.
	params := mapping.MapParams{TxData: &mapping.VerificationRequest{
		BlockHeight: blockHeight, RawTxHex: fixture.RawTxHex,
		MerkleProofHex: fixture.MerkleProofHex, TxIndex: fixture.TxIndex}, Instructions: []string{instruction}}
	payload, err := tinyjson.Marshal(params)
	require.NoError(t, err)
	require.True(t, ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "map-dep", BlockId: "block:map", Index: 70, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "map", Payload: payload, RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: owner}).Success)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "activateKey", []byte("")).Err)

	// Governance engages Ragnarök mid-rotation (gen-0 retiring+funded, gen-1 active).
	require.True(t, callKeyAction(t, &ct, contractId, owner, "ragnarok", []byte("")).Success)
	require.Equal(t, "1", ct.StateGet(contractId, constants.RagnarokModeKey))

	// migrateVault stays LIVE under ragnarok — consolidates gen-0 into gen-1.
	r := callKeyAction(t, &ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, r.Err, "migrateVault must stay live under ragnarok: "+r.ErrMsg)
	sweepTxId := r.Ret
	require.NotEmpty(t, sweepTxId)

	// confirmSpend stays LIVE (settles the sweep) under ragnarok.
	cr := confirmMigrationSweep(t, &ct, contractId, owner, sweepTxId, 101)
	require.True(t, cr.Success, "confirmSpend must stay live under ragnarok: "+cr.ErrMsg)
	vaults, _, activeGen := loadVaults(t, &ct, contractId)
	require.Equal(t, uint32(1), activeGen)
	require.Equal(t, mapping.VaultStatusDraining, vaults[0].Status)

	// renewKey stays LIVE under ragnarok (never-brick: a long wind-down must not
	// let a fund-holding gen's key expire).
	rk := callKeyAction(t, &ct, contractId, owner, "renewKey", []byte(""))
	require.Empty(t, rk.Err, "renewKey must stay live under ragnarok: "+rk.ErrMsg)
}

// TestRagnarokOracleHeaderPathStaysLive — the oracle header path (addBlocks)
// must keep functioning under Ragnarök so claim/confirm SPV proofs can still be
// verified and headers aren't stuck at a stale tip mid-wind-down.
func TestRagnarokOracleHeaderPathStaysLive(t *testing.T) {
	seedTime := time.Unix(0, 0)
	seedHex, chainHex := buildHeaderChain(t, seedTime, 2)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, seedHex))
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.RagnarokModeKey, "1") // ragnarok already engaged

	payload, err := tinyjson.Marshal(blocklist.AddBlocksParams{Blocks: chainHex, LatestFee: 2})
	require.NoError(t, err)
	r := callRagnarokAction(t, &ct, contractId, owner, "addBlocks", payload, 1000000)
	require.True(t, r.Success, "addBlocks (oracle header path) must stay live under ragnarok: "+r.ErrMsg)
}

// TestClaimRagnarokGatedOnFlag — claimRagnarok is unreachable/inert until
// governance has set RagnarokModeKey.
func TestClaimRagnarokGatedOnFlag(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.BalancePrefix+owner, encodeBalance(t, 10000))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	// RagnarokModeKey deliberately left ABSENT.

	payload, err := tinyjson.Marshal(mapping.TransferParams{To: regtestDestAddress(t)})
	require.NoError(t, err)
	r := callRagnarokAction(t, &ct, contractId, owner, "claimRagnarok", payload, 20000)
	require.False(t, r.Success, "claimRagnarok must be refused while ragnarok is not engaged")
	require.Contains(t, r.ErrMsg, "ragnarok")
	require.Equal(t, encodeBalance(t, 10000), ct.StateGet(contractId, constants.BalancePrefix+owner),
		"a refused claim must not debit the caller")
}

// TestClaimRagnarokDustFloor — a balance at or below dustThreshold cannot be
// claimed (mirrors HandleUnmap's own dust floor).
func TestClaimRagnarokDustFloor(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.BalancePrefix+owner, encodeBalance(t, 500)) // < dustThreshold (546)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	ct.StateSet(contractId, constants.RagnarokModeKey, "1")

	payload, err := tinyjson.Marshal(mapping.TransferParams{To: regtestDestAddress(t)})
	require.NoError(t, err)
	r := callRagnarokAction(t, &ct, contractId, owner, "claimRagnarok", payload, 20000)
	require.False(t, r.Success, "a dust-or-below balance must not be claimable")
	require.Contains(t, r.ErrMsg, "dust")
	require.Equal(t, encodeBalance(t, 500), ct.StateGet(contractId, constants.BalancePrefix+owner))
}

// TestClaimRagnarokDrainsAndSettles — the end-to-end Guard-1 proof: claimRagnarok
// drains the caller's ENTIRE balance to zero and debits Supply immediately at
// BUILD (exactly like an ordinary unmap), while the swept inputs stay
// REGISTERED + reserved (a live "us-" record) until confirmSpend settles them —
// delete-at-confirm inherited verbatim, no new mechanics.
func TestClaimRagnarokDrainsAndSettles(t *testing.T) {
	const balance = int64(8000)
	ct, contractId, owner := seedClaimFixture(t, balance)

	payload, err := tinyjson.Marshal(mapping.TransferParams{To: regtestDestAddress(t)})
	require.NoError(t, err)
	r := callRagnarokAction(t, ct, contractId, owner, "claimRagnarok", payload, 20000)
	require.True(t, r.Success, r.ErrMsg)

	// Balance + Supply are debited immediately at build.
	require.Equal(t, "", ct.StateGet(contractId, constants.BalancePrefix+owner), "claim drains the balance to zero")
	supply, err := mapping.UnmarshalSupply([]byte(ct.StateGet(contractId, constants.SupplyKey)))
	require.NoError(t, err)
	require.Equal(t, int64(0), supply.ActiveSupply)
	require.Equal(t, int64(0), supply.UserSupply)

	// Guard-1: swept inputs stay registered + a live "us-" record exists until settle.
	txSpends, err := mapping.UnmarshalTxSpendsRegistry([]byte(ct.StateGet(contractId, constants.TxSpendsRegistryKey)))
	require.NoError(t, err)
	require.Len(t, txSpends, 1, "exactly one pending claim tx")
	claimTxId := txSpends[0]
	require.NotEmpty(t, ct.StateGet(contractId, constants.PendingUnmapPrefix+claimTxId),
		"a live us- record must exist for the claim (Guard-1 delete-at-confirm)")
	regBuild, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, regBuild, 2, "swept inputs stay registered until settle (delete-at-confirm)")

	// confirmSpend settles the claim.
	cr := confirmMigrationSweep(t, ct, contractId, owner, claimTxId, 101)
	require.True(t, cr.Success, cr.ErrMsg)
	require.Empty(t, ct.StateGet(contractId, constants.PendingUnmapPrefix+claimTxId), "us- record cleared at settle")
	require.Empty(t, ct.StateGet(contractId, constants.TxSpendsPrefix+claimTxId), "signing data cleared at settle")
	// Balance stays drained post-settle (settleUnmap does no Supply/balance mutation).
	require.Equal(t, "", ct.StateGet(contractId, constants.BalancePrefix+owner))
}

// TestClaimRagnarokExemptFromPause — build-map §3d: claimRagnarok is
// pause-EXEMPT (Ragnarök supersedes pause for the return path), and its settle
// at confirmSpend is separately pause-exempt for a live "us-" record (BRK-4b) —
// both hold simultaneously.
func TestClaimRagnarokExemptFromPause(t *testing.T) {
	const balance = int64(8000)
	ct, contractId, owner := seedClaimFixture(t, balance)
	ct.StateSet(contractId, constants.PausedKey, "1")

	payload, err := tinyjson.Marshal(mapping.TransferParams{To: regtestDestAddress(t)})
	require.NoError(t, err)
	r := callRagnarokAction(t, ct, contractId, owner, "claimRagnarok", payload, 20000)
	require.True(t, r.Success, "claimRagnarok must succeed even while PAUSED: "+r.ErrMsg)

	txSpends, err := mapping.UnmarshalTxSpendsRegistry([]byte(ct.StateGet(contractId, constants.TxSpendsRegistryKey)))
	require.NoError(t, err)
	require.Len(t, txSpends, 1)
	claimTxId := txSpends[0]

	cr := confirmMigrationSweep(t, ct, contractId, owner, claimTxId, 101)
	require.True(t, cr.Success, "settle must succeed even while PAUSED (BRK-4b pause-exemption for a live us- record): "+cr.ErrMsg)
}

// TestClaimRagnarokRequiresActiveGenBacking — build-map §4b, the sharpest
// documented interaction: claimRagnarok reuses getInputUtxoIds UNCHANGED, whose
// D-1 filter selects ACTIVE-generation UTXOs only. If Ragnarök trips while a
// caller's backing sits entirely under a just-superseded (retiring) generation,
// the claim is refused (fail-closed, no debit) until migrateVault — kept LIVE
// under ragnarok specifically for this reason — consolidates the funds into the
// active generation, after which the SAME claim succeeds.
func TestClaimRagnarokRequiresActiveGenBacking(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const amount = int64(100000)
	const blockHeight = uint32(100)
	fixture := buildMapFixture(t, instruction, amount, blockHeight)
	// A second, separate deposit crediting a DIFFERENT account ("hive:reserve") — real
	// extra BTC backing beyond the test user's own claimable balance. Without this, the
	// vault's ONLY real backing is exactly the user's own deposit, and migrateVault's
	// real on-chain miner fee (paid out of the swept UTXO's actual value — see
	// TestMigrateVaultSweepsRetiringGen) would eat into that same UTXO, leaving strictly
	// less than the user's registered balance and making a full-balance claim
	// unsatisfiable for a reason UNRELATED to the D-1 property this test targets. A real
	// deployed vault always carries this kind of surplus from accumulated historical fees
	// (topUpFeeReserve); this fixture models that surplus as a second depositor's coin.
	const reserveInstruction = "deposit_to=hive:reserve"
	const reserveAmount = int64(20000)
	const reserveBlockHeight = uint32(99)
	reserveFixture := buildMapFixture(t, reserveInstruction, reserveAmount, reserveBlockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1, FeeSupply: 100000})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	ct.StateSet(contractId, constants.BlockPrefix+"99", decodeHex(t, reserveFixture.BlockHeaderHex))
	seedActiveGen0(t, &ct, contractId, owner)

	// Deposit the surplus first, then the test user's own deposit, both to gen-0 (active).
	reserveParams := mapping.MapParams{TxData: &mapping.VerificationRequest{
		BlockHeight: reserveBlockHeight, RawTxHex: reserveFixture.RawTxHex,
		MerkleProofHex: reserveFixture.MerkleProofHex, TxIndex: reserveFixture.TxIndex}, Instructions: []string{reserveInstruction}}
	reservePayload, err := tinyjson.Marshal(reserveParams)
	require.NoError(t, err)
	require.True(t, ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "map-reserve", BlockId: "block:map", Index: 69, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "map", Payload: reservePayload, RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: owner}).Success)

	// Then rotate: gen-0 -> retiring (funded), gen-1 -> active (empty).
	params := mapping.MapParams{TxData: &mapping.VerificationRequest{
		BlockHeight: blockHeight, RawTxHex: fixture.RawTxHex,
		MerkleProofHex: fixture.MerkleProofHex, TxIndex: fixture.TxIndex}, Instructions: []string{instruction}}
	payload, err := tinyjson.Marshal(params)
	require.NoError(t, err)
	require.True(t, ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "map-dep", BlockId: "block:map", Index: 70, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "map", Payload: payload, RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: owner}).Success)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "activateKey", []byte("")).Err)

	// Engage ragnarok while the funds still sit entirely under the RETIRING gen-0.
	require.True(t, callKeyAction(t, &ct, contractId, owner, "ragnarok", []byte("")).Success)

	claimPayload, err := tinyjson.Marshal(mapping.TransferParams{To: regtestDestAddress(t)})
	require.NoError(t, err)

	r1 := callRagnarokAction(t, &ct, contractId, owner, "claimRagnarok", claimPayload, 20000)
	require.False(t, r1.Success, "claimRagnarok must be refused while the balance is backed only by the retiring gen (D-1)")
	require.Equal(t, encodeBalance(t, amount), ct.StateGet(contractId, constants.BalancePrefix+owner),
		"a refused claim must not debit the caller")

	// migrateVault stays LIVE under ragnarok: consolidate gen-0 into gen-1.
	mr := callKeyAction(t, &ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, mr.Err, mr.ErrMsg)
	sweepTxId := mr.Ret
	require.NotEmpty(t, sweepTxId)
	require.True(t, confirmMigrationSweep(t, &ct, contractId, owner, sweepTxId, 101).Success)

	// Now gen-1 (active) holds the consolidated funds — the SAME claim now succeeds.
	r2 := callRagnarokAction(t, &ct, contractId, owner, "claimRagnarok", claimPayload, 20000)
	require.True(t, r2.Success, "claimRagnarok must succeed once migrateVault has consolidated funds into the active gen: "+r2.ErrMsg)
	require.Equal(t, "", ct.StateGet(contractId, constants.BalancePrefix+owner), "balance fully drained")
}
