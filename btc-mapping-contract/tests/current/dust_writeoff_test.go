package current_test

import (
	"strconv"
	"strings"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/require"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"
)

// V-1 dust-escape — writeOffDust (HandleWriteOffDust) + the mapping.go indexOutputs
// min-deposit floor. Proves: (a) the exact grief sequence the finding describes is
// resolved end-to-end (dust deadlocks NN#3 → writeOffDust clears it → rotation proceeds)
// AND the floor then defeats a repeat of the same attack; (b) the legacy-residual
// write-off's Supply math (I1/I2 held exact, I3 slack == D); (c) the floor is INERT
// pre-rotation (byte-identical map behaviour); (d) writeOffDust never touches an
// in-flight (reserved / pending-migration) input, even when a genuinely-eligible
// residual sits in the SAME generation.

type utxoSeed struct {
	id     uint16
	amount int64
}

// seedGenUtxos writes a UTXO registry containing exactly the given entries (all tagged
// generation `gen`), plus each entry's individual blob. Overwrites any existing registry —
// extends retire_test.go's single-entry fundGenUtxo idiom to multiple entries in one call,
// with a caller-controlled amount (fundGenUtxo hardcodes 5000).
func seedGenUtxos(t *testing.T, ct *test_utils.ContractTest, contractId string, gen uint32, seeds []utxoSeed) {
	t.Helper()
	reg := make(mapping.UtxoRegistry, 0, len(seeds))
	for _, s := range seeds {
		reg = append(reg, mapping.UtxoRegistryEntry{Id: s.id, Amount: s.amount})
		u := mapping.Utxo{TxId: strings.Repeat("ab", 32), Vout: uint32(s.id), Amount: s.amount, Generation: gen}
		blob := mapping.MarshalUtxo(&u)
		require.NotNil(t, blob, "MarshalUtxo returned nil (bad txid length)")
		ct.StateSet(contractId, constants.UtxoPrefix+strconv.FormatUint(uint64(s.id), 16), string(blob))
	}
	ct.StateSet(contractId, constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(reg)))
}

// loadSupply reads + decodes the current Supply state.
func loadSupply(t *testing.T, ct *test_utils.ContractTest, contractId string) mapping.SystemSupply {
	t.Helper()
	s, err := mapping.UnmarshalSupply([]byte(ct.StateGet(contractId, constants.SupplyKey)))
	require.NoError(t, err)
	return *s
}

// seedReserve funds the operator fee reserve exactly as a real topUpFeeReserve would:
// FeeSupply rises by `amount` AND a matching untagged UTXO is appended to the registry on
// the ACTIVE generation. Both halves matter — crediting FeeSupply alone would leave the
// fixture claiming backing that does not exist, so conservation I1
// (Sigma(UTXO) == ActiveSupply + FeeSupply) would be false in the fixture and every I1
// assertion downstream would be measuring a lie. APPENDS to the registry (never
// overwrites), so it composes with seedGenUtxos.
func seedReserve(t *testing.T, ct *test_utils.ContractTest, contractId string, activeGen uint32, id uint16, amount int64) {
	t.Helper()
	var reg mapping.UtxoRegistry
	if raw := ct.StateGet(contractId, constants.UtxoRegistryKey); len(raw) > 0 {
		r, err := mapping.UnmarshalUtxoRegistry([]byte(raw))
		require.NoError(t, err)
		reg = r
	}
	reg = append(reg, mapping.UtxoRegistryEntry{Id: id, Amount: amount})
	u := mapping.Utxo{TxId: strings.Repeat("ef", 32), Vout: uint32(id), Amount: amount, Generation: activeGen}
	blob := mapping.MarshalUtxo(&u)
	require.NotNil(t, blob, "MarshalUtxo returned nil (bad txid length)")
	ct.StateSet(contractId, constants.UtxoPrefix+strconv.FormatUint(uint64(id), 16), string(blob))
	ct.StateSet(contractId, constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(reg)))
	sup := loadSupply(t, ct, contractId)
	sup.FeeSupply += amount
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&sup)))
}

// sumRegistry totals the current UTXO registry — the left-hand side of I1.
func sumRegistry(t *testing.T, ct *test_utils.ContractTest, contractId string) int64 {
	t.Helper()
	raw := ct.StateGet(contractId, constants.UtxoRegistryKey)
	if len(raw) == 0 {
		return 0
	}
	reg, err := mapping.UnmarshalUtxoRegistry([]byte(raw))
	require.NoError(t, err)
	var total int64
	for _, e := range reg {
		total += e.Amount
	}
	return total
}

// (a) ★ THE EXACT V-1 ATTACK, end-to-end: a sub-dust deposit lands on gen-0 while it is
// still ACTIVE (the floor is inert pre-rotation, so this is credited exactly like today —
// simulating the "legacy already-credited dust" case, e.g. a genuine small deposit that
// predates any rotation). Gen-0 then rotates and retires holding ONLY that dust — an
// isolated, provably un-sweepable residual (the un-drainable-dust deadlock). migrateVault
// can never sweep it and NN#3 (AnyFundedSupersededGen) permanently blocks the next
// createKey — until writeOffDust force-retires the residual, at which point the deadlock
// clears and rotation proceeds. Finally: the SAME attack repeated against the now-Draining
// gen-0 address is defeated AT THE DOOR by the min-deposit floor (now live, since a
// superseded generation exists) — the floor never lets this situation recur.
func TestWriteOffDust_DefeatsGriefSequence(t *testing.T) {
	const dustAmount = int64(600) // < dustThreshold(546) once its own rate-1 sweep fee is paid
	const blockHeight = uint32(100)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	// VR2-07: seed the tip above the deposit block so the maturity gate is met.
	ct.StateSet(contractId, constants.LastHeightKey, strconv.FormatUint(uint64(blockHeight)+2, 10))

	legacyDustInstr := "deposit_to=hive:legacy-victim"
	legacyFixture := buildMapFixture(t, legacyDustInstr, dustAmount, blockHeight)
	ct.StateSet(contractId, constants.BlockPrefix+strconv.FormatUint(uint64(blockHeight), 10), decodeHex(t, legacyFixture.BlockHeaderHex))

	seedActiveGen0(t, &ct, contractId, owner)

	// A tiny (sub-1000-sat) deposit lands on gen-0 WHILE IT IS ACTIVE — pre-rotation, the
	// floor has never engaged (hasSupersededGen is false), so it is credited exactly like
	// any other deposit today. This is the "legacy already-credited dust" precondition.
	legacyParams := mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight: blockHeight, RawTxHex: legacyFixture.RawTxHex,
			MerkleProofHex: legacyFixture.MerkleProofHex, TxIndex: legacyFixture.TxIndex,
		},
		Instructions: []string{legacyDustInstr},
	}
	legacyPayload, err := tinyjson.Marshal(legacyParams)
	require.NoError(t, err)
	legacyRes := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "map-legacy-dust", BlockId: "block:map1", Index: 70, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "map", Payload: legacyPayload,
		RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: owner,
	})
	require.True(t, legacyRes.Success, legacyRes.ErrMsg)
	require.Equal(t, encodeBalance(t, dustAmount), ct.StateGet(contractId, constants.BalancePrefix+"hive:legacy-victim"),
		"pre-rotation sub-floor deposit is credited (floor inert pre-rotation)")

	// Rotate: gen-0 → RETIRING (carrying ONLY the isolated dust residual), gen-1 → ACTIVE.
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "activateKey", []byte("")).Err)
	vaultsAfterRotate, _, activeGen := loadVaults(t, &ct, contractId)
	require.Equal(t, uint32(1), activeGen)
	require.Equal(t, mapping.VaultStatusRetiring, vaultsAfterRotate[0].Status)

	// NN#3: the next rotation is refused while gen-0 (Retiring) still holds the dust.
	require.NotEmpty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err,
		"createKey must be refused while gen-0 holds the un-drained dust residual (NN#3)")

	// The dust is UN-DRAINABLE: migrateVault cannot build a sweep for it (both
	// buildMigrationTransaction abort conditions fire for a 600-sat single-input residual),
	// so gen-0 never even reaches DRAINING — it stays wedged RETIRING.
	migrateRes := callKeyAction(t, &ct, contractId, owner, "migrateVault", []byte(""))
	require.NotEmpty(t, migrateRes.Err, "migrateVault must fail to sweep the un-sweepable dust residual")
	vaultsAfterFailedMigrate, _, _ := loadVaults(t, &ct, contractId)
	require.Equal(t, mapping.VaultStatusRetiring, vaultsAfterFailedMigrate[0].Status,
		"a failed build never flips gen-0 to draining")
	regStillDust, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, regStillDust, 1, "the un-swept dust UTXO is untouched by the failed build")

	// VR2-15: the write-off is charged to the operator's fee reserve, so it is REFUSED while
	// the reserve is empty — a liveness stall, cleared by a top-up, never a solvency break.
	supplyBefore := loadSupply(t, &ct, contractId)
	require.Equal(t, dustAmount, supplyBefore.ActiveSupply)
	require.Equal(t, dustAmount, supplyBefore.UserSupply)
	require.Equal(t, int64(0), supplyBefore.FeeSupply)
	starvedRes := callKeyAction(t, &ct, contractId, owner, "writeOffDust", []byte(""))
	require.Empty(t, starvedRes.Err, starvedRes.ErrMsg)
	require.Contains(t, starvedRes.Ret, "nothing to write off",
		"a reserve-short write-off skips the generation rather than charging user principal")
	regStarved, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, regStarved, 1, "a refused write-off writes no state — the dust UTXO is untouched")

	// Fund the reserve (gen-1 is ACTIVE at this point), then writeOffDust clears the
	// deadlock: the dust UTXO is deleted, the RESERVE is debited, and gen-0 (was Retiring)
	// flips to Draining so the existing reconciler can carry it onward.
	seedReserve(t, &ct, contractId, 1, 2048, dustAmount)

	writeOffRes := callKeyAction(t, &ct, contractId, owner, "writeOffDust", []byte(""))
	require.Empty(t, writeOffRes.Err, writeOffRes.ErrMsg)
	require.Contains(t, writeOffRes.Ret, "gen=0")

	regAfterWriteOff, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, regAfterWriteOff, 1, "the dust UTXO is deleted; the reserve UTXO remains")
	supplyAfter := loadSupply(t, &ct, contractId)
	require.Equal(t, int64(0), supplyAfter.FeeSupply, "the RESERVE absorbed the written-off dust")
	require.Equal(t, dustAmount, supplyAfter.ActiveSupply, "user principal is NOT debited by a write-off")
	require.Equal(t, dustAmount, supplyAfter.UserSupply, "user principal is NOT debited by a write-off")
	// I3 stays EXACT: the victim's credit still equals UserSupply, so no later withdrawal
	// can underflow UserSupply and revert for an unrelated user.
	require.Equal(t, encodeBalance(t, dustAmount), ct.StateGet(contractId, constants.BalancePrefix+"hive:legacy-victim"),
		"the dust depositor keeps the credit the protocol still owes them")
	require.Equal(t, sumRegistry(t, &ct, contractId), supplyAfter.ActiveSupply+supplyAfter.FeeSupply,
		"I1 holds exact after the write-off")
	vaultsAfterWriteOff, _, _ := loadVaults(t, &ct, contractId)
	require.Equal(t, mapping.VaultStatusDraining, vaultsAfterWriteOff[0].Status,
		"writeOffDust flips a Retiring gen carrying only dust to Draining")

	// NN#3 releases: the next rotation now succeeds (gen-2 minted PENDING).
	createRes := callKeyAction(t, &ct, contractId, owner, "createKey", []byte(""))
	require.Empty(t, createRes.Err, createRes.ErrMsg)
	vaultsAfterSecondRotate, _, _ := loadVaults(t, &ct, contractId)
	require.Len(t, vaultsAfterSecondRotate, 3, "gen-0 (draining) + gen-1 (active) + gen-2 (pending)")
	require.Equal(t, mapping.VaultStatusPending, vaultsAfterSecondRotate[2].Status)

	// ★ The SAME attack repeated against gen-0's now-Draining (still-matchable) address is
	// defeated AT THE DOOR: a superseded generation exists (gen-0, Draining) so the floor
	// is live — the deposit is silently skipped, never credited, never registered.
	repeatInstr := "deposit_to=hive:attacker-repeat"
	repeatBlockHeight := uint32(101)
	repeatFixture := buildMapFixture(t, repeatInstr, dustAmount, repeatBlockHeight)
	ct.StateSet(contractId, constants.BlockPrefix+strconv.FormatUint(uint64(repeatBlockHeight), 10), decodeHex(t, repeatFixture.BlockHeaderHex))
	// VR2-07: advance the tip past this second deposit too, so the maturity gate is
	// satisfied and the assertion below tests the DUST floor rather than depth.
	ct.StateSet(contractId, constants.LastHeightKey, strconv.FormatUint(uint64(repeatBlockHeight)+2, 10))
	repeatParams := mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight: repeatBlockHeight, RawTxHex: repeatFixture.RawTxHex,
			MerkleProofHex: repeatFixture.MerkleProofHex, TxIndex: repeatFixture.TxIndex,
		},
		Instructions: []string{repeatInstr},
	}
	repeatPayload, err := tinyjson.Marshal(repeatParams)
	require.NoError(t, err)
	repeatRes := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "map-repeat-attack", BlockId: "block:map2", Index: 71, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{"hive:attacker-repeat"}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "map", Payload: repeatPayload,
		RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: "hive:attacker-repeat",
	})
	require.True(t, repeatRes.Success, "a skipped dust deposit is not a tx abort: "+repeatRes.ErrMsg)
	require.Empty(t, ct.StateGet(contractId, constants.BalancePrefix+"hive:attacker-repeat"),
		"the repeat dust attack must NOT be credited — the floor is now live")
	regFinal, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, regFinal, 1, "the repeat dust attack must not register a UTXO (only the reserve UTXO remains)")
	require.Equal(t, uint16(2048), regFinal[0].Id, "the sole survivor is the fee-reserve UTXO, not the attacker's dust")
}

// (b) VR2-15 — legacy-dust write-off conservation, the regression test for the solvency
// break. A sub-dust UTXO is injected directly onto a DRAINING gen (simulating a pre-floor
// legacy deposit that WAS already credited: Active/User supply and a depositor's balance
// are bumped by D exactly as a real map call would).
//
// The write-off used to debit ActiveSupply+UserSupply by D. That held I1 and I2 but broke
// I3 (Σ(balances)==UserSupply) by exactly D forever, because the depositor's own balance was
// never debited — the Utxo blob carries no recipient. That slack is not cosmetic: HandleUnmap
// decrements UserSupply with safeSubtract64 on every withdrawal, so once the aggregate ran
// short of the balances it stood for, the LAST withdrawers underflowed and their withdrawals
// reverted permanently. The victims were whichever users withdrew last, not the depositor.
//
// The write-off is now charged to the operator's FEE RESERVE instead, so this test asserts:
// the write-off is REFUSED while the reserve is short (a liveness stall a permissionless
// top-up clears, never a solvency break); once funded it debits FeeSupply by EXACTLY D and
// leaves ActiveSupply, UserSupply and the depositor's balance untouched; and I1, I2 and I3
// all hold EXACT afterwards rather than I3 acquiring slack.
func TestWriteOffDust_LegacyResidualConservation(t *testing.T) {
	ct, contractId, owner := newRetireCT(t)
	const h = 900000
	const D = int64(300) // sub-dust residual: unsweepable even at the fixed minimum fee rate
	const legacyDepositor = "hive:legacy-depositor"

	// writeOffDust loads a FULL ContractState (unlike retireVault), so the flat legacy keys
	// must exist even though we bypass the fold/ceremony (loadPublicKeys errors otherwise).
	// Zero-value vault keys (uninvolved in this pure state-machine + Supply-math test) are
	// harmless — no signing or address derivation happens on the write-off/build-failure path.
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{ActiveSupply: D, UserSupply: D, BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.BalancePrefix+legacyDepositor, encodeBalance(t, D))
	seedRetireState(ct, contractId, h, mapping.VaultRegistry{
		{Generation: 1, Status: mapping.VaultStatusDraining, Predecessor: 0, RetiredHeight: h - 1000},
		{Generation: 2, Status: mapping.VaultStatusActive, Predecessor: 1},
	}, 3, 2)
	seedGenUtxos(t, ct, contractId, 1, []utxoSeed{{id: 1024, amount: D}})

	// The residual can never be swept (both buildMigrationTransaction abort conditions fire
	// for a 300-sat single-input tranche) — migrateVault fails, gen-1 stays Draining.
	migrateRes := callKeyAction(t, ct, contractId, owner, "migrateVault", []byte(""))
	require.NotEmpty(t, migrateRes.Err, "migrateVault must fail to sweep the un-sweepable legacy residual")

	// NN#3: createKey is refused while gen-1 (Draining) still holds the residual.
	require.NotEmpty(t, callKeyAction(t, ct, contractId, owner, "createKey", []byte("")).Err,
		"createKey must be refused while gen-1 holds the un-drained legacy residual (NN#3)")

	// RED-BEFORE: with an empty reserve the write-off must REFUSE this generation outright.
	// The old code charged ActiveSupply+UserSupply here and "succeeded" — that success was
	// the bug.
	require.Equal(t, int64(0), loadSupply(t, ct, contractId).FeeSupply, "reserve starts empty")
	starved := callKeyAction(t, ct, contractId, owner, "writeOffDust", []byte(""))
	require.Empty(t, starved.Err, starved.ErrMsg)
	require.Contains(t, starved.Ret, "nothing to write off",
		"a reserve-short write-off must skip the generation, not charge user principal")
	regStarved, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, regStarved, 1, "the refused write-off wrote no state")
	supplyStarved := loadSupply(t, ct, contractId)
	require.Equal(t, D, supplyStarved.ActiveSupply, "refused write-off leaves ActiveSupply alone")
	require.Equal(t, D, supplyStarved.UserSupply, "refused write-off leaves UserSupply alone")

	// Fund the reserve on the ACTIVE generation (gen-2), exactly as topUpFeeReserve would.
	seedReserve(t, ct, contractId, 2, 2048, D)
	require.Equal(t, D, loadSupply(t, ct, contractId).FeeSupply)

	// GREEN-AFTER: delete the residual, debit the RESERVE by exactly D.
	writeOffRes := callKeyAction(t, ct, contractId, owner, "writeOffDust", []byte(""))
	require.Empty(t, writeOffRes.Err, writeOffRes.ErrMsg)
	require.Contains(t, writeOffRes.Ret, "gen=1")

	regAfter, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, regAfter, 1, "the legacy residual UTXO is deleted; the reserve UTXO remains")

	supply := loadSupply(t, ct, contractId)
	require.Equal(t, int64(0), supply.FeeSupply, "FeeSupply debited by exactly D — the reserve absorbed the write-off")
	require.Equal(t, D, supply.ActiveSupply, "ActiveSupply is NOT touched: a write-off is not a user debit")
	require.Equal(t, D, supply.UserSupply, "UserSupply is NOT touched: a write-off is not a user debit")

	// I1: Σ(UTXO) == ActiveSupply + FeeSupply  → D == D + 0.
	require.Equal(t, sumRegistry(t, ct, contractId), supply.ActiveSupply+supply.FeeSupply, "I1 holds exact post write-off")
	// I2: ActiveSupply == UserSupply  → D == D.
	require.Equal(t, supply.ActiveSupply, supply.UserSupply, "I2 holds exact post write-off")
	// I3: Σ(balances) == UserSupply, EXACT — no slack. This is the whole point: the depositor
	// keeps the credit the protocol still owes them, and UserSupply still stands for exactly
	// the balances that exist, so no later withdrawal underflows it and reverts.
	depositorBal := ct.StateGet(contractId, constants.BalancePrefix+legacyDepositor)
	require.Equal(t, encodeBalance(t, D), depositorBal, "the legacy depositor keeps their credit")
	require.Equal(t, D, supply.UserSupply, "I3 holds EXACT: Σ(balances) == UserSupply, no phantom-credit slack")

	// gen-1 stays Draining (it started Draining, not Retiring — write-off only flips a
	// Retiring gen; Draining/Inactive are already mid-flow for the existing reconciler).
	vaultsAfter, _, _ := loadVaults(t, ct, contractId)
	require.Equal(t, mapping.VaultStatusDraining, vaultByGen(t, vaultsAfter, 1).Status)

	// The existing (UNCHANGED) reconciler now carries the emptied gen forward:
	// DRAINING → INACTIVE (registry-empty).
	retireRes := callKeyAction(t, ct, contractId, owner, "retireVault", []byte(""))
	require.Empty(t, retireRes.Err, retireRes.ErrMsg)
	vaultsAfterRetire, _, _ := loadVaults(t, ct, contractId)
	require.Equal(t, mapping.VaultStatusInactive, vaultByGen(t, vaultsAfterRetire, 1).Status,
		"the emptied gen transitions Draining->Inactive via the unchanged reconciler")

	// NN#3 released: createKey now succeeds (mainv3 pre-seeded since MintNextGeneration will
	// mint generation 3 — nextGen was seeded at 3 — and TssCreateKey traps in-test on an
	// unseeded keyId).
	seedTssKey(t, ct, contractId, "mainv3", Gen1PrimaryHex)
	finalCreateRes := callKeyAction(t, ct, contractId, owner, "createKey", []byte(""))
	require.Empty(t, finalCreateRes.Err, finalCreateRes.ErrMsg)
}

// (c) INERT pre-rotation: with no superseded generation ever having existed, a sub-floor
// (< MinDepositSats) deposit is credited exactly as it always was — proving the min-deposit
// floor engages ONLY once rotation is live (hasSupersededGen), so this slice ships
// byte-identical map behaviour for every pre-rotation deploy.
func TestMapDustFloor_InertPreRotation(t *testing.T) {
	const subFloorAmount = int64(600) // < MinDepositSats(1000)
	const blockHeight = uint32(100)
	const instruction = "deposit_to=hive:dust-user" // Hive usernames are capped at 16 chars
	fixture := buildMapFixture(t, instruction, subFloorAmount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	// VR2-07: seed the tip above the deposit block so the maturity gate is met.
	ct.StateSet(contractId, constants.LastHeightKey, strconv.FormatUint(uint64(blockHeight)+2, 10))
	ct.StateSet(contractId, constants.BlockPrefix+strconv.FormatUint(uint64(blockHeight), 10), decodeHex(t, fixture.BlockHeaderHex))
	seedActiveGen0(t, &ct, contractId, owner) // gen-0 ACTIVE only — no rotation has ever happened

	params := mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight: blockHeight, RawTxHex: fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex, TxIndex: fixture.TxIndex,
		},
		Instructions: []string{instruction},
	}
	payload, err := tinyjson.Marshal(params)
	require.NoError(t, err)
	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "map-subfloor-pre-rotation", BlockId: "block:map", Index: 70, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "map", Payload: payload,
		RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: owner,
	})
	require.True(t, r.Success, r.ErrMsg)

	require.Equal(t, encodeBalance(t, subFloorAmount), ct.StateGet(contractId, constants.BalancePrefix+"hive:dust-user"),
		"a sub-floor deposit is credited pre-rotation (floor inert — hasSupersededGen is false)")
	reg, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, reg, 1, "the sub-floor deposit IS registered pre-rotation")
	require.Equal(t, subFloorAmount, reg[0].Amount)
	supply := loadSupply(t, &ct, contractId)
	require.Equal(t, subFloorAmount, supply.ActiveSupply)
	require.Equal(t, subFloorAmount, supply.UserSupply)
}

// (d) writeOffDust refuses to touch an in-flight input — BOTH exclusion forms, Guard-1
// reservation ("ru-") and BRK-1 pending-migration ("ms-") — even when a genuinely-eligible
// dust residual sits in the SAME generation: only the eligible one is written off; the two
// in-flight UTXOs are left registered (and Supply is debited by exactly the eligible one's
// amount), so neither pending spend can ever fail settle with "input missing from registry".
func TestWriteOffDust_SkipsInFlightInputs(t *testing.T) {
	ct, contractId, owner := newRetireCT(t)
	const h = 900000
	const reservedAmt = int64(300)   // in-flight unmap (Guard-1 "ru-" reservation)
	const inFlightAmt = int64(300)   // in-flight migration sweep ("ms-" record)
	const eligibleAmt = int64(300)   // genuinely un-owned dust — MUST be written off

	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: reservedAmt + inFlightAmt + eligibleAmt,
		UserSupply:   reservedAmt + inFlightAmt + eligibleAmt,
		BaseFeeRate:  1,
	})))
	seedRetireState(ct, contractId, h, mapping.VaultRegistry{
		{Generation: 1, Status: mapping.VaultStatusDraining, Predecessor: 0, RetiredHeight: h - 1000},
		{Generation: 2, Status: mapping.VaultStatusActive, Predecessor: 1},
	}, 3, 2)
	seedGenUtxos(t, ct, contractId, 1, []utxoSeed{
		{id: 1024, amount: reservedAmt},
		{id: 1025, amount: inFlightAmt},
		{id: 1026, amount: eligibleAmt},
	})

	// id 1024: reserved by an in-flight unmap (Guard-1).
	ct.StateSet(contractId, constants.ReservedUtxoPrefix+strconv.FormatUint(1024, 10), "1")

	// id 1025: committed to an in-flight migration sweep (BRK-1 "ms-" record).
	sweepTxId := strings.Repeat("cd", 32) // 64 hex chars = 32 raw bytes, round-trips through the packed registry
	ct.StateSet(contractId, constants.MigrationSweepRegistryKey,
		string(mapping.MarshalTxSpendsRegistry(mapping.TxSpendsRegistry{sweepTxId})))
	sweepRecord := &mapping.MigrationSweep{
		InputIds: []uint16{1025}, BtcFee: 10, SuccessorAddress: "irrelevant-for-this-test", SuccessorGen: 2,
	}
	ct.StateSet(contractId, constants.MigrationSweepPrefix+sweepTxId, string(mapping.MarshalMigrationSweep(sweepRecord)))

	// The write-off is charged to the reserve (VR2-15), so fund it on the ACTIVE gen (gen-2).
	// It must be funded by eligibleAmt PLUS the in-flight sweep's own reserved fee: the
	// write-off may only spend the reserve SURPLUS over what pending sweeps have claimed,
	// or an already-broadcast sweep could not settle. sweepRecord below reserves BtcFee 10.
	const pendingSweepFee = int64(10)
	seedReserve(t, ct, contractId, 2, 2048, eligibleAmt+pendingSweepFee)

	writeOffRes := callKeyAction(t, ct, contractId, owner, "writeOffDust", []byte(""))
	require.Empty(t, writeOffRes.Err, writeOffRes.ErrMsg)
	require.Contains(t, writeOffRes.Ret, "gen=1")
	require.Contains(t, writeOffRes.Ret, "sats="+strconv.FormatInt(eligibleAmt, 10),
		"only the eligible (non-in-flight) residual's amount is written off")

	reg, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, reg, 3, "the two in-flight UTXOs and the reserve UTXO survive; only the eligible one is deleted")
	survivingIds := map[uint16]bool{}
	for _, e := range reg {
		survivingIds[e.Id] = true
	}
	require.True(t, survivingIds[1024], "the reserved (in-flight unmap) UTXO must survive")
	require.True(t, survivingIds[1025], "the in-flight migration sweep's input must survive")
	require.True(t, survivingIds[2048], "the reserve UTXO is untouched by a write-off")
	require.False(t, survivingIds[1026], "the eligible dust UTXO must be deleted")

	supply := loadSupply(t, ct, contractId)
	require.Equal(t, pendingSweepFee, supply.FeeSupply,
		"the RESERVE is debited by EXACTLY the eligible residual, leaving the in-flight sweep's "+
			"reserved fee intact so its deferred confirm-side debit still cannot underflow")
	require.Equal(t, reservedAmt+inFlightAmt+eligibleAmt, supply.ActiveSupply,
		"user principal is untouched by a write-off")
	require.Equal(t, reservedAmt+inFlightAmt+eligibleAmt, supply.UserSupply)
	require.Equal(t, sumRegistry(t, ct, contractId), supply.ActiveSupply+supply.FeeSupply, "I1 holds exact")

	// gen-1 is STILL funded (the two surviving in-flight UTXOs) — NN#3 correctly stays
	// blocked; a second write-off call cannot free them either (idempotent no-op on them).
	require.NotEmpty(t, callKeyAction(t, ct, contractId, owner, "createKey", []byte("")).Err,
		"createKey must stay refused: gen-1 still holds the two in-flight (excluded) UTXOs")
}


// (e) VR2-15 x BRK-1: a write-off may only spend the reserve SURPLUS over the fees that
// in-flight migration sweeps have already claimed.
//
// Migration defers each sweep's FeeSupply debit to its confirm, and keeps that debit safe by
// maintaining FeeSupply >= Σ(pending sweep fees) at every build — which is what makes the
// confirm-side debit "GUARANTEED to succeed (never a post-L1 brick)". A write-off that spent
// the reserve down to zero without respecting that sum would leave an ALREADY-BROADCAST
// sweep unable to settle: the exact "permanent registry <-> L1 divergence + a wedged sweep
// that re-aborts forever" the deferred debit exists to avoid.
//
// Here the reserve covers the residual EXACTLY but not the pending sweep's fee on top, so
// the write-off must decline. The positive control is (d) above, which funds residual + fee
// and proceeds — so this is not simply "write-off never runs".
func TestWriteOffDust_LeavesPendingSweepFeesIntact(t *testing.T) {
	ct, contractId, owner := newRetireCT(t)
	const h = 900000
	const inFlightAmt = int64(300)     // input committed to an in-flight sweep
	const eligibleAmt = int64(300)     // genuinely un-owned dust
	const pendingSweepFee = int64(10)  // the fee that sweep already reserved

	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: inFlightAmt + eligibleAmt,
		UserSupply:   inFlightAmt + eligibleAmt,
		BaseFeeRate:  1,
	})))
	seedRetireState(ct, contractId, h, mapping.VaultRegistry{
		{Generation: 1, Status: mapping.VaultStatusDraining, Predecessor: 0, RetiredHeight: h - 1000},
		{Generation: 2, Status: mapping.VaultStatusActive, Predecessor: 1},
	}, 3, 2)
	seedGenUtxos(t, ct, contractId, 1, []utxoSeed{
		{id: 1025, amount: inFlightAmt},
		{id: 1026, amount: eligibleAmt},
	})

	sweepTxId := strings.Repeat("cd", 32)
	ct.StateSet(contractId, constants.MigrationSweepRegistryKey,
		string(mapping.MarshalTxSpendsRegistry(mapping.TxSpendsRegistry{sweepTxId})))
	ct.StateSet(contractId, constants.MigrationSweepPrefix+sweepTxId,
		string(mapping.MarshalMigrationSweep(&mapping.MigrationSweep{
			InputIds: []uint16{1025}, BtcFee: pendingSweepFee,
			SuccessorAddress: "irrelevant-for-this-test", SuccessorGen: 2,
		})))

	// Reserve covers the residual EXACTLY, with nothing left for the pending sweep's fee.
	seedReserve(t, ct, contractId, 2, 2048, eligibleAmt)

	res := callKeyAction(t, ct, contractId, owner, "writeOffDust", []byte(""))
	require.Empty(t, res.Err, res.ErrMsg)
	require.Contains(t, res.Ret, "nothing to write off",
		"the write-off must decline rather than spend a pending sweep's reserved fee")

	reg, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, reg, 3, "a declined write-off writes no state: both gen-1 UTXOs and the reserve UTXO remain")

	supply := loadSupply(t, ct, contractId)
	require.Equal(t, eligibleAmt, supply.FeeSupply,
		"the reserve is untouched, so the in-flight sweep's deferred fee debit still cannot underflow")
	require.Equal(t, inFlightAmt+eligibleAmt, supply.ActiveSupply, "user principal untouched")
	require.Equal(t, inFlightAmt+eligibleAmt, supply.UserSupply)
	require.Equal(t, sumRegistry(t, ct, contractId), supply.ActiveSupply+supply.FeeSupply, "I1 holds exact")
}
