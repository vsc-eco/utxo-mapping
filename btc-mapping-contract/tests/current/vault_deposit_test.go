package current_test

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/require"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
)

// confirmMigrationSweep confirms an internally-built migration sweep tx. It reads the
// sweep's serialized (unsigned) tx from the "d-" signing record, wraps it in a single-tx
// regtest block (MerkleRoot = TxHash, empty proof, TxIndex=0) seeded at blockHeight, and
// calls confirmSpend — the delete-at-confirm settle that BRK-1 defers from build. The
// segwit txid is witness-independent, so the unsigned serialization confirms under the
// same txid the sweep was recorded under. Returns the call result.
func confirmMigrationSweep(
	t *testing.T, ct *test_utils.ContractTest, contractId, caller, sweepTxId string, blockHeight uint32,
) test_utils.ContractTestCallResult {
	t.Helper()
	sigRaw := ct.StateGet(contractId, constants.TxSpendsPrefix+sweepTxId)
	require.NotEmpty(t, sigRaw, "pending signing data must exist for the sweep")
	sd, err := mapping.UnmarshalSigningData([]byte(sigRaw))
	require.NoError(t, err)
	require.NotEmpty(t, sd.Tx, "sweep signing data must carry the serialized tx")

	var sweepTx wire.MsgTx
	require.NoError(t, sweepTx.Deserialize(bytes.NewReader(sd.Tx)))
	require.Equal(t, sweepTxId, sweepTx.TxID(), "deserialized sweep tx id must match the recorded id")

	// Single-tx block: MerkleRoot = TxHash so the empty-proof SPV verification passes.
	txHash := sweepTx.TxHash()
	header := buildRegtestHeader(chainhash.Hash{}, txHash, time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC))
	ct.StateSet(contractId, constants.BlockPrefix+strconv.FormatUint(uint64(blockHeight), 10), serializeHeaderRaw(t, header))
	ct.StateSet(contractId, constants.LastHeightKey, strconv.FormatUint(uint64(blockHeight), 10))

	params := mapping.ConfirmSpendParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight: blockHeight, RawTxHex: hex.EncodeToString(sd.Tx), MerkleProofHex: "", TxIndex: 0,
		},
		Indices: []uint32{0},
	}
	payload, err := tinyjson.Marshal(params)
	require.NoError(t, err)
	return ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "confirm-sweep-" + sweepTxId[:8], BlockId: "block:confirm", Index: 72, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{caller}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "confirmSpend", Payload: payload,
		RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: caller,
	})
}

// utxoGenerationForId loads the stored UTXO blob for a pool id and returns its
// generation tag — the value the spend path uses to pick per-generation keys.
func utxoGenerationForId(t *testing.T, ct *test_utils.ContractTest, contractId string, id uint16) uint32 {
	t.Helper()
	raw := ct.StateGet(contractId, constants.UtxoPrefix+strconv.FormatUint(uint64(id), 16))
	require.NotEmpty(t, raw, "utxo blob must exist for id")
	u, err := mapping.UnmarshalUtxo([]byte(raw))
	require.NoError(t, err)
	return u.Generation
}

// TestMigrateVaultSweepsRetiringGen is the S2 end-to-end proof: after a rotation, a
// migrateVault sweep moves the RETIRING generation's confirmed UTXO to the SUCCESSOR
// (active) vault — the input is spent (deleted), the sweep output is indexed UNCONFIRMED
// and tagged the successor generation (C-B: a sweep pays the successor P2WSH, otherwise
// invisible to the change indexer), the retiring gen transitions to DRAINING, and only
// the miner fee leaves ActiveSupply (internal transfer otherwise Supply-neutral).
func TestMigrateVaultSweepsRetiringGen(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const amount = int64(100000)
	const blockHeight = uint32(100)
	fixture := buildMapFixture(t, instruction, amount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	// FeeSupply reserve seeded so the sweep's miner fee is funded from the reserve (X-2),
	// not user principal.
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1, FeeSupply: 100000})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	seedActiveGen0(t, &ct, contractId, owner)

	// Deposit to gen-0 (active) → one confirmed gen-0 UTXO.
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

	// Rotate: gen-0 → retiring, gen-1 → active.
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "activateKey", []byte("")).Err)

	regBefore, _ := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.Len(t, regBefore, 1, "one confirmed gen-0 deposit UTXO before migration")

	// NN#3 (S2-close): a new rotation is refused while the superseded gen-0 still holds funds.
	require.NotEmpty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err,
		"createKey must be refused while gen-0 holds funds (NN#3)")
	// migrateVault is pause-gated (S2-close F-2): refused while paused, works after unpause.
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "pause", []byte("")).Err)
	require.NotEmpty(t, callKeyAction(t, &ct, contractId, owner, "migrateVault", []byte("")).Err,
		"migrateVault must be refused while paused (F-2)")
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "unpause", []byte("")).Err)

	// Migrate: BUILD+RECORD the sweep of the retiring gen-0 UTXO to the gen-1 successor.
	// BRK-1 (delete-at-confirm): BUILD settles NOTHING — the input is not spent, no output
	// is indexed, and FeeSupply is not debited; all three happen atomically at confirmSpend.
	r := callKeyAction(t, &ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	sweepTxId := r.Ret
	require.NotEmpty(t, sweepTxId)

	// gen-0 → draining (a sweep is in flight), gen-1 still active.
	vaults, _, activeGen := loadVaults(t, &ct, contractId)
	require.Equal(t, uint32(1), activeGen)
	require.Equal(t, mapping.VaultStatusDraining, vaults[0].Status, "retiring gen-0 transitions to draining once a sweep is built")
	require.Equal(t, mapping.VaultStatusActive, vaults[1].Status)

	// BRK-1 at BUILD: the gen-0 input is NOT spent — it stays in the registry (confirmed,
	// gen-0, full deposit value) so AnyFundedSupersededGen keeps NN#3 blocking the next
	// rotation until the sweep confirms. No output is indexed; the "ms-" record and the
	// pending "d-" spend are written; FeeSupply is untouched.
	regBuild, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, regBuild, 1, "the gen-0 input stays in the registry until the sweep confirms (delete-at-confirm)")
	require.GreaterOrEqual(t, regBuild[0].Id, uint16(constants.UtxoConfirmedPoolStart), "the un-swept input is still CONFIRMED")
	require.Equal(t, amount, regBuild[0].Amount, "the input is untouched (full deposit) — nothing indexed at build")
	require.Equal(t, uint32(0), utxoGenerationForId(t, &ct, contractId, regBuild[0].Id), "still the gen-0 input")
	require.NotEmpty(t, ct.StateGet(contractId, constants.MigrationSweepPrefix+sweepTxId), "the sweep record is written at build")
	require.NotEmpty(t, ct.StateGet(contractId, constants.TxSpendsPrefix+sweepTxId), "the sweep is recorded as a pending spend")
	supplyBuild, err := mapping.UnmarshalSupply([]byte(ct.StateGet(contractId, constants.SupplyKey)))
	require.NoError(t, err)
	require.Equal(t, int64(100000), supplyBuild.FeeSupply, "FeeSupply is NOT debited at build (deferred to confirm)")

	// A second migrate BEFORE the sweep confirms selects nothing — the only gen-0 UTXO is
	// committed to the in-flight sweep (excluded), so no double-sweep is built.
	r2 := callKeyAction(t, &ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, r2.Err)
	require.Contains(t, r2.Ret, "nothing to migrate")
	drainingVaults, _, _ := loadVaults(t, &ct, contractId)
	require.Equal(t, mapping.VaultStatusDraining, drainingVaults[0].Status, "gen-0 stays draining while its sweep is pending")

	// Confirm the sweep: the atomic swap runs — the gen-0 input is deleted, the sweep
	// output is indexed CONFIRMED and tagged gen-1, the reserved miner fee is debited, and
	// the "ms-"/"d-" records are cleared.
	cr := confirmMigrationSweep(t, &ct, contractId, owner, sweepTxId, 101)
	require.True(t, cr.Success, cr.ErrMsg)

	regDone, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, regDone, 1, "one UTXO after confirm (the successor output)")
	require.GreaterOrEqual(t, regDone[0].Id, uint16(constants.UtxoConfirmedPoolStart), "the sweep output is CONFIRMED after confirmSpend")
	require.Equal(t, uint32(1), utxoGenerationForId(t, &ct, contractId, regDone[0].Id), "sweep output tagged the successor gen (C-B)")
	require.Less(t, regDone[0].Amount, amount, "sweep output = deposit minus the miner fee")
	require.Greater(t, regDone[0].Amount, int64(0))
	require.Empty(t, ct.StateGet(contractId, constants.MigrationSweepPrefix+sweepTxId), "the sweep record is deleted at confirm")

	// Conservation: FeeSupply dropped by EXACTLY the swept miner fee (input − output).
	supplyDone, err := mapping.UnmarshalSupply([]byte(ct.StateGet(contractId, constants.SupplyKey)))
	require.NoError(t, err)
	require.Equal(t, int64(100000)-(amount-regDone[0].Amount), supplyDone.FeeSupply, "FeeSupply debited by exactly the miner fee at confirm")

	// gen-0 is now truly drained (its input is gone) → the next rotation is unblocked.
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err,
		"the next rotation is allowed once the sweep has CONFIRMED and gen-0 is drained (NN#3)")
}

// TestMigrateVaultEmptyGenStaysRetiring — S2-close F-1 fix: a superseded generation with
// no funds is NOT flipped to Inactive by S2 (that would drop it out of deposit-matching +
// renewal, reopening the C-2/NR-4 late-deposit loss). It stays retiring/draining (still
// fund-holding) until S5's fund-gated + match-until-purged finalization.
func TestMigrateVaultEmptyGenStaysRetiring(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	seedActiveGen0(t, &ct, contractId, owner)

	// Rotate with NO deposits → gen-0 retiring but empty.
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "activateKey", []byte("")).Err)

	r := callKeyAction(t, &ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	require.Contains(t, r.Ret, "nothing to migrate")
	vaults, _, activeGen := loadVaults(t, &ct, contractId)
	require.Equal(t, uint32(1), activeGen)
	require.Equal(t, mapping.VaultStatusRetiring, vaults[0].Status, "empty superseded gen stays retiring (NOT inactive in S2)")
	require.Equal(t, mapping.VaultStatusActive, vaults[1].Status)
}

// TestMigrateVaultRejectsExcessiveFee — S2.4 (V5-4) fee ceiling: a sweep whose miner fee
// exceeds half the tranche value is rejected (fail-safe), so a rogue/glitched oracle
// BaseFeeRate can't burn most of a migration on fees. The gen keeps its UTXOs (atomic).
func TestMigrateVaultRejectsExcessiveFee(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const amount = int64(100000)
	const blockHeight = uint32(100)
	fixture := buildMapFixture(t, instruction, amount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	// High BaseFeeRate → the ~146 vB sweep fee (~73000 sats) exceeds half the deposit.
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 500})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	seedActiveGen0(t, &ct, contractId, owner)

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

	// Excessive fee → migrate REJECTS; gen-0 stays retiring, input UTXO not deleted.
	r := callKeyAction(t, &ct, contractId, owner, "migrateVault", []byte(""))
	require.NotEmpty(t, r.Err, "migrate must reject a sweep whose fee exceeds half the tranche value")
	vaults, _, _ := loadVaults(t, &ct, contractId)
	require.Equal(t, mapping.VaultStatusRetiring, vaults[0].Status, "gen-0 stays retiring after a rejected sweep")
	reg, _ := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.Len(t, reg, 1, "the input UTXO is NOT deleted on a rejected sweep (atomic fail-safe)")
}

// TestMigrateVaultRejectsWithoutFeeReserve — X-2 fix: a sweep whose miner fee cannot be
// funded from FeeSupply is rejected (fail-safe), never eroding user principal. The gen
// keeps its UTXOs and ActiveSupply is untouched (solvency preserved).
func TestMigrateVaultRejectsWithoutFeeReserve(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const amount = int64(100000)
	const blockHeight = uint32(100)
	fixture := buildMapFixture(t, instruction, amount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	// FeeSupply reserve = 0 → the sweep fee cannot be funded.
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	seedActiveGen0(t, &ct, contractId, owner)

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

	r := callKeyAction(t, &ct, contractId, owner, "migrateVault", []byte(""))
	require.NotEmpty(t, r.Err, "migrate must reject when FeeSupply can't fund the sweep fee (X-2)")
	vaults, _, _ := loadVaults(t, &ct, contractId)
	require.Equal(t, mapping.VaultStatusRetiring, vaults[0].Status, "gen-0 stays retiring after a rejected sweep")
	reg, _ := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.Len(t, reg, 1, "input UTXO not deleted (atomic)")
}

// TestDoubleRotationRequiresDrain — S2-close NN#3 end-to-end: a second rotation is refused
// while the first superseded generation still holds funds, and ALLOWED once it's drained.
// Proves the NN#3-gated rotation lifecycle (rotate → drain → rotate) — funded old keys
// cannot pile up.
func TestDoubleRotationRequiresDrain(t *testing.T) {
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

	// Deposit to gen-0, then rotate → gen-0 retiring (funded), gen-1 active.
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

	// Second rotation REFUSED while gen-0 (retiring) still holds the deposit (NN#3).
	require.NotEmpty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err,
		"second rotation must be refused while gen-0 holds funds (NN#3)")

	// Build the gen-0 drain sweep. BRK-1 (delete-at-confirm): migrateVault only DEFERS the
	// input deletion to confirmSpend, so gen-0 still holds its UTXO right after the build →
	// the second rotation STAYS blocked. This is the stronger, safer NN#3: a gen is
	// "drained" only when its sweep CONFIRMS on L1, never merely when it is built.
	dr := callKeyAction(t, &ct, contractId, owner, "migrateVault", []byte(""))
	require.Empty(t, dr.Err)
	sweepTxId := dr.Ret
	require.NotEmpty(t, sweepTxId)
	require.NotEmpty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err,
		"second rotation must STAY refused while gen-0's sweep is only built, not yet confirmed (BRK-1)")

	// Confirm the sweep → gen-0's input is deleted → gen-0 is truly drained.
	require.True(t, confirmMigrationSweep(t, &ct, contractId, owner, sweepTxId, 101).Success)

	// Now the second rotation is ALLOWED (gen-0 drained → gen-2 minted).
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err,
		"second rotation allowed once gen-0's sweep has CONFIRMED (NN#3)")
	vaults, _, activeGen := loadVaults(t, &ct, contractId)
	require.Len(t, vaults, 3, "gen-0 (draining) + gen-1 (active) + gen-2 (pending)")
	require.Equal(t, mapping.VaultStatusDraining, vaults[0].Status)
	require.Equal(t, mapping.VaultStatusActive, vaults[1].Status)
	require.Equal(t, uint32(2), vaults[2].Generation)
	require.Equal(t, mapping.VaultStatusPending, vaults[2].Status)
	require.Equal(t, uint32(1), activeGen)
}

// TestMapCreditsRetiringGenDeposit is the S1.4 end-to-end proof (NR-4 / C-2). After a
// rotation, a deposit that lands on the RETIRING generation's address is still
// credited to the recipient AND its UTXO is tagged with the retiring generation — so
// the eventual sweep builds a gen-0 witness, not a gen-1 one. Without S1.4's
// multi-generation address matching (active-gen-only) the retiring address is absent
// from the registry, the output goes unrecognised, and the depositor's funds vanish
// while the vault still holds the coin — the exact fund-loss C-2 flags. This test is
// its own revert-verify: reverting parseInstructions to active-gen-only leaves the
// balance uncredited and the UTXO registry empty.
func TestMapCreditsRetiringGenDeposit(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const amount = int64(12345)
	const blockHeight = uint32(100)

	// The fixture pays the deposit address derived from the gen-0 keys
	// (TestPrimary/Backup) — i.e. the generation that becomes RETIRING after the
	// rotation below.
	fixture := buildMapFixture(t, instruction, amount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	owner := "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))

	// Mainnet starting point: post-fold gen-0 ACTIVE with the legacy keys + seeded
	// successor TSS keys so the rotation ceremony's createKey/activate don't trap.
	seedActiveGen0(t, &ct, contractId, owner)

	// Rotate: mint gen-1 → register its keys → activate. gen-0 → RETIRING, gen-1 → ACTIVE.
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "activateKey", []byte("")).Err)
	vaults, _, activeGen := loadVaults(t, &ct, contractId)
	require.Equal(t, uint32(1), activeGen, "gen-1 must be active after rotation")
	require.Len(t, vaults, 2)
	require.Equal(t, mapping.VaultStatusRetiring, vaults[0].Status, "gen-0 must be retiring")
	require.Equal(t, mapping.VaultStatusActive, vaults[1].Status, "gen-1 must be active")

	// Deposit onto the RETIRING gen-0 address.
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
			TxId: "map-retiring", BlockId: "block:map", Index: 70, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "map",
		Payload:    payload,
		RcLimit:    100000000,
		Intents:    []contracts.Intent{},
		Caller:     owner,
	})
	require.Empty(t, r.Err, r.ErrMsg)
	require.True(t, r.Success)

	// (1) The depositor IS credited — the C-2 fund-loss is closed.
	require.Equal(t, encodeBalance(t, amount),
		ct.StateGet(contractId, constants.BalancePrefix+"hive:milo-hpr"),
		"a deposit to the RETIRING gen address must credit the recipient (S1.4 NR-4)")

	// (2) The UTXO is tagged with the RETIRING generation (0), not the active gen-1 —
	// so the sweep will build the correct per-generation witness.
	reg, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, reg, 1, "exactly one UTXO indexed")
	require.Equal(t, uint32(0), utxoGenerationForId(t, &ct, contractId, reg[0].Id),
		"the retiring-gen deposit UTXO must be tagged generation 0")
}

// TestUnmapExcludesRetiringGenUtxo — D-1 (S3): after a rotation, an ordinary user
// unmap must NOT select the retiring generation's UTXO. Retiring/draining-gen
// UTXOs leave the vault ONLY via a migration sweep (which the node output-scopes
// to the successor); dragging one into a user unmap would make the retiring key
// sign a user-address output — refused by the node's output-scoped signing gate,
// stranding the already-debited withdrawal. Here gen-0 (retiring) holds the only
// UTXO and gen-1 (active) is empty, so the unmap must be refused with NO debit
// (fail-safe: the user retries once the sweep moves funds to gen-1), never
// selecting the gen-0 UTXO.
func TestUnmapExcludesRetiringGenUtxo(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const amount = int64(100000)
	const blockHeight = uint32(100)
	fixture := buildMapFixture(t, instruction, amount, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	seedActiveGen0(t, &ct, contractId, owner)

	// Deposit to gen-0 while ACTIVE → one confirmed gen-0 UTXO + user balance.
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

	// Rotate: gen-0 → retiring, gen-1 → active (gen-1 holds NO UTXO).
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	require.Empty(t, callKeyAction(t, &ct, contractId, owner, "activateKey", []byte("")).Err)

	// A user unmap that would need the gen-0 (retiring) UTXO must be refused.
	unmapPayload, err := tinyjson.Marshal(mapping.TransferParams{Amount: "50000", To: regtestDestAddress(t)})
	require.NoError(t, err)
	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "unmap-d1", BlockId: "block:unmap", Index: 71, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "unmap", Payload: unmapPayload,
		RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: owner,
	})
	require.False(t, r.Success, "unmap must be refused: only the retiring gen-0 UTXO exists (D-1)")

	// Fail-safe: balance unchanged (no debit) and the gen-0 UTXO is untouched.
	require.Equal(t, encodeBalance(t, amount), ct.StateGet(contractId, constants.BalancePrefix+owner),
		"a refused unmap must not debit the caller")
	reg, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, reg, 1, "the retiring gen-0 UTXO is untouched by the refused unmap")
	require.Equal(t, uint32(0), utxoGenerationForId(t, &ct, contractId, reg[0].Id))
}
