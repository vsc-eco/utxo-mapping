package current_test

// Swaps through the REAL DEX router and BTC/HBD pool (dex-contracts bin/dex-router-v2.wasm and
// bin/dex.wasm) against this vault, across a rotation:
//   SWAP-S1  a swap-tagged deposit swaps to HBD; the vault keeps nothing on its own account and
//            the router's allowance ends at zero.
//   SWAP-S3  while gen-0 is RETIRING, a swap paid to gen-1's address swaps and the UTXO joins gen-1.
//   SWAP-T2  a LATE swap paid to the retiring gen-0's address swaps and the UTXO joins gen-0
//            (credited to the gen that owns the address, so migration sweeps it).
//   SWAP-T6  an unmeetable min_amount_out refunds the recipient in wrapped BTC; no HBD, nothing
//            left on the vault's own account, allowance back to zero.
//   SWAP-P6  a DEX withdrawal of BTC (HBD -> BTC, destination BTC) during the rotation spends
//            ACTIVE-gen inputs only (D-1); gen-0's UTXOs stay for the sweep.
// The DEX wasm is not in this repo. Build dex-contracts (`make` there) and point DEX_CONTRACTS_BIN
// at its bin directory; without it the test skips:
//
//	DEX_CONTRACTS_BIN=/path/to/dex-contracts/bin go test ./tests/current/ -run TestSwapMigrationThroughRealDex -v

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	pendulumoracle "vsc-node/modules/incentive-pendulum/oracle"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/require"
)

const (
	swapMigMapping = "vsc1BpQYDaMwcfdsh9T7DSEHZvdma1XaSXMPPj"
	swapMigPool    = "vsc1BquGPy8B766YpstdcL5cSF2GkWVVsVxJS3"
	swapMigRouter  = "vsc1Bpc3SgDqCRQxzeDrvV7T4XKV6BZuHmME5F"
	swapMigOwner   = "hive:milo-hpr"
)

func swapMigReadWasm(t *testing.T, name string) []byte {
	t.Helper()
	dir := os.Getenv("DEX_CONTRACTS_BIN")
	if dir == "" {
		t.Skip("skipping: set DEX_CONTRACTS_BIN to a built dex-contracts bin directory (dex.wasm, dex-router-v2.wasm)")
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil || len(b) == 0 {
		t.Skipf("skipping: DEX wasm %s not available in %s", name, dir)
	}
	return b
}

func swapMigCall(t *testing.T, ct *test_utils.ContractTest, contractId, caller, action string, payload []byte, intents []contracts.Intent, rc uint) test_utils.ContractTestCallResult {
	t.Helper()
	if intents == nil {
		intents = []contracts.Intent{}
	}
	return ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: "swapmig-" + action + "-" + strconv.FormatInt(time.Now().UnixNano(), 36), BlockId: "block:swapmig",
			Index: 1, OpIndex: 0, Timestamp: "2025-10-14T00:00:00",
			RequiredAuths: []string{caller}, RequiredPostingAuths: []string{},
		},
		ContractId: contractId, Action: action, Payload: payload, RcLimit: rc, Intents: intents, Caller: caller,
	})
}

func swapMigJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// newSwapMigCT deploys the vault (this repo's dev.wasm), the real router and BTC/HBD pool, seeds the
// pool with liquidity and points the vault at the router. Returns the harness with gen-0 active.
func newSwapMigCT(t *testing.T) *test_utils.ContractTest {
	t.Helper()
	dexWasm := swapMigReadWasm(t, "dex.wasm")
	routerWasm := swapMigReadWasm(t, "dex-router-v2.wasm")

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	ct.SetPendulumGeometry(pendulumoracle.GeometryOutputs{OK: true, V: 500_000, P: 250_000, E: 1_000_000, T: 1_000_000, SBps: 5000},
		[]string{swapMigPool})

	ct.RegisterContract(swapMigMapping, swapMigOwner, ContractWasm)
	ct.RegisterContract(swapMigPool, swapMigOwner, dexWasm)
	ct.RegisterContract(swapMigRouter, swapMigOwner, routerWasm)

	ok := func(r test_utils.ContractTestCallResult, what string) {
		require.True(t, r.Success, "%s: %s %s", what, r.Err, r.ErrMsg)
	}
	ok(swapMigCall(t, &ct, swapMigRouter, swapMigOwner, "register_token",
		swapMigJSON(t, map[string]any{"name": "BTC", "chain": "BTC", "mapping_contract": swapMigMapping}), nil, 2000), "register BTC")
	ok(swapMigCall(t, &ct, swapMigRouter, swapMigOwner, "register_token",
		swapMigJSON(t, map[string]any{"name": "HBD", "chain": "HIVE"}), nil, 2000), "register HBD")
	ok(swapMigCall(t, &ct, swapMigRouter, swapMigOwner, "register_pool",
		swapMigJSON(t, map[string]any{"asset0": "btc", "asset1": "hbd", "dex_contract_id": swapMigPool}), nil, 2000), "register pool")
	ok(swapMigCall(t, &ct, swapMigPool, swapMigOwner, "init",
		swapMigJSON(t, map[string]any{"asset0": "btc", "asset1": "hbd", "fee_bps": 100,
			"asset0_mapping_contract": swapMigMapping, "router_contract": swapMigRouter}), nil, 2000), "init pool")

	// Liquidity: 1.49 BTC of the owner's mapped balance and 100,000.000 HBD.
	const lpBTC, lpHBD = int64(1_49000000), int64(100000_000)
	ct.StateSet(swapMigMapping, constants.BalancePrefix+swapMigOwner, encodeBalance(t, 2_00000000))
	ct.StateSet(swapMigMapping, constants.AllowancePrefix+swapMigOwner+constants.DirPathDelimiter+"contract:"+swapMigPool,
		encodeBalance(t, 2_00000000))
	ct.Deposit(swapMigOwner, lpHBD+1_000_000, "hbd")
	ok(swapMigCall(t, &ct, swapMigPool, swapMigOwner, "add_liquidity",
		swapMigJSON(t, map[string]any{"amount0": strconv.FormatInt(lpBTC, 10), "amount1": strconv.FormatInt(lpHBD, 10), "recipient": swapMigOwner}),
		[]contracts.Intent{
			{Type: "transfer.allow", Args: map[string]string{"limit": strconv.FormatInt(lpBTC, 10), "token": "btc", "contract_id": swapMigMapping}},
			{Type: "transfer.allow", Args: map[string]string{"limit": strconv.FormatInt(lpHBD, 10), "token": "hbd", "contract_id": ""}},
		}, 2000), "add liquidity")

	ct.StateSet(swapMigMapping, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1, FeeSupply: 100000})))
	seedActiveGen0(t, &ct, swapMigMapping, swapMigOwner) // gen-0 ACTIVE with keystore keys main/mainv1/mainv2
	ct.StateSet(swapMigMapping, constants.RouterContractIdKey, swapMigRouter)
	ct.StateSet(swapMigMapping, constants.LastHeightKey, "102")
	return &ct
}

// swapMigMap pays `amount` to primaryHex's deposit address for `instruction` in its own block at
// `height` (header seeded, last height = height+2) and maps it as the depositor.
func swapMigMap(t *testing.T, ct *test_utils.ContractTest, primaryHex, instruction string, amount int64, height uint32) test_utils.ContractTestCallResult {
	t.Helper()
	address, _, err := mapping.DepositAddress(primaryHex, TestBackupPubKeyHex, instruction, regtestParams())
	require.NoError(t, err)
	tx := buildTestTx(t, address, amount)
	header := buildRegtestHeader(chainhash.Hash{}, tx.TxHash(), time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	ct.StateSet(swapMigMapping, constants.BlockPrefix+strconv.FormatUint(uint64(height), 10), decodeHex(t, serializeHeader(t, header)))
	ct.StateSet(swapMigMapping, constants.LastHeightKey, strconv.FormatUint(uint64(height)+2, 10))
	var buf bytes.Buffer
	require.NoError(t, tx.Serialize(&buf))
	payload, err := tinyjson.Marshal(mapping.MapParams{
		TxData:       &mapping.VerificationRequest{BlockHeight: height, RawTxHex: serializeTx(t, tx), MerkleProofHex: "", TxIndex: 0},
		Instructions: []string{instruction},
	})
	require.NoError(t, err)
	r := swapMigCall(t, ct, swapMigMapping, "hive:swapmig-depositor", "map", payload, nil, 1_000_000)
	dumpLogs(t, r.Logs)
	return r
}

func swapMigBal(t *testing.T, ct *test_utils.ContractTest, acct string) int64 {
	t.Helper()
	return decodeBalance(t, ct.StateGet(swapMigMapping, constants.BalancePrefix+acct))
}

func swapMigHBD(ct *test_utils.ContractTest, acct string) int64 {
	return ct.LedgerSession.GetBalance(acct, 1, "hbd")
}

func swapMigNoResidue(t *testing.T, ct *test_utils.ContractTest, label string) {
	t.Helper()
	require.Equal(t, int64(0), swapMigBal(t, ct, "contract:"+swapMigMapping), "%s: the vault must keep nothing on its own account", label)
	require.Equal(t, "", ct.StateGet(swapMigMapping, constants.AllowancePrefix+"contract:"+swapMigMapping+constants.DirPathDelimiter+"contract:"+swapMigRouter),
		"%s: the router's allowance must end at zero", label)
}

// newUtxoIds returns the registry ids present in `after` but not in `before`.
func newUtxoIds(before, after map[uint16]int64) []uint16 {
	out := []uint16{}
	for id := range after {
		if _, had := before[id]; !had {
			out = append(out, id)
		}
	}
	return out
}

func TestSwapMigrationThroughRealDex(t *testing.T) {
	ct := newSwapMigCT(t)

	// SWAP-S1: one active gen, a swap-tagged deposit swaps to HBD.
	const recipS1 = "hive:swapmig-s1"
	before := registryIds(t, ct, swapMigMapping)
	r := swapMigMap(t, ct, TestPrimaryPubKeyHex, "swap_to="+recipS1+"&swap_asset_out=hbd", 1_000_000, 100)
	require.True(t, r.Success, "SWAP-S1 map: %s %s", r.Err, r.ErrMsg)
	require.Greater(t, swapMigHBD(ct, recipS1), int64(0), "SWAP-S1: the recipient must receive HBD")
	require.Equal(t, int64(0), swapMigBal(t, ct, recipS1), "SWAP-S1: no wrapped BTC left with the recipient")
	swapMigNoResidue(t, ct, "SWAP-S1")
	ids := newUtxoIds(before, registryIds(t, ct, swapMigMapping))
	require.Len(t, ids, 1)
	require.Equal(t, uint32(0), utxoGenerationForId(t, ct, swapMigMapping, ids[0]), "SWAP-S1: the UTXO joins gen-0")

	// Rotate: mint gen-1, register its key, activate it. gen-0 (funded) becomes RETIRING.
	require.Empty(t, callKeyAction(t, ct, swapMigMapping, swapMigOwner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, ct, swapMigMapping, swapMigOwner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	require.Empty(t, callKeyAction(t, ct, swapMigMapping, swapMigOwner, "activateKey", []byte("")).Err)
	vaults, _, active := loadVaults(t, ct, swapMigMapping)
	require.Equal(t, uint32(1), active, "gen-1 is active")
	require.Equal(t, mapping.VaultStatusRetiring, vaults[0].Status, "gen-0 is retiring")

	// SWAP-S3: a swap paid to gen-1's address while gen-0 is retiring.
	const recipS3 = "hive:swapmig-s3"
	before = registryIds(t, ct, swapMigMapping)
	r = swapMigMap(t, ct, Gen1PrimaryHex, "swap_to="+recipS3+"&swap_asset_out=hbd", 5_000_000, 110)
	require.True(t, r.Success, "SWAP-S3 map: %s %s", r.Err, r.ErrMsg)
	require.Greater(t, swapMigHBD(ct, recipS3), int64(0), "SWAP-S3: the recipient must receive HBD")
	swapMigNoResidue(t, ct, "SWAP-S3")
	ids = newUtxoIds(before, registryIds(t, ct, swapMigMapping))
	require.Len(t, ids, 1)
	require.Equal(t, uint32(1), utxoGenerationForId(t, ct, swapMigMapping, ids[0]), "SWAP-S3: the UTXO joins gen-1")

	// SWAP-T2: a LATE swap paid to the retiring gen-0's address.
	const recipT2 = "hive:swapmig-t2"
	before = registryIds(t, ct, swapMigMapping)
	r = swapMigMap(t, ct, TestPrimaryPubKeyHex, "swap_to="+recipT2+"&swap_asset_out=hbd", 700_000, 120)
	require.True(t, r.Success, "SWAP-T2 map: %s %s", r.Err, r.ErrMsg)
	require.Greater(t, swapMigHBD(ct, recipT2), int64(0), "SWAP-T2: the recipient must receive HBD")
	swapMigNoResidue(t, ct, "SWAP-T2")
	ids = newUtxoIds(before, registryIds(t, ct, swapMigMapping))
	require.Len(t, ids, 1)
	require.Equal(t, uint32(0), utxoGenerationForId(t, ct, swapMigMapping, ids[0]), "SWAP-T2: the UTXO joins the gen that owns the address (gen-0), so migration sweeps it")

	// SWAP-T6: an unmeetable min_amount_out refunds the recipient in wrapped BTC.
	const recipT6 = "hive:swapmig-t6"
	r = swapMigMap(t, ct, Gen1PrimaryHex, "swap_to="+recipT6+"&swap_asset_out=hbd&min_amount_out=99999999999999", 800_000, 130)
	require.True(t, r.Success, "SWAP-T6 map must succeed (refund, not revert): %s %s", r.Err, r.ErrMsg)
	require.Equal(t, int64(0), swapMigHBD(ct, recipT6), "SWAP-T6: no HBD when the bound is not met")
	require.Equal(t, int64(800_000), swapMigBal(t, ct, recipT6), "SWAP-T6: the recipient is refunded the full amount in wrapped BTC")
	swapMigNoResidue(t, ct, "SWAP-T6")

	// SWAP-P6: a DEX withdrawal of BTC during the rotation must spend ACTIVE-gen inputs only.
	const withdrawer = "hive:swapmig-w13"
	ct.Deposit(withdrawer, 200_000+1_000_000, "hbd")
	gens := map[uint16]uint32{}
	before = registryIds(t, ct, swapMigMapping)
	for id := range before {
		gens[id] = utxoGenerationForId(t, ct, swapMigMapping, id)
	}
	r = swapMigCall(t, ct, swapMigRouter, withdrawer, "execute",
		swapMigJSON(t, map[string]any{"type": "swap", "version": "1.0.0", "asset_in": "hbd", "asset_out": "btc",
			"amount_in": "200000", "recipient": regtestDestAddress(t), "destination_chain": "BTC"}),
		[]contracts.Intent{{Type: "transfer.allow", Args: map[string]string{"token": "hbd", "limit": "200000"}}}, 100_000)
	dumpLogs(t, r.Logs)
	require.True(t, r.Success, "SWAP-P6 HBD->BTC withdrawal: %s %s", r.Err, r.ErrMsg)
	// The spend reserves its inputs (ReservedUtxoPrefix, "ru-<id>"); they stay in the registry
	// until the spend settles.
	reserved := []uint16{}
	for id := range before {
		if ct.StateGet(swapMigMapping, constants.ReservedUtxoPrefix+strconv.FormatUint(uint64(id), 10)) != "" {
			reserved = append(reserved, id)
		}
	}
	require.NotEmpty(t, reserved, "SWAP-P6: the withdrawal must reserve inputs for its spend")
	for _, id := range reserved {
		require.Equal(t, uint32(1), gens[id], "SWAP-P6: input %d is from gen-%d; a withdrawal during the rotation must use ACTIVE gen-1 only (D-1)", id, gens[id])
	}
	for id, g := range gens {
		if g == 0 {
			require.Equal(t, "", ct.StateGet(swapMigMapping, constants.ReservedUtxoPrefix+strconv.FormatUint(uint64(id), 10)),
				"SWAP-P6: retiring gen-0's UTXO %d must stay free for the migration sweep", id)
		}
	}
	t.Logf("SWAP-P6: reserved inputs %v (all gen-1); gen-0 UTXOs untouched", reserved)
}
