package current_test

import (
	"strconv"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/require"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
)

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
