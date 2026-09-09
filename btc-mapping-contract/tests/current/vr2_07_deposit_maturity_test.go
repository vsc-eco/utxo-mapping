package current_test

import (
	"strconv"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// VR2-07: a deposit must be buried MinDepositConfirmations deep before it is
// credited, and refusing it is a clean "not yet" the depositor can retry.
//
// Before this, a deposit was creditable the instant its header landed — which is
// only the oracle's own relay threshold, 2 confirmations on mainnet. A 2-block
// Bitcoin reorg is routine, and the contract can follow a reorg at most 2 blocks
// deep (HandleReplaceBlocks is hard-capped at 2 on mainnet), so a deposit orphaned
// by one kept its L2 credit while the backing coins ceased to exist: user supply
// inflated against a vault that never received them, with no in-band way to
// reconcile.
//
// Refusing BEFORE indexing is what makes this implementable. Balance is a single
// fungible integer, so "credit but hold the top N sats" would need a parallel
// pending-credit ledger; and un-crediting later is worse still, because the
// depositor may already have moved the phantom credit and the subtraction guards
// only integer wrap, not a negative result — the exact class that halted the fleet
// once already. Nothing is indexed, nothing is credited, and the same
// permissionless proof works unchanged once the deposit matures.
func TestVR207_ImmatureDepositIsRefusedThenCreditedOnceItMatures(t *testing.T) {
	const contractId = "vr207_maturity"
	const owner = "hive:milo-hpr"
	const recipient = "hive:milo-receiver"
	const instruction = "deposit_to=" + recipient
	const depositHeight = uint32(100)
	const amount int64 = 500_000

	fixture := buildMapFixture(t, instruction, amount, depositHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	ct.RegisterContract(contractId, owner, ContractWasm)

	ct.StateSet(contractId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	params := mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    depositHeight,
			RawTxHex:       fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex,
			TxIndex:        fixture.TxIndex,
		},
		Instructions: []string{instruction},
	}
	payload, err := tinyjson.Marshal(params)
	require.NoError(t, err)

	doMap := func(txId string) test_utils.ContractTestCallResult {
		return ct.Call(stateEngine.TxVscCallContract{
			Self: stateEngine.TxSelf{
				TxId: txId, BlockId: "block:vr207", Index: 0, OpIndex: 0,
				Timestamp: "2026-09-07T00:00:00", RequiredAuths: []string{owner},
				RequiredPostingAuths: []string{},
			},
			ContractId: contractId, Action: "map", Payload: payload,
			RcLimit: 10000, Intents: []contracts.Intent{}, Caller: owner,
		})
	}
	setTip := func(h uint32) {
		ct.StateSet(contractId, constants.LastHeightKey, strconv.FormatUint(uint64(h), 10))
	}
	balance := func() int64 {
		return decodeBalance(t, ct.StateGet(contractId, constants.BalancePrefix+recipient))
	}

	// At the tip: zero confirmations. This is precisely the window a reorg can take
	// back, and it is what the contract used to credit.
	setTip(depositHeight)
	r := doMap("vr2-07-at-tip")
	require.False(t, r.Success, "a deposit at the tip must not be credited")
	assert.Contains(t, r.ErrMsg, "not confirmed deeply enough",
		"the refusal must say why, so a depositor knows to retry rather than assume failure")

	// One short. Boundaries are where gates are usually wrong, so both sides are
	// pinned rather than just the easy case.
	setTip(depositHeight + 1)
	require.False(t, doMap("vr2-07-one-short").Success, "one confirmation short must still refuse")

	// Nothing was recorded by either refusal: no balance, no UTXO registry entry,
	// and no observed-tx entry. That last one matters — an observed entry would
	// make the retry below a silent no-op, turning "not yet" into "never".
	require.Zero(t, balance(), "an immature deposit must not be credited")
	require.Empty(t, ct.StateGet(contractId, constants.UtxoRegistryKey),
		"an immature deposit must not enter the UTXO registry")
	require.Empty(t, ct.StateGet(contractId, constants.ObservedBlockPrefix+"100"),
		"an immature deposit must not be marked observed, or the retry would be swallowed")

	// Matured. The SAME proof, unchanged, now credits.
	setTip(depositHeight + 2)
	ok := doMap("vr2-07-matured")
	require.True(t, ok.Success, "the same proof must succeed once matured; err=%q msg=%q", ok.Err, ok.ErrMsg)
	assert.Equal(t, amount, balance(), "the matured deposit credits in full, exactly once")

	// And a replay after maturing is still a no-op, so the retry path did not open
	// a double-credit.
	require.True(t, doMap("vr2-07-replay").Success, "a replay is a no-op, not an abort")
	assert.Equal(t, amount, balance(), "replaying the matured proof must not credit twice")
}

// The gate must be a per-transaction property of the deposit's depth, not
// something an attacker can sidestep by splitting one deposit across several
// outputs. This is why the required depth is FLAT rather than scaled by value:
// indexOutputs makes one UTXO per output with no aggregation, so a value-scaled
// threshold would be defeated by splitting, while a flat floor applies to every
// output of every transaction alike.
func TestVR207_MaturityAppliesToEveryOutputOfATransaction(t *testing.T) {
	const contractId = "vr207_multi"
	const owner = "hive:milo-hpr"
	const recipient = "hive:milo-receiver"
	const instruction = "deposit_to=" + recipient
	const depositHeight = uint32(100)

	// A deliberately small deposit: under a value-scaled rule this is exactly the
	// piece an attacker would split down to in order to slip under the threshold.
	fixture := buildMapFixture(t, instruction, 1_500, depositHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	ct.RegisterContract(contractId, owner, ContractWasm)

	ct.StateSet(contractId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	payload, err := tinyjson.Marshal(mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    depositHeight,
			RawTxHex:       fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex,
			TxIndex:        fixture.TxIndex,
		},
		Instructions: []string{instruction},
	})
	require.NoError(t, err)

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: "vr2-07-small", BlockId: "block:vr207m", Index: 0, OpIndex: 0,
			Timestamp: "2026-09-07T00:00:00", RequiredAuths: []string{owner},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId, Action: "map", Payload: payload,
		RcLimit: 10000, Intents: []contracts.Intent{}, Caller: owner,
	})
	assert.False(t, r.Success,
		"a small deposit is refused at zero depth exactly like a large one — the "+
			"floor is flat precisely so splitting cannot buy an exemption")
}
