package current_test

import (
	"strings"
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

// VR2-03 (diagnosability half): proving a transaction against a height whose header
// is not in state must say SO, naming the height.
//
// This started as a reported nil-dereference. It is not one. The host returns
// `result.Ok("")` for a missing key (execution-context.go:401-409) and the sdk binding
// hands that string back (wasm/sdk/sdk.go:117-127), so `sdk.StateGetObject` never
// yields nil for a missing key. A pruned header produces an EMPTY string, `BtcDecode`
// fails on EOF, and the caller gets a clean `bad_input`. The comment at
// theft_gate.go:76-78 claiming verifyTransaction "dereferences a nil header" is wrong
// about the mechanism; its pre-check is harmless but is not preventing a trap.
//
// What IS wrong is the message. Headers are pruned at 4608 blocks
// (`PruneOldHeaders`), so a sweep mined on Bitcoin but not confirmed to the contract
// within ~32 days loses its proving header, and confirmSpend can then never settle it
// — the generation stays "funded", the next rotation is blocked and the bond stays
// locked. That is the moment an operator most needs to know WHY, and what they got was
// "error decoding block header: EOF": it names neither the missing header nor the
// height, and reads like a malformed-proof error rather than a pruned-state one.
//
// This test is therefore about diagnosability, not memory safety, and it is scoped
// that way deliberately. The substantive half of VR2-03 — not pruning a header a
// pending spend still needs — is a separate change.
func TestVR203_MissingBlockHeaderIsNamedInTheError(t *testing.T) {
	const contractId = "vr203_hdr"
	const owner = "hive:milo-hpr"
	const recipient = "hive:milo-receiver"
	const instruction = "to=" + recipient
	const seededHeight = uint32(100)
	// The proof will claim a height the contract has no header for.
	const unprovableHeight = uint32(101)

	fixture := buildMapFixture(t, instruction, 500_000, seededHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	ct.RegisterContract(contractId, owner, ContractWasm)

	ct.StateSet(contractId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "101")
	// Height 100's header IS seeded; height 101's is deliberately absent — exactly the
	// shape a pruned header leaves behind.
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	callMap := func(txId string, height uint32) test_utils.ContractTestCallResult {
		params := mapping.MapParams{
			TxData: &mapping.VerificationRequest{
				BlockHeight:    height,
				RawTxHex:       fixture.RawTxHex,
				MerkleProofHex: fixture.MerkleProofHex,
				TxIndex:        fixture.TxIndex,
			},
			Instructions: []string{instruction},
		}
		payload, err := tinyjson.Marshal(params)
		require.NoError(t, err)
		return ct.Call(stateEngine.TxVscCallContract{
			Self: stateEngine.TxSelf{
				TxId: txId, BlockId: "block:vr203", Index: 0, OpIndex: 0,
				Timestamp: "2026-09-07T00:00:00", RequiredAuths: []string{owner},
				RequiredPostingAuths: []string{},
			},
			ContractId: contractId, Action: "map", Payload: payload,
			RcLimit: 10000, Intents: []contracts.Intent{}, Caller: owner,
		})
	}

	// POSITIVE CONTROL — the same call against the seeded height must SUCCEED, so a
	// failure below is attributable to the missing header and nothing else.
	ok := callMap("vr2-03-control", seededHeight)
	require.True(t, ok.Success,
		"positive control: mapping against the SEEDED height must succeed; err=%q msg=%q", ok.Err, ok.ErrMsg)

	// THE CASE — proving against a height with no header.
	r := callMap("vr2-03-missing", unprovableHeight)
	require.False(t, r.Success, "mapping against a height with no header must fail")

	// It must fail with a message that NAMES the problem. Matching the text is the
	// whole point: a trap also produces "not success", so an assertion on failure
	// alone would pass just as well before the fix as after it.
	combined := r.Err + " " + r.ErrMsg
	assert.True(t, strings.Contains(combined, "block header"),
		"the failure must name the missing header; got err=%q msg=%q", r.Err, r.ErrMsg)
	assert.True(t, strings.Contains(combined, "101"),
		"the failure must name the height it could not prove against; got err=%q msg=%q", r.Err, r.ErrMsg)
}
