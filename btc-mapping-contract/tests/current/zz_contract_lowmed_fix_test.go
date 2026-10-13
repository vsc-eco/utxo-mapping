package current_test

// Low/med contract findings: PR32-1, ADDR-1, NI-4, RD-1.
//
// PR32-1: checkOracle's testnet/regtest owner-bypass accepted a posting-only signature
//   (the owner becomes the Caller), unlike checkAdmin which requires active authority. Now
//   checkOracle calls requireOwnerActive too.
// ADDR-1: the destination != change-address guard compared raw strings, but bech32 is
//   case-insensitive (BIP173); an uppercase form of the change address bypassed it and both
//   outputs then carried the same script. Now compared with EqualFold.
// NI-4: a migration tranche of ~85 confirmed inputs makes confirmSpend's non-witness tx hex
//   exceed Hive's 8192-byte custom_json cap, so the tranche could never settle. MaxMigrationInputs
//   lowered to 70 so the settle payload always fits.
// RD-1: the re-drive staleness gate was anchored on the passed txid's BuildHeight, so
//   re-driving the ORIGINAL repeatedly in one window minted a replacement each call. Now
//   anchored on the group's latest member.

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// PR32-1: addBlocks (checkOracle-gated) must refuse a posting-only owner signature on the
// testnet/regtest build, matching the admin/owner gates.
func TestWR_PR321_AddBlocksRequiresActiveAuth(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)

	// checkOracle runs first in addBlocks, before any payload parsing, so the payload is
	// irrelevant to the auth decision.
	posting := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "pr32-posting", BlockId: "b", Index: 0, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{}, RequiredPostingAuths: []string{owner}},
		ContractId: contractId, Action: "addBlocks", Payload: []byte("{}"),
		RcLimit: 100000, Intents: []contracts.Intent{}, Caller: owner,
	})
	require.False(t, posting.Success, "addBlocks with posting-only owner auth must be refused (PR32-1)")
	require.Contains(t, posting.ErrMsg, "active authority",
		"refused by the active-auth gate specifically, not a later block error; got %q", posting.ErrMsg)

	// Control: with ACTIVE auth the call clears checkOracle (it then fails on the empty
	// payload, but NOT with the auth error) - proving the rejection above is auth-specific.
	active := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "pr32-active", BlockId: "b", Index: 0, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "addBlocks", Payload: []byte("{}"),
		RcLimit: 100000, Intents: []contracts.Intent{}, Caller: owner,
	})
	require.NotContains(t, active.ErrMsg, "active authority",
		"active-auth addBlocks must get past checkOracle (any failure is downstream, not auth)")
}

// ADDR-1: an unmap whose destination is the UPPERCASE form of the vault change address must
// be refused - the raw-string guard missed it, letting the user's output collide with change.
func TestWR_ADDR1_UnmapRejectsUppercaseChangeAddress(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const deposit = int64(100_000)
	const blockHeight = uint32(100)
	fixture := buildMapFixture(t, instruction, deposit, blockHeight)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(contractId, owner, ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey,
		string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1, FeeSupply: 100_000})))
	ct.StateSet(contractId, constants.LastHeightKey, "102")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	seedActiveGen0(t, &ct, contractId, owner)
	require.True(t, ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "map-dep", BlockId: "block:map", Index: 70, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "map",
		Payload: func() []byte {
			p, err := tinyjson.Marshal(mapping.MapParams{
				TxData: &mapping.VerificationRequest{BlockHeight: blockHeight, RawTxHex: fixture.RawTxHex,
					MerkleProofHex: fixture.MerkleProofHex, TxIndex: fixture.TxIndex},
				Instructions: []string{instruction}})
			require.NoError(t, err)
			return p
		}(),
		RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: owner}).Success)

	// The vault's untagged change address (gen-0 keys == the Test* pubkeys), uppercased.
	changeAddr, _, err := mapping.AddressWithBackup(TestPrimaryPubKeyHex, TestBackupPubKeyHex, nil, regtestParams())
	require.NoError(t, err)
	upper := strings.ToUpper(changeAddr)
	require.NotEqual(t, changeAddr, upper, "precondition: a bech32 address has a distinct uppercase form")

	up, err := tinyjson.Marshal(mapping.TransferParams{Amount: "40000", To: upper})
	require.NoError(t, err)
	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{TxId: "unmap-upper", BlockId: "block:unmap", Index: 71, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{owner}, RequiredPostingAuths: []string{}},
		ContractId: contractId, Action: "unmap", Payload: up,
		RcLimit: 100000000, Intents: []contracts.Intent{}, Caller: owner})
	require.False(t, r.Success, "unmap to the uppercase form of the change address must be refused (ADDR-1)")
	require.Contains(t, r.ErrMsg, "must differ from the vault change address",
		"refused by Guard 1 case-insensitively; got %q", r.ErrMsg)
}

// NI-4: a MaxMigrationInputs-input sweep's confirmSpend carries the non-witness tx in its
// custom_json; that payload must stay under Hive's 8192-byte cap or the tranche can never
// settle. Regression guard on the cap.
func TestWR_NI4_MigrationCapKeepsConfirmSpendUnderHiveCap(t *testing.T) {
	const hiveCustomJSONCap = 8192

	tx := wire.NewMsgTx(wire.TxVersion)
	for i := 0; i < constants.MaxMigrationInputs; i++ {
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: uint32(i)},
			Sequence:         wire.MaxTxInSequenceNum,
		})
	}
	// One P2WSH successor output (OP_0 <32-byte program> = 34 bytes), no witnesses, so
	// tx.Serialize() yields exactly the non-witness encoding confirmSpend verifies.
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: append([]byte{0x00, 0x20}, make([]byte, 32)...)})
	var buf bytes.Buffer
	require.NoError(t, tx.Serialize(&buf))
	rawHex := hex.EncodeToString(buf.Bytes())

	// confirmSpend's json also carries the Merkle proof, block height, tx index and indices;
	// reserve generously for a worst-case Bitcoin block's proof plus the envelope.
	const proofAndEnvelopeReserve = 1200
	payload := len(rawHex) + proofAndEnvelopeReserve
	require.Lessf(t, payload, hiveCustomJSONCap,
		"a %d-input sweep's confirmSpend payload (%d tx-hex + %d reserve = %d) must stay under Hive's %d cap (NI-4)",
		constants.MaxMigrationInputs, len(rawHex), proofAndEnvelopeReserve, payload, hiveCustomJSONCap)
}

// RD-1: a re-drive within the staleness window of the LATEST replacement must be refused,
// even when the caller passes the ORIGINAL txid (whose own BuildHeight stayed old).
func TestWR_RD1_RedriveRefusedWithinWindowOfLatest(t *testing.T) {
	ct, contractId, owner := newH2CT(t, []utxoSeed{{10, 40_000}}, 100_000)
	orig, _, replBuild := migrateAndRedrive(t, ct, contractId, owner)
	// migrateAndRedrive left the height at the first re-drive's build height, so the latest
	// replacement is this-block-new: a second re-drive of the ORIGINAL must be refused.
	second := callKeyAction(t, ct, contractId, owner, "redriveSpend", []byte(orig))
	require.False(t, second.Success,
		"a second re-drive within the window of the latest replacement must be refused (RD-1)")
	require.Contains(t, second.ErrMsg, "not yet stale enough",
		"refused by the staleness gate anchored on the latest replacement; got %q", second.ErrMsg)

	// Once a full window elapses from the LATEST replacement, a re-drive is allowed again.
	setHeight(ct, contractId, replBuild+constants.RedriveStaleBlocks)
	third := callKeyAction(t, ct, contractId, owner, "redriveSpend", []byte(orig))
	require.Empty(t, third.Err,
		fmt.Sprintf("re-drive allowed once a full window elapses from the latest replacement: %s", third.ErrMsg))
}
