package current_test

import (
	"strconv"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// VR2-06: a settle must wait the same depth as a credit.
//
// confirmSpend deletes the spent inputs from the registry and promotes the
// transaction's outputs. If that transaction is then reorged out, the contract
// believes coins moved that did not: the inputs are gone from its books while the
// coins still sit at the old address, so the generation reads as EMPTY while
// holding funds. Nothing in-band reconciles that — the spend record was cleared,
// so redrive cannot rebuild it, and the vault can never be drained.
//
// Crediting a deposit and settling a spend are the same question about the same
// chain, so they take the same answer. Both now go through
// requireConfirmationDepth.
func TestVR206_ImmatureSettleIsRefusedThenSucceedsOnceItMatures(t *testing.T) {
	ct, contractId, fixture := setupConfirmSpendContract(t)

	setTip := func(h uint32) {
		ct.StateSet(contractId, constants.LastHeightKey, strconv.FormatUint(uint64(h), 10))
	}
	params := mapping.ConfirmSpendParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    fixture.BlockHeight,
			RawTxHex:       fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex,
			TxIndex:        fixture.TxIndex,
		},
		Indices: []uint32{0},
	}
	confirm := func() bool {
		return callConfirmSpend(t, ct, contractId, "hive:milo-hpr", params).Success
	}

	// At the tip: zero confirmations, exactly the window a reorg can take back.
	setTip(fixture.BlockHeight)
	require.False(t, confirm(), "a settle at the tip must be refused")

	// One short — boundaries are where gates are usually wrong.
	setTip(fixture.BlockHeight + 1)
	require.False(t, confirm(), "one confirmation short must still refuse")

	// The spend record must SURVIVE both refusals. If a refused settle cleared it,
	// the withdrawal would be unrecoverable: nothing left to confirm and nothing
	// left to redrive.
	require.NotEmpty(t, ct.StateGet(contractId, constants.TxSpendsRegistryKey),
		"a refused settle must leave the pending spend intact, not consume it")

	// Matured: the same proof, unchanged, now settles.
	setTip(fixture.BlockHeight + 2)
	assert.True(t, confirm(), "the same proof must settle once the spend has matured")
}

// The settle wait has to stay strictly inside the redrive staleness window.
//
// A settle waiting on depth keeps its spend record live. If the redrive window
// opened first, an operator watching a "stale" spend could RBF a transaction that
// Bitcoin has ALREADY mined — producing a replacement that can never confirm,
// because its inputs are spent, while adding a member to the spend group and
// burning a signature. Ordering the two windows removes that interaction entirely
// rather than guarding against it, which is why this is asserted as an invariant
// rather than left as a comment.
func TestVR206_ConfirmationDepthStaysInsideTheRedriveWindow(t *testing.T) {
	for _, network := range []string{
		constants.Mainnet, constants.Testnet3, constants.Testnet4, constants.Regtest,
	} {
		depth := constants.MinConfirmationDepth(network)
		if depth == 0 {
			t.Errorf("%s: a zero depth leaves the gate inert — testnet cannot then "+
				"prove what mainnet enforces", network)
		}
		if depth >= constants.RedriveStaleBlocks {
			t.Errorf("%s: confirmation depth %d must stay below RedriveStaleBlocks %d, "+
				"or an operator can redrive a transaction that is already mined",
				network, depth, constants.RedriveStaleBlocks)
		}
	}
}
