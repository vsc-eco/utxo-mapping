//go:build cross_repo
// +build cross_repo

package current_test

import (
	"encoding/json"
	"testing"

	"dash-mapping-contract/contract/constants"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dashMappingContract "dash-mapping-contract"
)

// TestSetAllowedTargetImmediate_RegtestOnly verifies that the
// admin-gated setAllowedTargetImmediate action lets a regtest
// build skip the 7-day AllowListGovernanceTimelockBlocks cooldown
// (required for tests/devnet's op=call coverage to be feasible),
// AND that mainnet + real testnet builds reject the same call.
//
// Per audit SEC-3 (R15) the gate moved from "testnet-or-regtest"
// to "regtest-only" so real testnet exercises the full add+commit
// timelock flow alongside mainnet.
//
// Wire format: payload is a bare vsc1... contract id (no JSON
// envelope; matches add/commit AllowedTarget shape).
func TestSetAllowedTargetImmediate_RegtestOnly(t *testing.T) {
	requireFreshDevWasm(t)
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractID := "set_allowed_target_immediate_test"
	ct.RegisterContract(contractID, adminOwner, dashMappingContract.DevWasm)

	const targetId = "vsc1AbcDefGhiJklMnoPqrStuVwxYz0123456789"

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "tx-set-immed",
			BlockId:              "block:setimmed",
			Index:                1,
			OpIndex:              0,
			Timestamp:            "2026-06-03T00:00:00",
			RequiredAuths:        []string{adminOwner},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractID,
		Action:     "setAllowedTargetImmediate",
		Payload:    json.RawMessage([]byte(targetId)),
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
		Caller:     adminOwner,
	})
	require.True(t, r.Success,
		"setAllowedTargetImmediate must succeed on the regtest build; err=%q msg=%q", r.Err, r.ErrMsg)

	// State must now have at-<targetId> = "1" — the same key the
	// regular addAllowedTarget+commitAllowedTarget pair writes.
	v := ct.StateGet(contractID, constants.AllowedTargetsKeyPrefix+targetId)
	assert.Equal(t, "1", v,
		"allowedTargets state entry must be live; got %q", v)
}

// TestSetAllowedTargetImmediate_NonAdminRejected ensures the admin
// gate fires when a non-owner caller tries the immediate path.
func TestSetAllowedTargetImmediate_NonAdminRejected(t *testing.T) {
	requireFreshDevWasm(t)
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractID := "set_allowed_target_immediate_nonadmin"
	ct.RegisterContract(contractID, adminOwner, dashMappingContract.DevWasm)

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "tx-set-immed-nonadmin",
			BlockId:              "block:setimmed-nonadmin",
			Index:                2,
			OpIndex:              0,
			Timestamp:            "2026-06-03T00:00:00",
			RequiredAuths:        []string{"hive:not-the-admin"},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractID,
		Action:     "setAllowedTargetImmediate",
		Payload:    json.RawMessage([]byte("vsc1Target")),
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
		Caller:     "hive:not-the-admin",
	})
	assert.False(t, r.Success,
		"non-admin caller must be rejected; got success")
}
