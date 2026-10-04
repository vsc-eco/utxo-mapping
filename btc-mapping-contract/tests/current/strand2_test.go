package current_test

// STRAND-2: a deposit to a swap address whose swap cannot even be attempted (no
// asset out in its instruction, or no router registered yet) used to revert the
// whole `map`, so the SPV-verified BTC was never credited and every retry failed
// the same way. It must now be credited to the depositor as a plain deposit, like
// a swap the router refuses. Needs the regtest dev.wasm (`make test` builds it).

import (
	"strings"
	"testing"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"
)

func TestStrand2_UnattemptableSwapIsCreditedAsDeposit(t *testing.T) {
	const blockHeight = uint32(100)
	const amount = int64(10000)
	const depositor = "hive:milo-hpr"

	cases := []struct {
		name        string
		instruction string
		router      bool
		reason      string
	}{
		{"no asset out", "swap_to=hive:milo-hpr", true, "asset out required to execute a swap"},
		{"no router registered", "swap_to=hive:milo-hpr&swap_asset_out=hbd", false, "router contract not initialized"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := buildMapFixture(t, tc.instruction, amount, blockHeight)
			ct := test_utils.NewContractTest()
			t.Cleanup(func() { ct.DataLayer.Stop() })

			contractId := "mapping_contract"
			ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
			ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
			ct.StateSet(contractId, constants.LastHeightKey, "102")
			ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
			ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
			ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
			if tc.router {
				ct.StateSet(contractId, constants.RouterContractIdKey, "router_contract")
			}

			payload, err := tinyjson.Marshal(mapping.MapParams{
				TxData: &mapping.VerificationRequest{
					BlockHeight:    blockHeight,
					RawTxHex:       fixture.RawTxHex,
					MerkleProofHex: fixture.MerkleProofHex,
					TxIndex:        fixture.TxIndex,
				},
				Instructions: []string{tc.instruction},
			})
			require.NoError(t, err)
			r := ct.Call(stateEngine.TxVscCallContract{
				Self: stateEngine.TxSelf{
					TxId:                 "strand2-" + strings.ReplaceAll(tc.name, " ", "-"),
					BlockId:              "block:map",
					Index:                69,
					OpIndex:              0,
					Timestamp:            "2025-10-14T00:00:00",
					RequiredAuths:        []string{depositor},
					RequiredPostingAuths: []string{},
				},
				ContractId: contractId,
				Action:     "map",
				Payload:    payload,
				RcLimit:    1000000,
				Intents:    []contracts.Intent{},
				Caller:     depositor,
			})
			dumpLogs(t, r.Logs)

			require.True(t, r.Success, "the map must succeed, not revert: %s %s", r.Err, r.ErrMsg)
			assert.Equal(t, encodeBalance(t, amount), ct.StateGet(contractId, constants.BalancePrefix+depositor),
				"the depositor must be credited the full amount")
			assert.Equal(t, "", ct.StateGet(contractId, constants.BalancePrefix+"contract:"+contractId),
				"the contract must not hold the deposit")
			supply, err := mapping.UnmarshalSupply([]byte(ct.StateGet(contractId, constants.SupplyKey)))
			require.NoError(t, err)
			assert.Equal(t, amount, supply.ActiveSupply, "active supply counts the deposit")
			assert.Equal(t, amount, supply.UserSupply, "user supply counts the deposit")
			logged := false
			for _, out := range r.Logs {
				for _, l := range out.Logs {
					if strings.Contains(l, "deposit-swap not attempted ("+tc.reason+")") {
						logged = true
					}
				}
			}
			assert.True(t, logged, "the fallback must be logged with its reason")
		})
	}
}
