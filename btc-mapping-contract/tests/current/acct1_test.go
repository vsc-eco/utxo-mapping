package current_test

// ACCT-1: a deduct_fee unmap must debit the user exactly what leaves the vault
// (sendAmount + true miner fee, vscFee is 0 today), so Σ(UTXO) stays equal to
// Active+Fee. Before the fix it debited `amount`: with a change output the vault
// kept an uncounted surplus, and with sub-dust change (burned to the miner) the
// vault lost more than the user was charged. Both shapes run through the real wasm.

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"
)

// logField returns the value of key k in the first contract log line with prefix.
func logField(r test_utils.ContractTestCallResult, prefix, k string) (int64, bool) {
	for _, out := range r.Logs {
		for _, l := range out.Logs {
			if !strings.HasPrefix(l, prefix+constants.LogDelimiter) {
				continue
			}
			for _, kv := range strings.Split(l, constants.LogDelimiter) {
				if v, ok := strings.CutPrefix(kv, k+constants.LogKeyDelimiter); ok {
					n, err := strconv.ParseInt(v, 10, 64)
					return n, err == nil
				}
			}
		}
	}
	return 0, false
}

func TestAcct1_DeductFeeUnmapDebitsWhatLeavesTheVault(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const fakeTxId0 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const user = "hive:milo-hpr"
	cases := []struct {
		name      string
		utxo      int64
		amount    int64
		burnsDust bool
	}{
		{"change output", 100_000, 50_000, false},
		{"sub-dust change burned", 50_300, 50_000, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct := test_utils.NewContractTest()
			t.Cleanup(func() { ct.DataLayer.Stop() })
			contractId := "mapping_contract"
			ct.RegisterContract(contractId, user, ContractWasm)
			activateTssKey(&ct, contractId)

			balance := tc.utxo // the user owns the whole vault
			ct.StateSet(contractId, constants.BalancePrefix+user, encodeBalance(t, balance))
			ct.StateSet(contractId, constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(mapping.UtxoRegistry{
				{Id: 1024, Amount: tc.utxo},
			})))
			ct.StateSet(contractId, constants.UtxoPrefix+"400", depositUtxoBinary(t, fakeTxId0, 0, tc.utxo, instruction))
			ct.StateSet(contractId, constants.UtxoLastIdKey, encodeUtxoCounters(1025, 0))
			ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
				ActiveSupply: balance, UserSupply: balance, BaseFeeRate: 2,
			})))
			ct.StateSet(contractId, constants.LastHeightKey, "102")
			ct.StateSet(contractId, constants.BlockPrefix+"100", buildSeedHeaderRaw(t, time.Unix(0, 0)))
			ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
			ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

			payload, _ := tinyjson.Marshal(mapping.TransferParams{
				Amount:    fmt.Sprintf("%d", tc.amount),
				To:        regtestDestAddress(t),
				DeductFee: true,
			})
			r := ct.Call(stateEngine.TxVscCallContract{
				Self:       *basicSelf(t, user),
				ContractId: contractId,
				Action:     "unmap",
				Payload:    payload,
				RcLimit:    10000,
				Intents:    []contracts.Intent{},
			})
			dumpLogs(t, r.Logs)
			require.True(t, r.Success, "unmap failed: %s: %s", r.Err, r.ErrMsg)

			sent, ok1 := logField(r, "unmap", "s")
			debited, ok2 := logField(r, "unmap", "d")
			btcFee, ok3 := logField(r, "fee", "b")
			require.True(t, ok1 && ok2 && ok3, "unmap and fee logs must be present")
			after := decodeBalance(t, ct.StateGet(contractId, constants.BalancePrefix+user))
			supply, err := mapping.UnmarshalSupply([]byte(ct.StateGet(contractId, constants.SupplyKey)))
			require.NoError(t, err)
			t.Logf("amount %d: sent %d, true btc fee %d, debited %d (balance %d -> %d), active %d",
				tc.amount, sent, btcFee, debited, balance, after, supply.ActiveSupply)

			assert.Equal(t, sent+btcFee, debited, "the debit is exactly what leaves the vault")
			assert.Equal(t, balance-debited, after, "the balance drops by the debit")
			assert.Equal(t, balance-debited, supply.ActiveSupply, "active supply drops by the debit")
			assert.Equal(t, balance-debited, supply.UserSupply, "user supply drops by the debit")
			if tc.burnsDust {
				assert.Equal(t, tc.utxo, sent+btcFee, "no change output: the whole input leaves the vault")
				assert.Greater(t, debited, tc.amount, "the burned remainder is charged, not absorbed by the vault")
			} else {
				assert.Less(t, debited, tc.amount, "the unused fee estimate stays with the user")
			}
		})
	}
}
