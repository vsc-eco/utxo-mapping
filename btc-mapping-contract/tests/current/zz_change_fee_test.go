package current_test

import (
	"bytes"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
	"vsc-node/lib/test_utils"
)

// changeFeeWithdraw withdraws `amount` from one 10M-sat active coin at 10 sat/vB and returns
// the miner fee (input - outputs) and the number of outputs.
func changeFeeWithdraw(t *testing.T, amount int64) (int64, int) {
	t.Helper()
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	cid, owner := "mapping_contract", "hive:milo-hpr"
	ct.RegisterContract(cid, owner, ContractWasm)
	ct.StateSet(cid, constants.LastHeightKey, "102")
	seedActiveGen0(t, &ct, cid, owner)
	seedGenUtxos(t, &ct, cid, 0, []utxoSeed{{1100, 10_000_000}})
	ct.StateSet(cid, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{
		ActiveSupply: 10_000_000, UserSupply: 10_000_000, BaseFeeRate: 10,
	})))
	ct.StateSet(cid, constants.BalancePrefix+owner, encodeBalance(t, 10_000_000))
	r := wqUnmap(t, &ct, cid, owner, amount)
	require.True(t, r.Success, r.ErrMsg)
	p := wqPending(t, &ct, cid)
	require.Len(t, p, 1)
	var tx wire.MsgTx
	require.NoError(t, tx.Deserialize(bytes.NewReader(signingTx(t, &ct, cid, p[0]))))
	var out int64
	for _, o := range tx.TxOut {
		out += o.Value
	}
	return 10_000_000 - out, len(tx.TxOut)
}

// CHANGE-FEE-1: k change outputs cost k * 43 vbytes, not 43 * k(k+1)/2. Same input, same
// destination script; one withdrawal leaves four change outputs, the other one. The miner
// fee differs by exactly three outputs at the rate (3 * 43 * 10 = 1,290 sats); the old
// pricing charged 9 * 43 * 10 = 3,870.
func TestChangeFee_EachChangeOutputPricedOnce(t *testing.T) {
	feeFour, outsFour := changeFeeWithdraw(t, 5_000_000)
	feeOne, outsOne := changeFeeWithdraw(t, 9_400_000)
	require.Equal(t, 1+4, outsFour, "destination + four change outputs")
	require.Equal(t, 1+1, outsOne, "destination + one change output")
	require.Equal(t, int64(3*43*10), feeFour-feeOne, "three extra change outputs, each priced once")
}
