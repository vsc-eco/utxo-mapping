package current_test

// STRAND-1: a fee top-up paid to a RETIRING generation's address was refused
// (the top-up matched the active generation only), so its BTC sat unindexed on
// L1. It must now be credited to FeeSupply and indexed as that generation's UTXO,
// so the migration sweeps it to the successor (THORChain credits an inbound to a
// retiring vault and migrates it; Chainflip consolidates the previous key's UTXOs).
// The deposit path already matches every fund-holding generation (S1.4); this is
// the same rule for the reserve.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"
)

func TestStrand1_TopUpToRetiringGenIsCreditedAndSwept(t *testing.T) {
	const amount = int64(250000)
	const blockHeight = uint32(100)
	// The fixture pays the untagged address of the gen-0 keys, the generation that
	// becomes RETIRING after the rotation below.
	fx := buildFeeReserveFixture(t, amount, blockHeight)
	ct, contractId, owner := newFeeReserveCT(t, fx, 3)

	require.Empty(t, callKeyAction(t, ct, contractId, owner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, ct, contractId, owner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	require.Empty(t, callKeyAction(t, ct, contractId, owner, "activateKey", []byte("")).Err)
	vaults, _, activeGen := loadVaults(t, ct, contractId)
	require.Equal(t, uint32(1), activeGen, "gen-1 must be active after rotation")
	require.Equal(t, mapping.VaultStatusRetiring, vaultByGen(t, vaults, 0).Status, "gen-0 must be retiring")

	res := callTopUpFeeReserve(t, ct, contractId, "hive:some-random-funder", fx, "tx-topup-retiring")
	require.True(t, res.Success, "a top-up to the retiring generation must be credited, not refused: %s", res.ErrMsg)

	supply := loadSupply(t, ct, contractId)
	require.Equal(t, amount, supply.FeeSupply, "FeeSupply credited by exactly the deposited value")
	require.Equal(t, int64(0), supply.ActiveSupply+supply.UserSupply, "user principal untouched")
	reg, err := mapping.UnmarshalUtxoRegistry([]byte(ct.StateGet(contractId, constants.UtxoRegistryKey)))
	require.NoError(t, err)
	require.Len(t, reg, 1, "the top-up is indexed")
	require.Equal(t, uint32(0), utxoGenerationForId(t, ct, contractId, reg[0].Id),
		"indexed under the RETIRING generation it paid, so the migration sweeps it")
	require.Equal(t, reg[0].Amount, supply.ActiveSupply+supply.FeeSupply, "I1 holds exact")
}
