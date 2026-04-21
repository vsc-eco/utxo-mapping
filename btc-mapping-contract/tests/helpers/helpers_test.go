package helpers

import (
	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
)

func TestCreateAddress(t *testing.T) {
	const primaryDevnet = "03f165fa283f493b927100160982a67517ab001b0d9bb75c84cf288758ce4ef850"
	const primaryTestnet = "0306945cec9ab7dec54c40f57c904c055afdacdde6bd34fa050fcbcbdb6d5733a8"
	const backupTestnetDevnet = "0242f9da15eae56fe6aca65136738905c0afdb2c4edf379e107b3b00b98c7fc9f0"
	const primaryMainnet = "027d904166730f0846ee1a5ccb223d96629ad3979696a0a0a21067ba78535ef56a"
	const backupMainnet = "03aa1f2fcdb6a3903db82bbfaa3397417bc866ba607e9c84df63b893133e131314"
	const recipient = "hive:milo-hpr"
	const instruction = constants.DepositToKey + "=" + recipient
	t.Log("instruction:", instruction)

	address, _, err := mapping.DepositAddress(
		primaryTestnet,
		backupTestnetDevnet,
		instruction,
		&chaincfg.TestNet4Params,
	)
	// address, _, err := mapping.DepositAddress(primaryMainnet, backupMainnet, instruction, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal("error creating address:", err)
	}
	t.Log("address:", address)
}
