package helpers

import (
	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
)

func TestCreateAddress(t *testing.T) {
	// const primary = "03f165fa283f493b927100160982a67517ab001b0d9bb75c84cf288758ce4ef850" // devnet
	const primary = "021d8d732df00fed0ae061496fc22b43644980d3c68ae720f92c66ff83948afab4" // testnet
	const backup = "0242f9da15eae56fe6aca65136738905c0afdb2c4edf379e107b3b00b98c7fc9f0"
	const recipient = "hive:milo-hpr"
	const instruction = constants.DepositToKey + "=" + recipient
	t.Log("instruction:", instruction)
	var network = chaincfg.TestNet4Params

	address, _, err := mapping.DepositAddress(primary, backup, instruction, &network)
	if err != nil {
		t.Fatal("error creating address:", err)
	}
	t.Log("address:", address)
}
