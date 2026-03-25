package main

import (
	"btc-mapping-contract/contract/mapping"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/chaincfg"
)

func main() {
	primaryPubKey := "037252c3e934177fdcc14e3b3dbf295378fce11305ca513e9f2651dc2839e3be1a"
	backupPubKey := "0242f9da15eae56fe6aca65136738905c0afdb2c4edf379e107b3b00b98c7fc9f0"

	recipient := "hive:tibfox"
	if len(os.Args) > 1 {
		recipient = os.Args[1]
	}

	instruction := "deposit_to=" + recipient
	fmt.Println("Instruction:", instruction)

	address, _, err := mapping.DepositAddress(primaryPubKey, backupPubKey, instruction, &chaincfg.TestNet3Params)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	fmt.Println("Deposit address:", address)
}
