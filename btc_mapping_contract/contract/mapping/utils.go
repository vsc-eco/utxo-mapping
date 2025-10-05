package mapping

import (
	"contract-template/sdk"
	"crypto/sha256"
	"encoding/hex"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// func getInternalAddressForBitcoinAddress(btcAddress string) (string, bool) {
// 	for internalAddr, blockchainAccount := range mc.accountRegistry {
// 		if blockchainAccount.address == btcAddress {
// 			return internalAddr, true
// 		}
// 	}

// 	return "", false
// }

func verifyProof() bool {
	return true
}

func createInstructionMap(instructions *[]string) *[]Instruction {
	instructionMap := make(map[string]string)
	for _, instruction := range *instructions {
		hasher := sha256.New()
		hasher.Write([]byte(instruction))
		hashBytes := hasher.Sum(nil)
		tag := hex.EncodeToString(hashBytes)
		instructionObjects = append(instructionObjects, Instruction{rawInstruction: instruction, address: hex.EncodeToString(hashBytes)})
	}
	return &instructionObjects
}

func isForVscAcc(txOut *wire.TxOut, addresses map[string]bool) bool {
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, &chaincfg.TestNet3Params)
	if err != nil {
		sdk.Abort(err.Error())
	}
	for _, addr := range addrs {
		if addresses[addr.EncodeAddress()] {
			return true
		}
	}
	return false
}

func indexOutputs(msgTx *wire.MsgTx) {
	outputsForVsc := []wire.TxOut{}

	for _, txOut := range msgTx.TxOut {
		if isForVscAcc(txOut, tmpAddrs) {
			outputsForVsc = append(outputsForVsc, *txOut)
		}
	}
}
