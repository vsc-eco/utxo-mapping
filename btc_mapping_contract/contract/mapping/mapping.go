package mapping

import (
	"contract-template/sdk"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func (cs *ContractState) getInternalAddressForBitcoinAddress(btcAddress string) (string, bool) {
	for internalAddr, blockchainAccount := range cs.accountRegistry {
		if blockchainAccount.address == btcAddress {
			return internalAddr, true
		}
	}

	return "", false
}

func verifyProof(proof *[]byte) bool {
	return true
}

func (cs *ContractState) createInstructionMap() error {
	if cs.instructions.rawInstructions == nil {
		return errors.New("Instructions not populated")
	}
	for _, instruction := range *cs.instructions.rawInstructions {
		hasher := sha256.New()
		hasher.Write([]byte(instruction))
		hashBytes := hasher.Sum(nil)
		tag := hex.EncodeToString(hashBytes)
		address, _, err := createP2WSHAddress(cs.publicKey, tag, &chaincfg.TestNet3Params)
		if err != nil {
			return err
		}
		cs.instructions.addresses[address] = true
	}
	return nil
}

func isForVscAcc(txOut *wire.TxOut, addresses map[string]bool) bool {
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, &chaincfg.TestNet3Params)
	if err != nil {
		sdk.Abort(err.Error())
	}
	// should always being exactly length 1 for P2SH an P2WSH addresses
	for _, addr := range addrs {
		addressString := addr.EncodeAddress()
		if addresses[addressString] {
			return true
		}
	}
	return false
}

func (cs *ContractState) indexOutputs(msgTx *wire.MsgTx) *[]Utxo {
	outputsForVsc := []Utxo{}

	for index, txOut := range msgTx.TxOut {
		if isForVscAcc(txOut, cs.instructions.addresses) {
			utxo := Utxo{
				txId:      msgTx.TxID(),
				vout:      uint32(index),
				amount:    txOut.Value,
				pkScript:  txOut.PkScript,
				confirmed: true,
			}
			outputsForVsc = append(outputsForVsc, utxo)
		}
	}

	return &outputsForVsc
}
