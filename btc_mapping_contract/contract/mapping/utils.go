package mapping

import (
	"contract-template/contract/utils"
	"contract-template/sdk"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/holiman/uint256"
)

func (mc *MappingContract) getInternalAddressForBitcoinAddress(btcAddress string) (string, bool) {
	for internalAddr, blockchainAccount := range mc.accountRegistry {
		if blockchainAccount.address == btcAddress {
			return internalAddr, true
		}
	}

	return "", false
}

func verifyProof(proof *[]byte) bool {
	return true
}

func createAddress(pubKeyHex string, tagHex string, network *chaincfg.Params) (string, []byte, error) {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "", nil, err
	}

	tagBytes, err := hex.DecodeString(tagHex)
	if err != nil {
		return "", nil, err
	}

	scriptBuilder := txscript.NewScriptBuilder()
	scriptBuilder.AddData(pubKeyBytes)              // Push pubkey
	scriptBuilder.AddOp(txscript.OP_CHECKSIGVERIFY) // OP_CHECKSIGVERIFY
	scriptBuilder.AddData(tagBytes)                 // Push tag/bits

	script, err := scriptBuilder.Script()
	if err != nil {
		return "", nil, err
	}

	witnessProgram := sha256.Sum256(script)
	address, err := btcutil.NewAddressWitnessScriptHash(witnessProgram[:], network)
	if err != nil {
		return "", nil, err
	}

	return address.EncodeAddress(), script, nil
}

func (mc *MappingContract) createInstructionMap() error {
	if mc.instructions.rawInstructions == nil {
		return errors.New("Instructions not populated")
	}
	for _, instruction := range *mc.instructions.rawInstructions {
		hasher := sha256.New()
		hasher.Write([]byte(instruction))
		hashBytes := hasher.Sum(nil)
		tag := hex.EncodeToString(hashBytes)
		address, _, err := utils.CreateAddress(mc.publicKey, tag, mc.instructions.addressType, &chaincfg.TestNet3Params)
		if err != nil {
			return err
		}
		mc.instructions.addresses[address] = true
	}
	return nil
}

func isForVscAcc(txOut *wire.TxOut, addresses map[string]bool) (string, bool) {

	_, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, &chaincfg.TestNet3Params)
	if err != nil {
		sdk.Abort(err.Error())
	}
	for _, addr := range addrs {
		addressString := addr.EncodeAddress()
		if addresses[addressString] {
			return addressString, true
		}
	}
	return "", false
}

func (mc *MappingContract) indexOutputs(msgTx *wire.MsgTx) *[]utxo {
	outputsForVsc := []utxo{}

	for index, txOut := range msgTx.TxOut {
		addr, ok := isForVscAcc(txOut, mc.instructions.addresses)
		if ok {
			utxo := utxo{
				TxID:    msgTx.TxID(),
				Vout:    uint32(index),
				Address: addr,
				Amount:  *uint256.NewInt(uint64(txOut.Value)),
			}
			outputsForVsc = append(outputsForVsc, utxo)
		}
	}

	return &outputsForVsc
}
