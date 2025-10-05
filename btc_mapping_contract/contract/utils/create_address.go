package utils

import (
	"contract-template/sdk"
	"crypto/sha256"
	"encoding/hex"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

type AddressType int

const (
	P2SH AddressType = iota
	P2WSH
)

func CreateAddress(pubKeyHex string, tagHex string, addressType AddressType, network *chaincfg.Params) (string, []byte, error) {
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

	var address string
	if addressType == P2SH {
		scriptHash := btcutil.Hash160(script)
		addressScriptHash, err := btcutil.NewAddressScriptHash(scriptHash, network)
		if err != nil {
			sdk.Abort(err.Error())
		}
		address = addressScriptHash.EncodeAddress()
	} else {
		witnessProgram := sha256.Sum256(script)
		addressWitnessScriptHash, err := btcutil.NewAddressWitnessScriptHash(witnessProgram[:], network)
		if err != nil {
			return "", nil, err
		}
		address = addressWitnessScriptHash.EncodeAddress()
	}

	if err != nil {
		return "", nil, err
	}

	return address, script, nil
}
