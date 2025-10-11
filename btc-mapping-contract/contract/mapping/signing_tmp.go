package mapping

import (
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/txscript"
)

// hex
const PRIVATEKEY = "a9f4639b99f21599e3cc529567848119c7c6939e00bdb90b7c9c2d5974f3abea"

func signInput(sigHash []byte) ([]byte, error) {
	privateKeyBytes, err := hex.DecodeString(PRIVATEKEY)
	if err != nil {
		return nil, err
	}
	privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)

	signature := ecdsa.Sign(privateKey, sigHash)
	sigBytes := append(signature.Serialize(), byte(txscript.SigHashAll))

	return sigBytes, nil
}
