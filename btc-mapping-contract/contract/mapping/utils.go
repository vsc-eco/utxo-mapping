package mapping

import (
	"contract-template/sdk"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

func createP2WSHAddress(pubKeyHex string, tag []byte, network *chaincfg.Params) (string, []byte, error) {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "", nil, err
	}

	scriptBuilder := txscript.NewScriptBuilder()
	scriptBuilder.AddData(pubKeyBytes)              // Push pubkey
	scriptBuilder.AddOp(txscript.OP_CHECKSIGVERIFY) // OP_CHECKSIGVERIFY
	scriptBuilder.AddData(tag)                      // Push tag/bits

	script, err := scriptBuilder.Script()
	if err != nil {
		return "", nil, err
	}

	var address string
	witnessProgram := sha256.Sum256(script)
	addressWitnessScriptHash, err := btcutil.NewAddressWitnessScriptHash(witnessProgram[:], network)
	if err != nil {
		return "", nil, err
	}
	address = addressWitnessScriptHash.EncodeAddress()

	return address, script, nil
}

func checkSender(env sdk.Env, amount int64, balances AccountBalanceMap) error {
	activeAuths := env.Sender.RequiredAuths
	hasRequiredAuth := false
	for _, auth := range activeAuths {
		if auth == env.Sender.Address {
			hasRequiredAuth = true
			break
		}
	}
	if !hasRequiredAuth {
		return fmt.Errorf("active auth required to send funds")
	}
	senderBalance := balances[env.Sender.Address.String()]
	if senderBalance < amount {
		return fmt.Errorf("sender balance insufficient. has %d, needs %d", senderBalance, amount)
	}
	return nil
}
