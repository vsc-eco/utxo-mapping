package mapping

import (
	"bytes"
	"contract-template/sdk"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"

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

func checkSender(env sdk.Env, amount int64) (int64, error) {
	activeAuths := env.Sender.RequiredAuths
	hasRequiredAuth := false
	for _, auth := range activeAuths {
		if auth == env.Sender.Address {
			hasRequiredAuth = true
			break
		}
	}
	if !hasRequiredAuth {
		return 0, fmt.Errorf("active auth required to send funds")
	}

	senderBal, err := getAccBal(env.Sender.Address.String())
	if err != nil {
		return 0, err
	}

	if senderBal < amount {
		return 0, fmt.Errorf("sender balance insufficient. has %d, needs %d", senderBal, amount)
	}
	return senderBal, nil
}

func packUtxo(internalId uint32, amount int64, confirmed uint8) [3][]byte {
	idBytes := make([]byte, 4)
	amountBytes := make([]byte, 8)
	confirmedBytes := []byte{confirmed}

	binary.BigEndian.PutUint32(idBytes, internalId)
	binary.BigEndian.PutUint64(amountBytes, uint64(amount))

	idBytes = bytes.TrimLeft(idBytes, "\x00")
	amountBytes = bytes.TrimLeft(amountBytes, "\x00")

	if len(idBytes) == 0 {
		idBytes = []byte{0}
	}
	if len(amountBytes) == 0 {
		amountBytes = []byte{0}
	}

	return [3][]byte{idBytes, amountBytes, confirmedBytes}
}

func unpackUtxo(utxo [3][]byte) (uint32, int64, uint8) {
	idBytes := make([]byte, 4)
	amountBytes := make([]byte, 8)

	copy(idBytes[4-len(utxo[0]):], utxo[0])
	copy(amountBytes[8-len(utxo[1]):], utxo[1])

	internalId := binary.BigEndian.Uint32(idBytes)
	amount := int64(binary.BigEndian.Uint64(amountBytes))
	confirmed := utxo[2][0]

	return internalId, amount, confirmed
}

func getAccBal(vscAcc string) (int64, error) {
	balString := sdk.StateGetObject(balancePrefix + vscAcc)
	if *balString == "" {
		return 0, nil
	}
	bal, err := strconv.ParseInt(*balString, 10, 64)
	if err != nil {
		return 0, err
	}
	return bal, nil
}

// sets account balance to number (in base 10)
func setAccBal(vscAcc string, newBal int64) {
	sdk.StateSetObject(balancePrefix+vscAcc, strconv.FormatInt(newBal, 10))
}
