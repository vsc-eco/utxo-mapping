package mapping

import (
	"btc-mapping-contract/sdk"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

func createP2WSHAddressWithBackup(
	primaryPubKeyHex string, backupPubKeyHex string, tag []byte, network *chaincfg.Params,
) (string, []byte, error) {
	primaryPubKeyBytes, err := hex.DecodeString(primaryPubKeyHex)
	if err != nil {
		return "", nil, err
	}

	if backupPubKeyHex == "" {
		return createSimpleP2WSHAddress(primaryPubKeyBytes, tag, network)
	}

	backupPubKeyBytes, err := hex.DecodeString(backupPubKeyHex)
	if err != nil {
		return "", nil, err
	}

	csvBlocks := backupCSVBlocks

	if network.Net != chaincfg.MainNetParams.Net {
		csvBlocks = 2
	}

	scriptBuilder := txscript.NewScriptBuilder()

	// start if
	scriptBuilder.AddOp(txscript.OP_IF)

	// primary spending path
	// uses OP_CHECKSIG instead of OP_CHECKSIGVERIFY for tags of length 0
	// because an empty tag will leave the stack empty after verificaiton
	// and the tx will fail
	scriptBuilder.AddData(primaryPubKeyBytes)
	if tag == nil || len(tag) > 0 {
		scriptBuilder.AddOp(txscript.OP_CHECKSIGVERIFY)
		scriptBuilder.AddData(tag)
	} else {
		scriptBuilder.AddOp(txscript.OP_CHECKSIG)
	}

	// else: backup path
	scriptBuilder.AddOp(txscript.OP_ELSE)

	// CSV timelock check
	scriptBuilder.AddInt64(int64(csvBlocks))
	scriptBuilder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	scriptBuilder.AddOp(txscript.OP_DROP) // CSV leaves value on stack, need to drop it

	// backup key signature check
	scriptBuilder.AddData(backupPubKeyBytes)
	scriptBuilder.AddOp(txscript.OP_CHECKSIG)

	// end if
	scriptBuilder.AddOp(txscript.OP_ENDIF)

	script, err := scriptBuilder.Script()
	if err != nil {
		return "", nil, err
	}

	// Create P2WSH address
	witnessProgram := sha256.Sum256(script)
	addressWitnessScriptHash, err := btcutil.NewAddressWitnessScriptHash(witnessProgram[:], network)
	if err != nil {
		return "", nil, err
	}

	return addressWitnessScriptHash.EncodeAddress(), script, nil
}

func createP2WSHAddress(pubKeyHex string, tag []byte, network *chaincfg.Params) (string, []byte, error) {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "", nil, err
	}

	return createSimpleP2WSHAddress(pubKeyBytes, tag, network)
}

func createSimpleP2WSHAddress(pubKeyBytes []byte, tag []byte, network *chaincfg.Params) (string, []byte, error) {
	// uses OP_CHECKSIG instead of OP_CHECKSIGVERIFY for tags of length 0
	// because an empty tag will leave the stack empty after verificaiton
	// and the tx will fail
	scriptBuilder := txscript.NewScriptBuilder()
	if len(tag) > 0 {
		scriptBuilder.AddData(pubKeyBytes)
		scriptBuilder.AddOp(txscript.OP_CHECKSIGVERIFY)
		scriptBuilder.AddData(tag)
	} else {
		scriptBuilder.AddData(pubKeyBytes)
		scriptBuilder.AddOp(txscript.OP_CHECKSIG)
	}

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

func packUtxo(internalId uint32, amount int64, confirmed uint8) [3]int64 {
	return [3]int64{int64(internalId), amount, int64(confirmed)}
}

func unpackUtxo(utxo [3]int64) (uint32, int64, uint8) {
	return uint32(utxo[0]), utxo[1], uint8(utxo[2])
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

func (cs *ContractState) getNetwork(s string) (Network, error) {
	networkName := NetworkName(strings.ToLower(s))
	network, ok := cs.NetworkOptions[networkName]
	if ok {
		return network, nil
	}
	return nil, fmt.Errorf("Invalid network")
}

func IsTestnet(networkName string) bool {
	testnets := []string{
		Testnet3,
		Testnet4,
	}

	return slices.Contains(testnets, networkName)
}
