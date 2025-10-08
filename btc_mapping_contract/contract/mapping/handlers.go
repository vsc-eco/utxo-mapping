package mapping

import (
	"bytes"
	"contract-template/sdk"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func (cs *ContractState) HandleMap(rawTxHex *string, proofHex *string, instructionsString *string) error {
	var totalMapped int64

	rawTx, err := hex.DecodeString(*rawTxHex)
	if err != nil {
		return err
	}
	proof, err := hex.DecodeString(*proofHex)
	if err != nil {
		return err
	}
	if !verifyProof(&proof) {
		return errors.New("Proof could not be validated")
	}
	// TODO: create from instruction string once format is known
	// cs.setInstructions(instructionsString)

	var msgTx wire.MsgTx
	err = msgTx.Deserialize(bytes.NewReader(rawTx))
	if err != nil {
		return err
	}

	// gets all outputs the address of which is specified in the instructions
	relevantOutputs := *cs.indexOutputs(&msgTx)

	// create new utxos entries for all of the relevant outputs in the incoming transaction
	for _, utxo := range relevantOutputs {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(utxo.pkScript, &chaincfg.TestNet3Params)
		if err != nil {
			sdk.Abort(err.Error())
		}
		if vscAddress, ok := cs.getInternalAddressForBitcoinAddress(addrs[0].EncodeAddress()); ok {
			// Create UTXO entry
			utxoKey := fmt.Sprintf("%s:%d", utxo.txId, utxo.vout)
			cs.utxos[utxoKey] = utxo
			cs.observedTxs[utxoKey] = true

			// increment balance for recipient account (vsc account not btc account)
			cs.balances[vscAddress] += utxo.amount

			totalMapped += utxo.amount
		}
	}

	if totalMapped != 0 {
		cs.activeSupply += totalMapped
		cs.userSupply += totalMapped
	}

	return nil
}

// Returns: raw tx hex to be broadcast
func (cs *ContractState) HandleUnmap(amount int64, destBtcAddress string) string {
	vscFee, err := deductVscFee(amount)
	if err != nil {
		sdk.Abort(err.Error())
	}
	postFeeAmount := amount - vscFee
	inputUtxos, totalInputAmt, err := cs.getInputUtxos(postFeeAmount)
	if err != nil {
		sdk.Abort(err.Error())
	}
	changeAddress, _, err := createP2WSHAddress(cs.publicKey, "", &chaincfg.TestNet3Params)
	signingData, err := cs.createSpendTransaction(
		inputUtxos,
		totalInputAmt,
		destBtcAddress,
		changeAddress,
		postFeeAmount,
	)
	if err != nil {
		sdk.Abort(err.Error())
	}

	signatures := make(map[uint32][]byte, len(signingData.UnsignedSignHashes))
	for _, unsignedData := range signingData.UnsignedSignHashes {
		signature, err := signInput(unsignedData.sigHash)
		if err != nil {
			sdk.Abort(err.Error())
		}
		signatures[unsignedData.index] = signature
	}
	attachSignatures(signingData, signatures)

	var buf bytes.Buffer
	// this is the same as serialize, but
	if err := signingData.Tx.BtcEncode(&buf, wire.ProtocolVersion, wire.WitnessEncoding); err != nil {
		sdk.Abort(err.Error())
	}

	unconfirmedUtxos := indexUnconfimedOutputs(signingData)
	for _, utxo := range unconfirmedUtxos {
		// Create UTXO entry
		utxoKey := fmt.Sprintf("%s:%d", utxo.txId, utxo.vout)
		cs.utxos[utxoKey] = utxo
	}

	cs.balances[sdk.GetEnv().Sender.Address.String()] -= amount
	cs.activeSupply -= postFeeAmount
	cs.userSupply -= amount
	cs.feeSupply += vscFee

	return hex.EncodeToString(buf.Bytes())
}

func (cs *ContractState) HandleTrasfer(amount int64, destVscAddress string) {
	cs.balances[sdk.GetEnv().Sender.Address.String()] -= amount
	cs.balances[destVscAddress] += amount
}
