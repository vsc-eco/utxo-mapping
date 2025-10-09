package mapping

import (
	"bytes"
	"contract-template/sdk"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func (cs *ContractState) HandleMap(txData *VerificationRequest) error {
	var totalMapped int64

	rawTx, err := hex.DecodeString(txData.RawTxHex)
	if err != nil {
		return err
	}
	proofBytes, err := hex.DecodeString(txData.MerkleProofHex)
	if err != nil {
		return err
	}
	if len(proofBytes)%32 != 0 {
		return errors.New("Invalid proof strcuture")
	}
	merkleProof := make([]chainhash.Hash, len(proofBytes)/32)
	for i := 0; i < len(proofBytes); i += 32 {
		merkleProof[i/32] = chainhash.Hash(proofBytes[i : i+32])
	}
	if err := verifyTransaction(txData, rawTx); err != nil {
		return err
	}

	var msgTx wire.MsgTx
	err = msgTx.Deserialize(bytes.NewReader(rawTx))
	if err != nil {
		return err
	}

	// gets all outputs the address of which is specified in the instructions
	relevantOutputs := *cs.indexOutputs(&msgTx)

	// create new utxos entries for all of the relevant outputs in the incoming transaction
	for _, utxo := range relevantOutputs {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(utxo.PkScript, &chaincfg.TestNet3Params)
		if err != nil {
			sdk.Abort(err.Error())
		}
		if metadata, ok := cs.AddressRegistry[addrs[0].EncodeAddress()]; ok {
			// Create UTXO entry
			utxoKey := fmt.Sprintf("%s:%d", utxo.TxId, utxo.Vout)
			cs.Utxos[utxoKey] = utxo
			cs.ObservedTxs[utxoKey] = true

			// increment balance for recipient account (vsc account not btc account)
			cs.Balances[metadata.VscAddress] += utxo.Amount

			totalMapped += utxo.Amount
		}
	}

	if totalMapped != 0 {
		cs.ActiveSupply += totalMapped
		cs.UserSupply += totalMapped
	}

	return nil
}

// Returns: raw tx hex to be broadcast
func (cs *ContractState) HandleUnmap(instructions *UnmappingInputData) string {
	amount := instructions.amount
	vscFee, err := deductVscFee(amount)
	if err != nil {
		sdk.Abort(err.Error())
	}
	postFeeAmount := amount - vscFee
	inputUtxos, totalInputAmt, err := cs.getInputUtxos(postFeeAmount)
	if err != nil {
		sdk.Abort(err.Error())
	}
	changeAddress, _, err := createP2WSHAddress(cs.PublicKey, "", &chaincfg.TestNet3Params)
	signingData, err := cs.createSpendTransaction(
		inputUtxos,
		totalInputAmt,
		instructions.recipientBtcAddress,
		changeAddress,
		postFeeAmount,
	)
	if err != nil {
		sdk.Abort(err.Error())
	}

	signatures := make(map[uint32][]byte, len(signingData.UnsignedSignHashes))
	for _, unsignedData := range signingData.UnsignedSignHashes {
		signature, err := signInput(unsignedData.SigHash)
		if err != nil {
			sdk.Abort(err.Error())
		}
		signatures[unsignedData.Index] = signature
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
		utxoKey := fmt.Sprintf("%s:%d", utxo.TxId, utxo.Vout)
		cs.Utxos[utxoKey] = utxo
	}

	// cs.balances[sdk.GetEnv().Sender.Address.String()] -= amount
	cs.ActiveSupply -= postFeeAmount
	cs.UserSupply -= amount
	cs.FeeSupply += vscFee

	return hex.EncodeToString(buf.Bytes())
}

func (cs *ContractState) HandleTrasfer(amount int64, destVscAddress string) {
	cs.Balances[sdk.GetEnv().Sender.Address.String()] -= amount
	cs.Balances[destVscAddress] += amount
}
