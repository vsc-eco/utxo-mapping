package mapping

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/holiman/uint256"

	"contract-template/sdk"
)

func (mc *MappingContract) HandleMap(rawTxHex *string, proofHex *string, instructionsString *string) error {
	var totalMapped uint256.Int

	rawTx, err := hex.DecodeString(*rawTxHex)
	if err != nil {
		sdk.Abort(err.Error())
	}
	proof, err := hex.DecodeString(*proofHex)
	if err != nil {
		sdk.Abort(err.Error())
	}
	verifyProof(&proof)
	// TODO: create from instruction string once format is known
	mc.setInstructions(instructionsString)

	var msgTx wire.MsgTx
	err = msgTx.Deserialize(bytes.NewReader(rawTx))
	if err != nil {
		sdk.Abort(err.Error())
	}

	// gets all outputs the address of which is specified in the instructions
	relevantOutputs := *mc.indexOutputs(&msgTx)

	// create new utxos entries for all of the relevant outputs in the incoming transaction
	for _, utxo := range relevantOutputs {
		if internalAddress, ok := mc.getInternalAddressForBitcoinAddress(utxo.Address); ok {
			// Create UTXO entry
			utxoKey := fmt.Sprintf("%s:%d", utxo.TxID, utxo.Vout)
			mc.utxos[utxoKey] = utxo
			mc.observedTxs[utxoKey] = true

			balance := mc.balances[internalAddress]
			balance.Add(&balance, &utxo.Amount)
			mc.balances[internalAddress] = balance

			totalMapped.Add(&totalMapped, &utxo.Amount)
		}
	}

	if !totalMapped.IsZero() {
		mc.activeSupply.Add(&mc.activeSupply, &totalMapped)
	}

	return nil
}
