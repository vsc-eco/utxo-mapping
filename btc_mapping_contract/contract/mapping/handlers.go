package mapping

import (
	"bytes"
	"encoding/hex"
	"errors"
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
	// TODO: create from instruction string once format is known
	instructionRawArray := []string{}
	mc.instructions = mc.createInstructionObjects(&instructionRawArray)

	var msgTx wire.MsgTx
	err = msgTx.Deserialize(bytes.NewReader(rawTx))
	if err != nil {
		sdk.Abort(err.Error())
	}

	// create new utxos entries for all of the relevant outputs in the incoming transaction
	for _, output := range tx.Outputs {
		if internalAddress, ok := mc.getInternalAddressForBitcoinAddress(output.Address); ok {
			// Create UTXO entry
			utxoKey := fmt.Sprintf("%s:%d", tx.TxID, output.Index)
			mc.utxos[utxoKey] = Utxo{
				txID:    tx.TxID,
				index:   output.Index,
				address: output.Address,
				amount:  output.Amount,
			}

			balance := mc.balances[internalAddress]
			balance.Add(&balance, &output.Amount)
			mc.balances[internalAddress] = balance

			totalMapped.Add(&totalMapped, &output.Amount)
		}
	}

	// sum the total ouputs
	if totalMapped.IsZero() {
		return errors.New("no valid outputs found for mapping")
	}

	mc.activeSupply.Add(&mc.activeSupply, &totalMapped)

	return nil
}
