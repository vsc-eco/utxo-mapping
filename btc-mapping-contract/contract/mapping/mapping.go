package mapping

import (
	"contract-template/sdk"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func isForVscAcc(txOut *wire.TxOut, addresses map[string]*AddressMetadata, network *chaincfg.Params) (string, bool) {
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, network)
	if err != nil {
		sdk.Abort(err.Error())
	}
	// should always being exactly length 1 for P2SH an P2WSH addresses
	for _, addr := range addrs {
		addressString := addr.EncodeAddress()
		if _, ok := addresses[addressString]; ok {
			return addr.EncodeAddress(), true
		}
	}
	return "", false
}

func (ms *MappingState) indexOutputs(msgTx *wire.MsgTx) *[]Utxo {
	outputsForVsc := []Utxo{}

	for index, txOut := range msgTx.TxOut {
		if addr, ok := isForVscAcc(txOut, ms.AddressRegistry, ms.NetworkParams); ok {

			utxo := Utxo{
				TxId:      msgTx.TxID(),
				Vout:      uint32(index),
				Amount:    txOut.Value,
				PkScript:  txOut.PkScript,
				Tag:       hex.EncodeToString(ms.AddressRegistry[addr].Tag),
				Confirmed: true,
			}
			outputsForVsc = append(outputsForVsc, utxo)
		}
	}

	return &outputsForVsc
}

func (cs *ContractState) updateUtxoSpends(txId string) {
	utxoSpend, ok := cs.TxSpends[txId]
	if !ok {
		return
	}
	for _, sigHash := range utxoSpend.UnsignedSigHashes {
		utxoKey := fmt.Sprintf("%s:%d", txId, sigHash.Index)
		utxo, ok := cs.Utxos[utxoKey]
		if !ok {
			continue
		}
		utxo.Confirmed = true
	}
	delete(cs.TxSpends, txId)
}
