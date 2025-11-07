package mapping

import (
	"contract-template/sdk"
	"encoding/hex"
	"fmt"

	"github.com/CosmWasm/tinyjson"
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
				TxId:     msgTx.TxID(),
				Vout:     uint32(index),
				Amount:   txOut.Value,
				PkScript: txOut.PkScript,
				Tag:      hex.EncodeToString(ms.AddressRegistry[addr].Tag),
			}
			outputsForVsc = append(outputsForVsc, utxo)
		}
	}

	return &outputsForVsc
}

func (cs *ContractState) updateUtxoSpends(txId string) error {
	utxoSpend, ok := cs.TxSpends[txId]
	if !ok {
		return nil
	}
	// not the most efficient but there should never be more than a few of these
	type unconfirmedUtxo struct {
		indexInRegistry int
		utxo            *Utxo
	}

	unconfirmedUtxos := []unconfirmedUtxo{}

	for i, utxoBytes := range cs.UtxoList {
		internalId, _, confirmed := unpackUtxo(utxoBytes)
		if confirmed == 0 {
			utxo := Utxo{}
			utxoJson := sdk.StateGetObject(utxoPrefix + fmt.Sprintf("%x", internalId))
			err := tinyjson.Unmarshal([]byte(*utxoJson), &utxo)
			if err != nil {
				return err
			}
			unconfirmedUtxos = append(unconfirmedUtxos, unconfirmedUtxo{indexInRegistry: i, utxo: &utxo})
		}
	}

	for _, sigHash := range utxoSpend.UnsignedSigHashes {
		// check all unconfirmed utxos
		for _, unconfirmed := range unconfirmedUtxos {
			if txId == unconfirmed.utxo.TxId && sigHash.Index == unconfirmed.utxo.Vout {
				// set the confirmed byte array to 1
				cs.UtxoList[unconfirmed.indexInRegistry][2] = []byte{1}
				continue
			}
		}
	}
	delete(cs.TxSpends, txId)
	return nil
}
