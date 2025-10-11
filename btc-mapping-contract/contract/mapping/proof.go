package mapping

import (
	"bytes"
	"contract-template/contract/blocklist"
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func verifyTransaction(req *VerificationRequest, rawTxBytes []byte) error {
	blockMap := blocklist.BlockDataFromState().BlockMap

	// block header from contract state (input by chain oracle)
	rawHeaderHex := blockMap[req.BlockHeight]
	rawHeaderBytes, err := hex.DecodeString(rawHeaderHex)
	var blockHeader wire.BlockHeader
	blockHeader.BtcDecode(bytes.NewReader(rawHeaderBytes), wire.ProtocolVersion, wire.LatestEncoding)

	// sdk.Log(fmt.Sprintf("block hash: %s", blockHeader.BlockHash().String()))

	tx := wire.NewMsgTx(wire.TxVersion)
	if err := tx.Deserialize(bytes.NewReader(rawTxBytes)); err != nil {
		return err
	}

	merkleProof, err := merkleProofFromHex(req.MerkleProofHex)
	if err != nil {
		return err
	}

	calculatedHash := tx.TxHash()

	if !verifyMerkleProof(calculatedHash, req.TxIndex, merkleProof, blockHeader.MerkleRoot) {
		return errors.New("transaction cannot be validated, failed to reconstruct proof")
	}
	return nil
}

func merkleProofFromHex(proofHex string) ([]chainhash.Hash, error) {
	proofBytes, err := hex.DecodeString(proofHex)
	if err != nil {
		return nil, err
	}
	if len(proofBytes)%32 != 0 {
		return nil, errors.New("invalid proof format")
	}
	proof := make([]chainhash.Hash, len(proofBytes)/32)
	for i := 0; i < len(proofBytes); i += 32 {
		proof[i/32] = chainhash.Hash(proofBytes[i : i+32])
	}
	return proof, nil
}

func verifyMerkleProof(
	txHash chainhash.Hash,
	txIndex uint32,
	proof []chainhash.Hash,
	merkleRoot chainhash.Hash,
) bool {
	currentHash := txHash
	index := txIndex

	for _, siblingHash := range proof {
		var combined []byte
		if index%2 == 0 {
			combined = append(currentHash[:], siblingHash[:]...)
		} else {
			combined = append(siblingHash[:], currentHash[:]...)
		}

		hash := chainhash.DoubleHashH(combined)
		currentHash = hash
		index = index / 2
	}

	return currentHash.IsEqual(&merkleRoot)
}
