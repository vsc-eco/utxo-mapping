package mapping

import (
	"bytes"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func verifyTransaction(req *VerificationRequest) (bool, error) {
	headerMap := make(map[int32][]byte)
	rawHeader := headerMap[req.blockHeight]
	var blockHeader wire.BlockHeader
	blockHeader.BtcDecode(bytes.NewReader(rawHeader), wire.ProtocolVersion, wire.LatestEncoding)

	tx := wire.NewMsgTx(wire.TxVersion)
	if err := tx.Deserialize(bytes.NewReader(req.rawTx)); err != nil {
		return false, err
	}

	calculatedHash := tx.TxHash()

	if !verifyMerkleProof(calculatedHash, req.txIndex, req.merkleProof, blockHeader.MerkleRoot) {
		return false, nil
	}
	return true, nil
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
