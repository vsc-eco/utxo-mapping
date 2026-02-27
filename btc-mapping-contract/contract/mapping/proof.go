package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"bytes"
	"encoding/hex"
	"strconv"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func verifyTransaction(req *VerificationRequest, rawTxBytes []byte) error {
	// block header from contract state (input by chain oracle)
	rawHeaderHex := sdk.StateGetObject(constants.BlockPrefix + strconv.FormatUint(uint64(req.BlockHeight), 10))
	rawHeaderBytes, err := hex.DecodeString(*rawHeaderHex)
	if err != nil {
		return err
	}
	var blockHeader wire.BlockHeader
	blockHeader.BtcDecode(bytes.NewReader(rawHeaderBytes), wire.ProtocolVersion, wire.LatestEncoding)

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
		return ce.NewContractError(ce.ErrInput, "transaction cannot be validated, failed to reconstruct proof")
	}
	return nil
}

func merkleProofFromHex(proofHex string) ([]chainhash.Hash, error) {
	proofBytes, err := hex.DecodeString(proofHex)
	if err != nil {
		return nil, err
	}
	if len(proofBytes)%32 != 0 {
		return nil, ce.NewContractError(ce.ErrInput, "invalid proof format")
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

	var combined [64]byte

	for _, siblingHash := range proof {
		if index%2 == 0 {
			copy(combined[:32], currentHash[:])
			copy(combined[32:], siblingHash[:])
		} else {
			copy(combined[:32], siblingHash[:])
			copy(combined[32:], currentHash[:])
		}

		hash := chainhash.DoubleHashH(combined[:])
		currentHash = hash
		index = index / 2
	}

	return currentHash.IsEqual(&merkleRoot)
}
