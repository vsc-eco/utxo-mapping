package mapping

import (
	"crypto/sha256"

	"github.com/btcsuite/btcd/chaincfg"
)

// AddressWithBackup derives the P2WSH address for the given keys and tag.
// Tag semantics match createP2WSHAddressWithBackup:
//   - nil  -> OP_CHECKSIGVERIFY + OP_DATA_0 (change address path)
//   - []byte{} -> OP_CHECKSIG only (empty-tag UTXO)
//   - non-empty -> OP_CHECKSIGVERIFY + <tag>
func AddressWithBackup(
	primaryPubKeyHex, backupPubKeyHex string,
	tag []byte,
	network *chaincfg.Params,
) (address string, witnessScript []byte, err error) {
	primaryPubKey, err := DecodeCompressedPubKey(primaryPubKeyHex)
	if err != nil {
		return "", nil, err
	}
	backupPubKey, err := DecodeCompressedPubKey(backupPubKeyHex)
	if err != nil {
		return "", nil, err
	}
	return createP2WSHAddressWithBackup(primaryPubKey, backupPubKey, tag, network)
}

// DepositAddress derives the P2WSH deposit address for a given instruction string.
// The tag is SHA256(instruction), matching the on-chain derivation in parseInstructions.
func DepositAddress(
	primaryPubKeyHex, backupPubKeyHex, instruction string,
	network *chaincfg.Params,
) (address string, witnessScript []byte, err error) {
	primaryPubKey, err := DecodeCompressedPubKey(primaryPubKeyHex)
	if err != nil {
		return "", nil, err
	}
	backupPubKey, err := DecodeCompressedPubKey(backupPubKeyHex)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256([]byte(instruction))
	return createP2WSHAddressWithBackup(primaryPubKey, backupPubKey, sum[:], network)
}
