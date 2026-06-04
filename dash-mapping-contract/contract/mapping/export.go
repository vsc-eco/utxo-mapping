package mapping

import (
	"crypto/sha256"

	"github.com/btcsuite/btcd/chaincfg"
)

// AddressWithBackup derives the Dash P2SH address for the given keys
// and tag, returning (base58 P2SH address, redeem-script bytes).
//
// Tag semantics match createP2SHAddressWithBackup:
//   - nil  → OP_CHECKSIGVERIFY + OP_DATA_0 (change address path)
//   - []byte{} → OP_CHECKSIG only (empty-tag UTXO)
//   - non-empty → OP_CHECKSIGVERIFY + <tag>
//
// Naming history (audit R15-CONS-01): the second return value was
// originally called `witnessScript` while the on-chain commitment was
// P2WSH bech32. Commit acfb268 switched to P2SH because Dash never
// activated SegWit, so `witnessScript` is now properly called
// `redeemScript` (the script committed via HASH160 in the P2SH output).
func AddressWithBackup(
	primaryPubKeyHex, backupPubKeyHex string,
	tag []byte,
	network *chaincfg.Params,
) (address string, redeemScript []byte, err error) {
	primaryPubKey, err := DecodeCompressedPubKey(primaryPubKeyHex)
	if err != nil {
		return "", nil, err
	}
	backupPubKey, err := DecodeCompressedPubKey(backupPubKeyHex)
	if err != nil {
		return "", nil, err
	}
	return createP2SHAddressWithBackup(primaryPubKey, backupPubKey, tag, network)
}

// DepositAddress derives the Dash P2SH deposit address for a given
// instruction string. The tag is SHA256(instruction), matching the
// on-chain derivation in parseInstructions. Same P2WSH→P2SH naming
// history as AddressWithBackup.
func DepositAddress(
	primaryPubKeyHex, backupPubKeyHex, instruction string,
	network *chaincfg.Params,
) (address string, redeemScript []byte, err error) {
	primaryPubKey, err := DecodeCompressedPubKey(primaryPubKeyHex)
	if err != nil {
		return "", nil, err
	}
	backupPubKey, err := DecodeCompressedPubKey(backupPubKeyHex)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256([]byte(instruction))
	return createP2SHAddressWithBackup(primaryPubKey, backupPubKey, sum[:], network)
}
