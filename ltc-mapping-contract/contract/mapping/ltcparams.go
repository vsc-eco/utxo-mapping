package mapping

import (
	"math/big"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

// Litecoin network magic bytes (little-endian uint32 of pchMessageStart)
const (
	ltcMainNet  wire.BitcoinNet = 0xdbb6c0fb
	ltcTestNet4 wire.BitcoinNet = 0xf1c8d2fd
)

// scryptPowLimit is the PoW limit for Litecoin's Scrypt algorithm.
// Value: 00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
// TODO: Scrypt PoW validation not yet implemented in blocklist.go
var scryptPowLimit = new(big.Int).SetBytes([]byte{
	0x00, 0x00, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
})

// LtcMainNetParams defines the network parameters for the Litecoin main network.
// Source: https://github.com/litecoin-project/litecoin/blob/master/src/chainparams.cpp
var LtcMainNetParams = chaincfg.Params{
	Name:        "mainnet",
	Net:         ltcMainNet,
	DefaultPort: "9333",

	// Address encoding magics
	PubKeyHashAddrID: 0x30, // starts with L
	// NOTE: Litecoin has two P2SH prefixes. We use SCRIPT_ADDRESS2 (0x32, "M" prefix)
	// which is the Litecoin-canonical prefix. Legacy "3"-prefix P2SH addresses (0x05)
	// will NOT validate. This only affects unmap destination addresses.
	ScriptHashAddrID: 0x32, // starts with M (SCRIPT_ADDRESS2)
	PrivateKeyID:     0xB0,
	// WitnessPubKeyHashAddrID and WitnessScriptHashAddrID are btcd-internal values
	// used for address type identification, not for bech32 encoding. Using BTC defaults
	// as Litecoin does not define separate values. Proven unused: btcutil address
	// encoding/decoding uses only Bech32HRPSegwit for segwit addresses.
	WitnessPubKeyHashAddrID: 0x06,
	WitnessScriptHashAddrID: 0x0A,

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x88, 0xAD, 0xE4},
	HDPublicKeyID:  [4]byte{0x04, 0x88, 0xB2, 0x1E},
	HDCoinType:     2,

	// Bech32 human-readable part
	Bech32HRPSegwit: "ltc",

	// PoW
	PowLimit:     scryptPowLimit,
	PowLimitBits: 0x1e0ffff0,
}

// LtcTestNet4Params defines the network parameters for the Litecoin test network.
// Source: https://github.com/litecoin-project/litecoin/blob/master/src/chainparams.cpp
var LtcTestNet4Params = chaincfg.Params{
	Name:        "testnet4",
	Net:         ltcTestNet4,
	DefaultPort: "19335",

	// Address encoding magics
	PubKeyHashAddrID: 0x6F, // starts with m or n
	// NOTE: Same SCRIPT_ADDRESS2 limitation as mainnet. Using 0x3A (Litecoin-specific
	// testnet prefix). Legacy 0xC4 ("2"-prefix) P2SH addresses will NOT validate.
	ScriptHashAddrID: 0x3A, // SCRIPT_ADDRESS2
	PrivateKeyID:     0xEF,
	// See mainnet comment — proven unused by btcutil, safe for bech32 usage.
	WitnessPubKeyHashAddrID: 0x06,
	WitnessScriptHashAddrID: 0x0A,

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94},
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xCF},
	HDCoinType:     1,

	// Bech32 human-readable part
	Bech32HRPSegwit: "tltc",

	// PoW
	PowLimit:     scryptPowLimit,
	PowLimitBits: 0x1e0fffff,
}
