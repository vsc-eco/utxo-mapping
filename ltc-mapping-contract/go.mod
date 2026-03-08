module ltc-mapping-contract

go 1.25.6

// replace vsc-node => github.com/vsc-eco/go-vsc-node v0.0.0-20251120092146-ea108c70b7f0

replace vsc-node => ../../milo-go-vsc-node/

replace github.com/agl/ed25519 => github.com/binance-chain/edwards25519 v0.0.0-20200305024217-f36fc4b53d43

require (
	github.com/btcsuite/btcd v0.25.0
	github.com/btcsuite/btcd/btcutil v1.1.6
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
)

require (
	github.com/CosmWasm/tinyjson v0.9.0
	github.com/josharian/intern v1.0.0 // indirect
)

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.5 // indirect
	github.com/btcsuite/btclog v1.0.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
)
