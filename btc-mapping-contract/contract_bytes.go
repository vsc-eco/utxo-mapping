package dexcontracts

import (
	"embed"
	"fmt"
)

//go:embed bin
var artifactsFS embed.FS

const artifactsDir = "bin"

// Pre-loaded byte arrays (nil if file doesn't exist at package init)
var (
	DevWasm      []byte
	Testnet4Wasm []byte
	Testnet3Wasm []byte
	RegtestWasm  []byte
	// MainnetWasm is needed by the BTC-HDR-1 difficulty tests: mainnet is the
	// only network the contract builds for with ReduceMinDifficulty false, so
	// it is the only one where the retarget rules are enforced at all.
	MainnetWasm []byte
)

func init() {
	DevWasm, _ = loadWasmFile("dev.wasm")
	Testnet4Wasm, _ = loadWasmFile("testnet4.wasm")
	Testnet3Wasm, _ = loadWasmFile("testnet3.wasm")
	RegtestWasm, _ = loadWasmFile("regtest.wasm")
	MainnetWasm, _ = loadWasmFile("mainnet.wasm")
}

// loadWasmFile reads a WASM file from the embedded artifacts directory
func loadWasmFile(filename string) ([]byte, error) {
	path := fmt.Sprintf("%s/%s", artifactsDir, filename)
	data, err := artifactsFS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("wasm file not found: %s", filename)
	}
	return data, nil
}
