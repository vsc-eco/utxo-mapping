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
	DevWasm     []byte
	TestnetWasm []byte
	MainnetWasm []byte
	RegtestWasm []byte
)

func init() {
	DevWasm, _ = loadWasmFile("dev.wasm")
	TestnetWasm, _ = loadWasmFile("testnet.wasm")
	MainnetWasm, _ = loadWasmFile("mainnet.wasm")
	RegtestWasm, _ = loadWasmFile("regtest.wasm")
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
