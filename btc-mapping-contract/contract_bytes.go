package dexcontracts

import (
	"embed"
	"fmt"
)

//go:embed artifacts
var artifactsFS embed.FS

const artifactsDir = "artifacts"

// Pre-loaded byte arrays (nil if file doesn't exist at package init)
var (
	MainWasm     []byte
	Testnet4Wasm []byte
	Testnet3Wasm []byte
)

func init() {
	MainWasm, _ = loadWasmFile("main.wasm")
	Testnet4Wasm, _ = loadWasmFile("testnet4.wasm")
	Testnet3Wasm, _ = loadWasmFile("testnet4.wasm")
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
