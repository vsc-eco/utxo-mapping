// Proof of Concept VSC Smart Contract in Golang
//
// Build command: tinygo build -o main.wasm -gc=custom -scheduler=none -panic=trap -no-debug -target=wasm-unknown main.go
// Inspect Output: wasmer inspect main.wasm
// Run command (only works w/o SDK imports): wasmedge run main.wasm entrypoint 0
//
// Caveats:
// - Go routines, channels, and defer are disabled
// - panic() always halts the program, since you can't recover in a deferred function call
// - must import sdk or build fails
// - to mark a function as a valid entrypoint, it must be manually exported (//go:wasmexport <entrypoint-name>)
//
// TODO:
// - when panic()ing, call `env.abort()` instead of executing the unreachable WASM instruction
// - Remove _initalize() export & double check not necessary

package main

import (
	"contract-template/contract/mapping"
	_ "contract-template/sdk" // ensure sdk is imported
	"fmt"

	"contract-template/sdk"

	"github.com/holiman/uint256"
)

func main() {
	rawTxInput := ""
	MappingContract(&rawTxInput)
}

//go:wasmexport map_function
func MappingContract(incomingTx *string) *string {
	sdk.Log(*incomingTx)
	// derived from incomingTx (json or protobuf or something)
	rawTxHex := ""
	proofHex := ""
	instructions := ""
	// panic("test")
	mappingContract := mapping.NewMappingContract("publickey")
	mappingContract.HandleMap(&rawTxHex, &proofHex, &instructions)
	fmt.Println(mappingContract)
	return incomingTx
}

func UnmappingContract(tx *string) *string {
	sdk.Log(*tx)

	// derived from tx
	amount := uint256.NewInt(0)
}
