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
)

const PUBLICKEY = "0242f9da15eae56fe6aca65136738905c0afdb2c4edf379e107b3b00b98c7fc9f0"

//go:wasmexport add_blocks
func AddBlock(blockData *string) {

}

//go:wasmexport map
func Map(incomingTx *string) *string {
	// derived from incomingTx (json or protobuf or something)
	rawTxHex := "02000000000102878929613912a755c119219ce03b87e9928eddcc92a6e9386f633c944acb72260000000000fdffffff878929613912a755c119219ce03b87e9928eddcc92a6e9386f633c944acb72260100000000fdffffff011bd3010000000000220020f67a853d1ba339a1a38ec56f701daa96c3c6e4edbd8a28a5e258dc5a4f266cd302473044022077439890c726f95518196e2b83d83296cf0f48c1c381849e4906d61a4cc1138402203c233507c4b91566b7a7a6fca7213040e1ebf305c90e5145d9f225f537dd3b410121030b342439e114f84202991084723e71873300d730a1eacf6092d2e778325779a9024730440220693faf99b95c03cbfe90122b741ddbde368dd5211d272aa20dc19dcab00a4d2b0220299ecfe87c944370d9a1e91146aaa199cdbb50da37548755578ced5fb07ad7780121022b219f50bb0f57f84ee598b3434904706ee64289c5ac4b1218c4a3a35e390c6d2e454800"
	proofHex := ""
	instructions := ""
	// panic("test")
	contractState := mapping.NewTestValuesState(PUBLICKEY)
	err := contractState.HandleMap(&rawTxHex, &proofHex, &instructions)
	if err != nil {
		sdk.Abort(err.Error())
	}
	sdk.Log(fmt.Sprintln("\ncontract state:", contractState, "\n\n"))

	ret := "success"
	return &ret
}

//go:wasmexport unmap
func Unmap(tx *string) *string {
	// derived from tx
	amount := int64(10000)
	// recipientVscAddress := ""
	recipientBtcAddress := "tb1q5dgehs94wf5mgfasnfjsh4dqv6hz8e35w4w7tk"

	contractState := mapping.NewTestUnmapValuesState(PUBLICKEY)
	rawTx := contractState.HandleUnmap(amount, recipientBtcAddress)

	sdk.Log(fmt.Sprintln("\ncontract state:", contractState, "\n\n"))
	return &rawTx
}

//go:wasmexport transfer
func Transfer(tx *string) *string {
	// derived from tx
	amount := int64(0)
	recipientVscAddress := ""

	contractState := mapping.NewTestValuesState("publickey")
	contractState.HandleTrasfer(amount, recipientVscAddress)

	return tx
}
