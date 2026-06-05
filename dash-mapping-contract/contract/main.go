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
	"dash-mapping-contract/contract/blocklist"
	"dash-mapping-contract/contract/constants"
	ce "dash-mapping-contract/contract/contracterrors"
	"dash-mapping-contract/contract/mapping"
	_ "dash-mapping-contract/sdk" // ensure sdk is imported
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"

	"dash-mapping-contract/sdk"

	"github.com/CosmWasm/tinyjson"
)

// passed via ldflags, will compile for testnet when set to "testnet"
var NetworkMode string

func checkOracle() {
	caller := sdk.GetEnv().Caller.String()
	if caller == constants.OracleAddress {
		return
	}
	// Owner-as-oracle shortcut: applies on real testnet + regtest
	// (both run by a single trusted operator). Mainnet requires the
	// dedicated oracle identity.
	if constants.IsTestnetOrRegtest(NetworkMode) && caller == *sdk.GetEnvKey("contract.owner") {
		return
	}
	ce.CustomAbort(
		ce.NewContractError(ce.ErrNoPermission, "this action must be performed by a contract administrator"),
	)
}

func checkAdmin() {
	caller := sdk.GetEnv().Caller.String()
	if caller == constants.OracleAddress || caller == *sdk.GetEnvKey("contract.owner") {
		return
	}
	ce.CustomAbort(
		ce.NewContractError(ce.ErrNoPermission, "this action must be performed by a contract administrator"),
	)
}

func checkOwner() {
	if sdk.GetEnv().Caller.String() != *sdk.GetEnvKey("contract.owner") {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "action must be performed by the contract owner"),
		)
	}
}

func checkNotPaused() {
	s := sdk.StateGetObject(constants.PausedKey)
	if s != nil && *s == "1" {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrTransaction, "contract is paused"),
		)
	}
}

//go:wasmexport seedBlocks
func SeedBlocks(blockSeedInput *string) *string {
	checkAdmin()

	var seedParams blocklist.SeedBlocksParams
	err := tinyjson.Unmarshal([]byte(*blockSeedInput), &seedParams)
	if err != nil {
		ce.CustomAbort(ce.WrapContractError(ce.ErrJson, err, "error unmarshalling seed blocks input"))
	}

	// Idempotency relaxation: testnet + regtest can re-seed; mainnet
	// is one-shot. Both operator-modes need the relaxation.
	newLastHeight, err := blocklist.HandleSeedBlocks(seedParams, constants.IsTestnetOrRegtest(NetworkMode))
	if err != nil {
		ce.CustomAbort(err)
	}

	// Fresh deployments start at the latest migration version so they skip all migrations.
	sdk.StateSetObject(constants.MigrateVersionKey, constants.LatestMigrateVersion)

	outMsg := "last height: " + strconv.FormatUint(uint64(newLastHeight), 10)
	return &outMsg
}

// initPruning sets the prune floor for contracts deployed before pruning was
// added. Must be called once by the contract owner after a code upgrade.
// The floor should be the original seed height (the lowest block header
// stored in state). After this, addBlocks will automatically prune old headers.
//
//go:wasmexport initPruning
func InitPruning(input *string) *string {
	checkAdmin()

	floor, err := strconv.ParseUint(*input, 10, 32)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "expected block height as integer string"))
	}

	existing := sdk.StateGetObject(constants.PruneFloorKey)
	if existing != nil && *existing != "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "prune floor already set"))
	}

	sdk.StateSetObject(constants.PruneFloorKey, strconv.FormatUint(floor, 10))
	sdk.StateSetObject(constants.SeedHeightKey, strconv.FormatUint(floor, 10))

	return mapping.StrPtr("prune floor set to " + strconv.FormatUint(floor, 10))
}

// setMaxUnmapPerBlock tunes the BTC-C3 (propagated) per-Hive-block
// withdrawal cap. Argument is a non-negative integer string in
// duffs. Setting 0 disables the rate limit; any positive value
// caps the aggregate finalAmt across all unmaps in a single Hive
// block. Operators should set this proportional to TVL.
//
//go:wasmexport setMaxUnmapPerBlock
func SetMaxUnmapPerBlock(input *string) *string {
	checkAdmin()
	if input == nil || *input == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "expected duffs-per-block as integer string"))
	}
	v, err := strconv.ParseInt(strings.TrimSpace(*input), 10, 64)
	if err != nil || v < 0 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "expected non-negative integer duffs-per-block"))
	}
	sdk.StateSetObject(constants.MaxUnmapPerBlockKey, strconv.FormatInt(v, 10))
	if v == 0 {
		return mapping.StrPtr("max unmap per block disabled (rate limit off)")
	}
	return mapping.StrPtr("max unmap per block set to " + strconv.FormatInt(v, 10) + " duffs")
}

// prune removes old block headers beyond the retention window.
// Can be called independently of addBlocks to reduce state size.
// Returns the number of headers pruned and the current prune floor.
//
//go:wasmexport prune
func Prune(_ *string) *string {
	checkAdmin()

	lastHeight, err := blocklist.LastHeightFromState()
	if err != nil {
		ce.CustomAbort(ce.WrapContractError(ce.ErrStateAccess, err, "error reading last block height"))
	}

	pruned := blocklist.PruneOldHeaders(lastHeight)

	return mapping.StrPtr(
		"pruned " + strconv.Itoa(pruned) + " headers, last height: " + strconv.FormatUint(uint64(lastHeight), 10),
	)
}

//go:wasmexport addBlocks
func AddBlocks(addBlocksInput *string) *string {
	checkOracle()

	var addBlocksObj blocklist.AddBlocksParams
	err := tinyjson.Unmarshal([]byte(*addBlocksInput), &addBlocksObj)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	blockHeaders, err := blocklist.DivideHeaderList(&addBlocksObj.Blocks)
	if err != nil {
		ce.CustomAbort(
			ce.WrapContractError(ce.ErrInput, err, "error parsing block headers"),
		)
	}

	var resultBuilder strings.Builder
	lastHeight, err := blocklist.HandleAddBlocks(blockHeaders, NetworkMode)
	if err != nil {
		ce.CustomAbort(err)
	}
	resultBuilder.WriteString("last height: " + strconv.FormatUint(uint64(lastHeight), 10))

	blocklist.LastHeightToState(lastHeight)

	// update base fee rate, do this after blocks because blocks more likely to fail
	systemSupply, err := mapping.SupplyFromState()
	if err != nil {
		ce.CustomAbort(err)
	}
	latestFee := addBlocksObj.LatestFee
	if latestFee == 0 {
		latestFee = 1
	}
	systemSupply.BaseFeeRate = latestFee
	mapping.SaveSupplyToState(systemSupply)
	resultBuilder.WriteString(", base fee: " + strconv.FormatInt(systemSupply.BaseFeeRate, 10))

	return mapping.StrPtr(resultBuilder.String())
}

//go:wasmexport replaceBlock
func ReplaceBlock(input *string) *string {
	checkAdmin()

	blockBytes, err := hex.DecodeString(*input)
	if err != nil {
		ce.CustomAbort(ce.WrapContractError(ce.ErrInvalidHex, err, "error decoding replacement block hex"))
	}
	if len(blockBytes) != 80 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "expected exactly 80 bytes (one block header)"))
	}

	var header blocklist.BlockHeaderBytes
	copy(header[:], blockBytes)

	height, err := blocklist.HandleReplaceBlock(header, NetworkMode)
	if err != nil {
		ce.CustomAbort(err)
	}

	outMsg := "replaced block at height: " + strconv.FormatUint(uint64(height), 10)
	return &outMsg
}

// replaceBlocks handles multi-block reorgs by replacing the top N blocks at once.
// Input is a concatenated hex string of 80-byte block headers, ordered lowest-to-highest.
// The first header replaces lastHeight-(N-1), the last replaces lastHeight.
//
//go:wasmexport replaceBlocks
func ReplaceBlocks(input *string) *string {
	checkAdmin()

	blockHeaders, err := blocklist.DivideHeaderList(input)
	if err != nil {
		ce.CustomAbort(ce.WrapContractError(ce.ErrInput, err, "error parsing replacement block headers"))
	}

	height, err := blocklist.HandleReplaceBlocks(blockHeaders, NetworkMode)
	if err != nil {
		ce.CustomAbort(err)
	}

	outMsg := "replaced " + strconv.Itoa(len(blockHeaders)) + " blocks, tip at height: " + strconv.FormatUint(uint64(height), 10)
	return &outMsg
}

//go:wasmexport map
func Map(incomingTx *string) *string {
	checkNotPaused()
	var mapInstructions mapping.MapParams
	err := tinyjson.Unmarshal([]byte(*incomingTx), &mapInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	publicKeys, err := loadPublicKeys()
	if err != nil {
		ce.CustomAbort(err)
	}

	contractState, err := mapping.InitializeMappingState(publicKeys, NetworkMode, mapInstructions.Instructions...)
	if err != nil {
		ce.CustomAbort(err)
	}

	err = contractState.HandleMap(mapInstructions.TxData)
	if err != nil {
		ce.CustomAbort(err)
	}

	err = contractState.SaveToState()
	if err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

// MapInstantSendV2 is the lazy-attestation fast path for the Dash
// InstantSend login feature (workstream 5).
//
// Unlike Map, this action:
//   - Verifies a BLS quorum-aggregated attestation from Magi validators
//     instead of waiting for a full block-proof, allowing ~15-30s
//     finality from the user's perspective.
//   - Supports the `op=auth` instruction (login-only, no value movement)
//     and `op=call;contract=...;method=...;args=...;sid=...;amount=...`
//     for dispatching contract calls via dash-forwarder-contract.
//   - Maintains all the same security gates as Map (deposit address
//     re-derivation, multi-input rejection, rate limits, allow-list).
//
// Per spec §5.2.2 the caller need not be the oracle — any party can
// submit a valid attestation bundle. Authorization comes from the BLS
// quorum signature, not the caller identity.
//
//go:wasmexport mapInstantSendV2
func MapInstantSendV2(payload *string) *string {
	checkNotPaused()
	var params mapping.MapInstantSendV2ParamsFull
	if err := tinyjson.Unmarshal([]byte(*payload), &params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput))
	}

	publicKeys, err := loadPublicKeys()
	if err != nil {
		ce.CustomAbort(err)
	}

	contractState, err := mapping.InitializeMappingState(publicKeys, NetworkMode)
	if err != nil {
		ce.CustomAbort(err)
	}

	if err := contractState.HandleMapInstantSendV2(params); err != nil {
		ce.CustomAbort(err)
	}

	if err := contractState.SaveToState(); err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

// SetForwarderContractId — admin action to designate the canonical
// dash-forwarder-contract id this mapping trusts. Idempotent: re-setting
// to the same value is a no-op; changing to a different value requires
// pausing the contract first.
//
//go:wasmexport setForwarderContractId
func SetForwarderContractId(payload *string) *string {
	checkAdmin()
	if payload == nil || *payload == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "forwarder contract id required"))
	}
	existing := sdk.StateGetObject(constants.ForwarderContractIdStateKey)
	if existing != nil && *existing != "" && *existing != *payload {
		ce.CustomAbort(ce.NewContractError(ce.ErrNoPermission,
			"forwarder contract id already set; pause + clear required to change"))
	}
	sdk.StateSetObject(constants.ForwarderContractIdStateKey, *payload)
	return mapping.StrPtr("0")
}

// AddAllowedTarget — admin schedules a contract id for addition to the
// op=call allow-list. Spec §5.2.7 — the proposal sits in
// pendingAdd["pa/<target>"] until AllowListGovernanceTimelockBlocks
// elapse; then any caller (admin or not) can promote it via
// CommitAllowedTarget. This forces the timelock to be observable in
// chain state, defending against an admin-key compromise being able
// to instantly add an attacker-controlled contract.
//
//go:wasmexport addAllowedTarget
func AddAllowedTarget(payload *string) *string {
	checkAdmin()
	if payload == nil || *payload == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "target contract id required"))
	}
	currentBlock := sdk.GetEnv().BlockHeight
	if err := mapping.ProposeAllowedTargetAdd(*payload, currentBlock); err != nil {
		ce.CustomAbort(err)
	}
	return mapping.StrPtr("0")
}

// CommitAllowedTarget — promote a pending add to the active allow-list
// once its timelock has elapsed. Permissionless: anyone can poke this
// after the unlock block, so a buggy admin tooling can't silently
// stall promotions.
//
//go:wasmexport commitAllowedTarget
func CommitAllowedTarget(payload *string) *string {
	if payload == nil || *payload == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "target contract id required"))
	}
	currentBlock := sdk.GetEnv().BlockHeight
	committed, unlock, err := mapping.CommitAllowedTarget(*payload, currentBlock)
	if err != nil {
		ce.CustomAbort(err)
	}
	if !committed {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput,
			"add still in timelock; unlocks at block "+strconv.FormatUint(unlock, 10)))
	}
	return mapping.StrPtr("0")
}

// SetAllowedTargetImmediate — REGTEST ONLY: admin promotes a
// target straight into the active allowlist, bypassing the
// AllowListGovernanceTimelockBlocks 7-day cooldown. Refuses on
// mainnet AND on real testnet — only the throwaway regtest harness
// (devnet/CI runs) exposes this. Audit SEC-3 (R15) called out the
// old testnet-or-regtest gate as a footgun: a `dev.wasm` accidentally
// uploaded to mainnet would have admin-bypass intact. Real testnet
// must exercise the same add+commit timelock as mainnet so the
// timelock flow itself gets tested.
//
// Production + testnet allow-list mutations MUST go through the
// symmetric timelock pair (addAllowedTarget + commitAllowedTarget
// after the cooldown elapses).
//
//go:wasmexport setAllowedTargetImmediate
func SetAllowedTargetImmediate(payload *string) *string {
	checkAdmin()
	if !constants.IsRegtest(NetworkMode) {
		ce.CustomAbort(ce.NewContractError(ce.ErrNoPermission,
			"setAllowedTargetImmediate is regtest-only; use addAllowedTarget+commitAllowedTarget"))
	}
	if payload == nil || *payload == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "target contract id required"))
	}
	mapping.SetAllowedTargetImmediate(*payload)
	return mapping.StrPtr("0")
}

// SeedInternalHbd — REGTEST-ONLY admin enabler that directly credits a
// DashDID's contract-internal HBD balance. Used by devnet integration
// tests to pre-fund the op=call sender so dispatchForward's spec §5.2.6
// HBD pre-check (~500 milli-HBD RC reimbursement) doesn't gate the
// forwarder invocation. Without this, the first-time-user case has zero
// internal HBD on the mapping contract and the dispatch returns early
// with StatusForwardFailedInsufficientRC.
//
// Production NEVER hits this path — the production flow funds the
// sender's internal HBD via legitimate DASH→HBD swap deposits or
// transfer flows. The same `constants.IsRegtest(NetworkMode)` gate
// used by SetAllowedTargetImmediate ensures mainnet/testnet builds
// reject the call outright.
//
// Payload format: "<dashDID>,<amountMilliHbd>" — e.g.
// "did:pkh:bip122:00000bafbc94add76cb75e2ec9289483:yExampleAddr,1000".
// Amount is in milli-HBD (1000 milli = 1 HBD). Positive integers only.
//
//go:wasmexport seedInternalHbd
func SeedInternalHbd(payload *string) *string {
	checkAdmin()
	if !constants.IsRegtest(NetworkMode) {
		ce.CustomAbort(ce.NewContractError(ce.ErrNoPermission,
			"seedInternalHbd is regtest-only; production uses legitimate swap/transfer flows"))
	}
	if payload == nil || *payload == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "seed payload required (format: <dashDID>,<amountMilliHbd>)"))
	}
	// Parse "<did>,<amount>" — comma is safe because did:pkh:bip122 has
	// no commas in its grammar.
	idx := strings.Index(*payload, ",")
	if idx < 0 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput,
			"seed payload must be \"<dashDID>,<amountMilliHbd>\""))
	}
	did := (*payload)[:idx]
	amountStr := (*payload)[idx+1:]
	amount, perr := strconv.ParseInt(amountStr, 10, 64)
	if perr != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput,
			"seed amount not a valid int64: "+perr.Error()))
	}
	if did == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "seed did empty"))
	}
	if amount <= 0 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "seed amount must be positive"))
	}
	// Inline state write. Mirrors RegisterPublicKey + setForwarderContractId's
	// pattern of calling sdk.StateSetObject directly from the wasmexport
	// (proven to persist + be queryable via GQL getStateByKeys). The earlier
	// indirection through mapping.SeedInternalHbd → incInternalBalance →
	// setInternalBalance produced ok=true ret="0" on the contract output
	// but no observable state for the resulting "a-hbd/<did>" key — root
	// cause TBD but the direct-write equivalent below sidesteps it.
	//
	// Key shape MUST match mapping/forwarder_integration.go:484's
	// setInternalBalance("hbd", ...) write: "a-hbd/<did>", value is
	// big-endian uint64 with leading zero bytes trimmed.
	key := constants.BalancePrefix + "hbd" + "/" + did
	// Read existing balance + add.
	existingRaw := sdk.StateGetObject(key)
	existing := int64(0)
	if existingRaw != nil && *existingRaw != "" {
		var ebuf [8]byte
		copy(ebuf[8-len(*existingRaw):], *existingRaw)
		existing = int64(binary.BigEndian.Uint64(ebuf[:]))
	}
	newBal := existing + amount
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(newBal))
	pos := 0
	for pos < 7 && buf[pos] == 0 {
		pos++
	}
	sdk.StateSetObject(key, string(buf[pos:]))
	return mapping.StrPtr("0")
}

// CancelAllowedTargetAdd — admin aborts a pending add inside the
// timelock window.
//
//go:wasmexport cancelAllowedTargetAdd
func CancelAllowedTargetAdd(payload *string) *string {
	checkAdmin()
	if payload == nil || *payload == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "target contract id required"))
	}
	mapping.CancelPendingAllowedTargetAdd(*payload)
	return mapping.StrPtr("0")
}

// RemoveAllowedTarget — admin schedules a target for removal from the
// allow-list. Spec §5.2.7 makes removals timelocked symmetrically with
// adds so the community has the same window to react to a hostile
// admin trying to censor a target.
//
//go:wasmexport removeAllowedTarget
func RemoveAllowedTarget(payload *string) *string {
	checkAdmin()
	if payload == nil || *payload == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "target contract id required"))
	}
	currentBlock := sdk.GetEnv().BlockHeight
	if err := mapping.ProposeAllowedTargetRemove(*payload, currentBlock); err != nil {
		ce.CustomAbort(err)
	}
	return mapping.StrPtr("0")
}

// CommitAllowedTargetRemove — promote a pending remove to active once
// the timelock has elapsed. Permissionless.
//
//go:wasmexport commitAllowedTargetRemove
func CommitAllowedTargetRemove(payload *string) *string {
	if payload == nil || *payload == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "target contract id required"))
	}
	currentBlock := sdk.GetEnv().BlockHeight
	committed, unlock, err := mapping.CommitAllowedTargetRemove(*payload, currentBlock)
	if err != nil {
		ce.CustomAbort(err)
	}
	if !committed {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput,
			"remove still in timelock; unlocks at block "+strconv.FormatUint(unlock, 10)))
	}
	return mapping.StrPtr("0")
}

// CancelAllowedTargetRemove — admin aborts a pending removal inside
// the timelock window.
//
//go:wasmexport cancelAllowedTargetRemove
func CancelAllowedTargetRemove(payload *string) *string {
	checkAdmin()
	if payload == nil || *payload == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "target contract id required"))
	}
	mapping.CancelPendingAllowedTargetRemove(*payload)
	return mapping.StrPtr("0")
}

// SetValidatorSet — admin action to record the {validator DID →
// pubkey hex} list for an epoch. Payload format:
//
//	<epoch>;<did1>=<pubkey1>=<pop1>=<account1>|<did2>=<pubkey2>=<pop2>=<account2>|...
//
// pubkey is hex-encoded 48-byte compressed G1 (96 chars). PoP is a
// 96-byte BLS signature hex-encoded (192 chars). account is the
// validator's Hive account name — the value that lib/dids/bls.go's
// GenerateBlsPoP was called with on the announcer side.
//
// Per-validator PoP (proof-of-possession) is mandatory (audit R3-001) —
// the contract verifies each (pubkey, pop) pair via sdk.VerifyBls
// against the canonical BLS-PoP message:
//
//	"VSC-BLS-POP-v1" || pubkey_bytes || account_bytes
//
// matching lib/dids/bls.go's GenerateBlsPoP / VerifyBlsPoP. Without
// PoP, the aggregate verifier is exposed to a rogue-key attack once
// QuorumThreshold rises above 1. Round-4 audit R4-CSM-01 fixed a
// prior account-vs-DID mismatch that bricked the gate.
//
// To produce a payload entry from announcer-format outputs, use the
// utxo-mapping/dash-mapping-contract/cmd/gen-validator-set-payload
// helper. The PoP encoding
// pipeline is:
//
//	popB64, _ := dids.GenerateBlsPoP(privKey, account) // base64 raw-url
//	raw, _   := base64.RawURLEncoding.DecodeString(popB64)
//	popHex   := hex.EncodeToString(raw)                // 192 chars
//
// HandleMapInstantSendV2 reads the persisted set to gate which
// validator attestations are accepted at body.Epoch. Without an
// entry, the fast-path is closed for that epoch.
//
//go:wasmexport setValidatorSet
func SetValidatorSet(payload *string) *string {
	checkAdmin()
	if payload == nil || *payload == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "validator-set payload required"))
	}
	epoch, set, pops, accounts, err := mapping.ParseValidatorSetPayload(*payload)
	if err != nil {
		ce.CustomAbort(err)
	}
	if err := mapping.SaveValidatorSetForEpoch(epoch, set, pops, accounts); err != nil {
		ce.CustomAbort(err)
	}
	return mapping.StrPtr("0")
}

// SetMinAttestations — admin action to configure the N-of-M quorum
// threshold the fast-path enforces. Payload is a decimal int >= 1.
//
//go:wasmexport setMinAttestations
func SetMinAttestations(payload *string) *string {
	checkAdmin()
	if payload == nil || *payload == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "threshold required"))
	}
	n, err := strconv.Atoi(*payload)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "invalid threshold: "+*payload))
	}
	if err := mapping.SaveMinAttestations(n); err != nil {
		ce.CustomAbort(err)
	}
	return mapping.StrPtr("0")
}

// Withdraws BTC from the caller's own balance to a Bitcoin address.
// The `from` field is ignored — unmaps always draw from the caller's balance.
//
//go:wasmexport unmap
func Unmap(tx *string) *string {
	var unmapInstructions mapping.TransferParams
	err := tinyjson.Unmarshal([]byte(*tx), &unmapInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	// Enforce: unmap always uses caller as source
	unmapInstructions.From = ""

	doUnmap(&unmapInstructions)
	return mapping.StrPtr("0")
}

// Withdraws BTC from a third-party account that has approved the caller.
// Requires the `from` account to have set an allowance for the caller via `approve`.
//
//go:wasmexport unmapFrom
func UnmapFrom(tx *string) *string {
	var unmapInstructions mapping.TransferParams
	err := tinyjson.Unmarshal([]byte(*tx), &unmapInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	doUnmap(&unmapInstructions)
	return mapping.StrPtr("0")
}

func doUnmap(instructions *mapping.TransferParams) {
	checkNotPaused()
	if len(instructions.To) < 26 {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, "invalid destination address ["+instructions.To+"]"),
		)
	}

	publicKeys, err := loadPublicKeys()
	if err != nil {
		ce.CustomAbort(err)
	}

	contractState, err := mapping.IntializeContractState(publicKeys, NetworkMode)
	if err != nil {
		ce.CustomAbort(ce.Prepend(err, "error initializing contract state"))
	}

	err = contractState.HandleUnmap(instructions)
	if err != nil {
		ce.CustomAbort(err)
	}
	err = contractState.SaveToState()
	if err != nil {
		ce.CustomAbort(err)
	}
}

// Transfers funds from the Caller (immediate caller of the contract).
// The `from` field is ignored — transfers always draw from the caller's balance.
//
//go:wasmexport transfer
func Transfer(tx *string) *string {
	checkNotPaused()
	var transferInstructions mapping.TransferParams
	err := tinyjson.Unmarshal([]byte(*tx), &transferInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	// Enforce: transfer always uses caller as source
	transferInstructions.From = ""

	err = mapping.HandleTransfer(&transferInstructions)
	if err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

// Draws funds from a third-party account that has approved the caller.
// Requires the `from` account to have set an allowance for the caller via `approve`.
//
//go:wasmexport transferFrom
func TransferFrom(tx *string) *string {
	checkNotPaused()
	var drawInstructions mapping.TransferParams
	err := tinyjson.Unmarshal([]byte(*tx), &drawInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	err = mapping.HandleTransfer(&drawInstructions)
	if err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

// Sets a spending allowance for a spender contract to use the caller's tokens.
//
//go:wasmexport approve
func Approve(input *string) *string {
	checkNotPaused()
	env := sdk.GetEnv()
	var params mapping.AllowanceParams
	err := tinyjson.Unmarshal([]byte(*input), &params)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput))
	}
	if params.Spender == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "spender address required"))
	}
	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "invalid amount value"))
	}
	if amount < 0 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "allowance amount must be non-negative"))
	}
	if params.Spender == env.Caller.String() {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "cannot approve self as spender"))
	}
	mapping.HandleApprove(env.Caller.String(), params.Spender, amount)
	return mapping.StrPtr("0")
}

// Increases the spending allowance for a spender contract.
//
//go:wasmexport increaseAllowance
func IncreaseAllowance(input *string) *string {
	checkNotPaused()
	env := sdk.GetEnv()
	var params mapping.AllowanceParams
	err := tinyjson.Unmarshal([]byte(*input), &params)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput))
	}
	if params.Spender == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "spender address required"))
	}
	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "invalid amount value"))
	}
	if amount <= 0 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "amount must be positive"))
	}
	err = mapping.HandleIncreaseAllowance(env.Caller.String(), params.Spender, amount)
	if err != nil {
		ce.CustomAbort(err)
	}
	return mapping.StrPtr("0")
}

// Decreases the spending allowance for a spender contract.
//
//go:wasmexport decreaseAllowance
func DecreaseAllowance(input *string) *string {
	checkNotPaused()
	env := sdk.GetEnv()
	var params mapping.AllowanceParams
	err := tinyjson.Unmarshal([]byte(*input), &params)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput))
	}
	if params.Spender == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "spender address required"))
	}
	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "invalid amount value"))
	}
	if amount <= 0 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "amount must be positive"))
	}
	err = mapping.HandleDecreaseAllowance(env.Caller.String(), params.Spender, amount)
	if err != nil {
		ce.CustomAbort(err)
	}
	return mapping.StrPtr("0")
}

// Confirms a pending spend transaction by verifying its Merkle inclusion proof,
// then promoting the unconfirmed change UTXOs at the specified output indices
// to the confirmed pool.
//
//go:wasmexport confirmSpend
func ConfirmSpend(input *string) *string {
	checkNotPaused()
	var params mapping.ConfirmSpendParams
	err := tinyjson.Unmarshal([]byte(*input), &params)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput))
	}
	if params.TxData == nil || params.TxData.RawTxHex == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "tx_data.raw_tx_hex required"))
	}

	publicKeys, err := loadPublicKeys()
	if err != nil {
		ce.CustomAbort(err)
	}

	contractState, err := mapping.IntializeContractState(publicKeys, NetworkMode)
	if err != nil {
		ce.CustomAbort(err)
	}

	err = contractState.HandleConfirmSpend(params.TxData, params.Indices)
	if err != nil {
		ce.CustomAbort(err)
	}

	err = contractState.SaveToState()
	if err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

// Pauses all token operations (map, unmap, transfer, approve, confirmSpend).
// Admin/owner operations remain available while paused.
//
//go:wasmexport pause
func Pause(_ *string) *string {
	checkOwner()
	sdk.StateSetObject(constants.PausedKey, "1")
	return mapping.StrPtr("contract paused")
}

// Resumes all token operations after a pause.
//
//go:wasmexport unpause
func Unpause(_ *string) *string {
	checkOwner()
	sdk.StateDeleteObject(constants.PausedKey)
	return mapping.StrPtr("contract unpaused")
}

//go:wasmexport migrate
func Migrate(_ *string) *string {
	checkOwner()

	versionPtr := sdk.StateGetObject(constants.MigrateVersionKey)
	version := ""
	if versionPtr != nil {
		version = *versionPtr
	}

	// --- v1: migrate UTXO registry from 9-byte (uint8 ID + int64) to 8-byte
	// (uint16 ID + uint48) entries, and counter from 2 bytes to 4 bytes.
	// Old confirmed pool: 64–255 → new: 1024–65535 (offset +960).
	// Old unconfirmed pool: 0–63 → unchanged (0–1023 range, same IDs).
	// Individual UTXO blobs (u-<id>) are re-keyed to match the new hex IDs.
	if version < "1" {
		// Read old-format registry (9 bytes/entry: 1-byte ID + 8-byte amount BE)
		regRaw := sdk.StateGetObject(constants.UtxoRegistryKey)
		if regRaw != nil && len(*regRaw) > 0 {
			oldData := []byte(*regRaw)
			if len(oldData)%9 == 0 {
				entryCount := len(oldData) / 9
				newRegistry := make(mapping.UtxoRegistry, entryCount)
				for i := 0; i < entryCount; i++ {
					oldId := uint16(oldData[i*9])
					amount := int64(uint64(oldData[i*9+1])<<56 | uint64(oldData[i*9+2])<<48 |
						uint64(oldData[i*9+3])<<40 | uint64(oldData[i*9+4])<<32 |
						uint64(oldData[i*9+5])<<24 | uint64(oldData[i*9+6])<<16 |
						uint64(oldData[i*9+7])<<8 | uint64(oldData[i*9+8]))

					// Map old ID to new ID
					newId := oldId
					if oldId >= constants.OldUtxoConfirmedPoolStart {
						newId = oldId - constants.OldUtxoConfirmedPoolStart + constants.UtxoConfirmedPoolStart
					}
					newRegistry[i] = mapping.UtxoRegistryEntry{Id: newId, Amount: amount}

					// Re-key the UTXO blob: copy from old key to new key, delete old
					oldKey := constants.UtxoPrefix + strconv.FormatUint(uint64(oldId), 16)
					newKey := constants.UtxoPrefix + strconv.FormatUint(uint64(newId), 16)
					if oldKey != newKey {
						blob := sdk.StateGetObject(oldKey)
						if blob != nil && *blob != "" {
							sdk.StateSetObject(newKey, *blob)
							sdk.StateDeleteObject(oldKey)
						}
					}
				}
				// Write new-format registry (8 bytes/entry)
				sdk.StateSetObject(constants.UtxoRegistryKey, string(mapping.MarshalUtxoRegistry(newRegistry)))
			}
		}

		// Migrate counter from 2 bytes [uint8, uint8] to 4 bytes [uint16 BE, uint16 BE]
		counterRaw := sdk.StateGetObject(constants.UtxoLastIdKey)
		if counterRaw != nil && len(*counterRaw) == 2 {
			oldBytes := []byte(*counterRaw)
			oldConfirmed := uint16(oldBytes[0])
			oldUnconfirmed := uint16(oldBytes[1])

			newConfirmed := oldConfirmed
			if oldConfirmed >= constants.OldUtxoConfirmedPoolStart {
				newConfirmed = oldConfirmed - constants.OldUtxoConfirmedPoolStart + constants.UtxoConfirmedPoolStart
			}

			var buf [4]byte
			buf[0] = byte(newConfirmed >> 8)
			buf[1] = byte(newConfirmed)
			buf[2] = byte(oldUnconfirmed >> 8)
			buf[3] = byte(oldUnconfirmed)
			sdk.StateSetObject(constants.UtxoLastIdKey, string(buf[:]))
		}

		sdk.StateSetObject(constants.MigrateVersionKey, "1")
		sdk.Log("migrate|v=1")
	}

	// --- future migrations go here ---

	result := "migrated to v" + *sdk.StateGetObject(constants.MigrateVersionKey)
	return &result
}

//go:wasmexport getInfo
func GetInfo(_ *string) *string {
	return mapping.StrPtr(`{"name":"Dash","symbol":"DASH","decimals":"8"}`)
}

func loadPublicKeys() (mapping.PublicKeys, error) {
	primaryRaw := *sdk.StateGetObject(constants.PrimaryPublicKeyStateKey)
	if primaryRaw == "" {
		return mapping.PublicKeys{}, ce.NewContractError(ce.ErrInitialization, "no registered public key")
	}
	backupRaw := *sdk.StateGetObject(constants.BackupPublicKeyStateKey)

	var keys mapping.PublicKeys
	if len(primaryRaw) != 33 {
		return keys, ce.NewContractError(ce.ErrInitialization, "stored primary key is not 33 bytes")
	}
	copy(keys.Primary[:], primaryRaw)
	if len(backupRaw) != 33 {
		return keys, ce.NewContractError(ce.ErrInitialization, "stored backup key is not 33 bytes")
	}
	copy(keys.Backup[:], backupRaw)
	return keys, nil
}

func validateAndDecodeKey(keyHex string) (mapping.CompressedPubKey, error) {
	key, err := mapping.DecodeCompressedPubKey(keyHex)
	if err != nil {
		return key, ce.WrapContractError(ce.ErrInput, err, "invalid compressed public key")
	}
	return key, nil
}

//go:wasmexport registerPublicKey
func RegisterPublicKey(keyStr *string) *string {
	env := sdk.GetEnv()
	// leave this as owner always
	if env.Caller.String() != *sdk.GetEnvKey("contract.owner") {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "action must be performed by the contract owner"),
		)
	}

	var keys mapping.RegisterKeyParams
	err := tinyjson.Unmarshal([]byte(*keyStr), &keys)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	var resultBuilder strings.Builder

	if keys.PrimaryPubKey != "" {
		key, err := validateAndDecodeKey(keys.PrimaryPubKey)
		if err != nil {
			ce.CustomAbort(ce.Prepend(err, "error registering primary public key"))
		}
		existingPrimary := sdk.StateGetObject(constants.PrimaryPublicKeyStateKey)
		// Bridge pubkey overwrite is regtest-only (audit SEC-3 R15).
		// Real testnet uses the same once-and-immutable model as
		// mainnet so the rotation flow (TODO: spec) gets exercised.
		if *existingPrimary == "" || constants.IsRegtest(NetworkMode) {
			sdk.StateSetObject(constants.PrimaryPublicKeyStateKey, string(key[:]))
			resultBuilder.WriteString("set primary key to: " + keys.PrimaryPubKey)
		} else {
			resultBuilder.WriteString("primary key already registered: " + hex.EncodeToString([]byte(*existingPrimary)))
		}
	}

	if keys.BackupPubKey != "" {
		key, err := validateAndDecodeKey(keys.BackupPubKey)
		if err != nil {
			ce.CustomAbort(ce.Prepend(err, "error registering backup public key"))
		}
		if resultBuilder.Len() > 0 {
			resultBuilder.WriteString(", ")
		}
		existingBackup := sdk.StateGetObject(constants.BackupPublicKeyStateKey)
		// Bridge pubkey overwrite is regtest-only (audit SEC-3 R15).
		if *existingBackup == "" || constants.IsRegtest(NetworkMode) {
			sdk.StateSetObject(constants.BackupPublicKeyStateKey, string(key[:]))
			resultBuilder.WriteString("set backup key to: " + keys.BackupPubKey)
		} else {
			resultBuilder.WriteString("backup key already registered: " + hex.EncodeToString([]byte(*existingBackup)))
		}
	}

	return mapping.StrPtr(resultBuilder.String())
}

//go:wasmexport createKey
func CreateKey(_ *string) *string {
	// leave this as owner always
	if sdk.GetEnv().Caller.String() != *sdk.GetEnvKey("contract.owner") {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "action must be performed by the contract owner"),
		)
	}

	keyId := constants.TssKeyName
	sdk.TssCreateKey(keyId, "ecdsa", 365)
	return mapping.StrPtr("key created, id: " + keyId)
}

//go:wasmexport renewKey
func RenewKey(_ *string) *string {
	// leave this as owner always
	if sdk.GetEnv().Caller.String() != *sdk.GetEnvKey("contract.owner") {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "action must be performed by the contract owner"),
		)
	}

	keyId := constants.TssKeyName
	sdk.TssRenewKey(keyId, 365)
	return mapping.StrPtr("key \"" + keyId + "\" renewed")
}

//go:wasmexport registerRouter
func RegisterRouter(input *string) *string {
	env := sdk.GetEnv()
	// leave this as owner always
	if env.Caller.String() != *sdk.GetEnvKey("contract.owner") {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "action must be performed by the contract owner"),
		)
	}

	var router mapping.RouterContract
	err := tinyjson.Unmarshal([]byte(*input), &router)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	var resultBuilder strings.Builder

	if router.ContractId != "" {
		existingPrimary := sdk.StateGetObject(constants.RouterContractIdKey)
		// Router overwrite is regtest-only (audit SEC-3 R15).
		if *existingPrimary == "" || constants.IsRegtest(NetworkMode) {
			sdk.StateSetObject(constants.RouterContractIdKey, router.ContractId)
			resultBuilder.WriteString("set router contract ID to: " + router.ContractId)
		} else {
			resultBuilder.WriteString("router contract ID already registered: " + *existingPrimary)
		}
	}

	return mapping.StrPtr(resultBuilder.String())
}
