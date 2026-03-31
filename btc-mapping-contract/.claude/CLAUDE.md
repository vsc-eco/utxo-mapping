# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Convention

**IMPORTANT**: Never run `go build`, `go vet`, `go run`, or any direct Go toolchain commands in this repo. This is a TinyGo WASM project — standard Go toolchain commands fail or give misleading errors.

Always use `make` targets:

```bash
make dev          # Build WASM for testnet4 (default dev target)
make testnet3     # Build for Bitcoin testnet3
make testnet4     # Build for Bitcoin testnet4
make mainnet      # Build for mainnet
make strip        # Strip built WASM with wasm-tools
make tinyjson     # Regenerate TinyJSON marshalers for //tinyjson:json structs
make test         # Run all tests (cd tests/current && go test -v)
make clean        # Remove all .wasm files
```

Run a single test:

```bash
make test FILTER=<test_name>
```

Make all targets besides "test" with USE_DOCKER=1

```bash
USE_DOCKER=1 make dev
```

## Architecture

This is a **TinyGo WASM smart contract** that maps Bitcoin UTXOs to Magi/VSC Network. It compiles to WebAssembly via TinyGo and runs on the VSC contract runtime. This runtime deploys a Virtual Machine where the contract runs. There is no garbage collector in this runtime, the whole Virtual Machine is torn down after execution. Avoid excessive heap allocation.

### Contract Modules

**`contract/main.go`** — WASM entry point. Exports functions via `//go:wasmexport` and routes calls to handlers. Key exported actions: `map`, `unmap`, `unmapFrom`, `transfer`, `transferFrom`, `approve`, `increaseAllowance`, `decreaseAllowance`, `addBlocks`, `seedBlocks`, `registerPublicKey`, `createKey`, `renewKey`, `registerRouter`, `confirmSpend`, `getInfo`, `initPruning`, `prune`, `replaceBlock`.

**`contract/mapping/`** — Core logic. `handlers.go` handles `map`/`unmap` actions. `mapping.go` processes UTXOs and indexes addresses. `utils.go` builds P2WSH addresses with backup spending paths (CSV timelock). `proof.go` verifies Bitcoin Merkle inclusion proofs. `init.go` loads contract state from storage.

**`contract/blocklist/`** — Stores and validates Bitcoin block headers. Validates header chain continuity before appending.

**`contract/constants/constants.go`** — All state storage key prefixes and contract-wide constants.

**`contract/contracterrors/`** — Structured error type (`ContractError`) with `CustomAbort()` to revert transactions.

**`sdk/`** — WASM runtime bindings for state I/O (`StateSetObject`/`StateGetObject`), environment (`GetEnv` for caller/auth), and TSS signing.

### State Storage Keys

Keys are defined in `contract/constants/constants.go`. The separator between prefix and key segment is `-` (i.e., `DirPathDelimiter = "-"`).

| Constant                    | Key pattern                    | Content                                                         |
| --------------------------- | ------------------------------ | --------------------------------------------------------------- |
| `BalancePrefix`             | `a-<address>`                  | Account balance in satoshis (compact big-endian int64, 1–8 B)  |
| `AllowancePrefix`           | `q-<owner>-<spender>`          | ERC-20-style spending allowance (compact big-endian int64)     |
| `ObservedPrefix`            | `o-<txid>:<vout>`              | Observed tx marker (value `"1"`)                                |
| `UtxoPrefix`                | `u-<hex_id>`                   | Individual UTXO binary blob                                     |
| `UtxoRegistryKey`           | `r`                            | UTXO registry (packed 9 bytes/entry: 1-byte ID + 8-byte amount) |
| `UtxoLastIdKey`             | `i`                            | 2 bytes: `[confirmedNextId, unconfirmedNextId]`                 |
| `TxSpendsRegistryKey`       | `p`                            | Tx spends registry (32 bytes/entry)                             |
| `TxSpendsPrefix`            | `d-<txid>`                     | Signing data for pending withdrawal (msgpack)                   |
| `SupplyKey`                 | `s`                            | 32 bytes: 4× int64 BE (`active`, `user`, `fee`, `base_fee_rate`) |
| `LastHeightKey`             | `h`                            | Last known block height (decimal string)                        |
| `BlockPrefix`               | `b-<height>`                   | 80-byte raw Bitcoin block header                                |
| `PrimaryPublicKeyStateKey`  | `pubkey`                       | TSS primary compressed public key (33 bytes)                    |
| `BackupPublicKeyStateKey`   | `backupkey`                    | TSS backup compressed public key (33 bytes)                     |
| `RouterContractIdKey`       | `routerid`                     | Router contract ID (string)                                     |

### Exported Action Schemas

#### Token operations

| Action | Params | Auth | Description |
|--------|--------|------|-------------|
| `map` | `MapParams{tx_data, instructions}` | None (permissionless, requires valid Merkle proof) | Deposit BTC into the contract via SPV proof |
| `unmap` | `TransferParams{amount, to, deduct_fee?, max_fee?}` | Active auth required | Withdraw BTC from caller's balance. `from` is ignored. `deduct_fee` deducts fees from amount instead of adding on top. `max_fee` (sats) reverts if total fee exceeds limit |
| `unmapFrom` | `TransferParams{amount, to, from, deduct_fee?, max_fee?}` | Active auth required | Withdraw BTC from a third-party account with sufficient allowance |
| `transfer` | `TransferParams{amount, to}` | Active auth required | Transfer mapped balance to another VSC account. `from` is ignored (always uses caller) |
| `transferFrom` | `TransferParams{amount, to, from}` | Active auth required | Transfer from a third-party account that has approved the caller |
| `approve` | `AllowanceParams{spender, amount}` | Caller is owner | Set spending allowance for a spender |
| `increaseAllowance` | `AllowanceParams{spender, amount}` | Caller is owner | Increase existing allowance |
| `decreaseAllowance` | `AllowanceParams{spender, amount}` | Caller is owner | Decrease existing allowance |
| `confirmSpend` | `ConfirmSpendParams{tx_data, indices}` | None (permissionless, requires valid Merkle proof) | Promote unconfirmed change UTXOs to confirmed pool |
| `getInfo` | — | None | Returns `{"name":"Bitcoin","symbol":"BTC","decimals":"8"}` |

#### Admin/owner operations

| Action | Params | Auth | Description |
|--------|--------|------|-------------|
| `seedBlocks` | `SeedBlocksParams{block_header, block_height}` | Admin | Seed initial block header |
| `addBlocks` | `AddBlocksParams{blocks, latest_fee}` | Admin | Append block headers, update base fee rate |
| `replaceBlock` | Raw 80-byte block header hex | Admin | Replace a single block header |
| `initPruning` | Block height string | Owner | Set prune floor for old block headers |
| `prune` | — | Admin | Remove old block headers beyond retention window |
| `registerPublicKey` | `RegisterKeyParams{primary_public_key?, backup_public_key?}` | Owner | Register TSS public keys |
| `createKey` | — | Owner | Create a new TSS key |
| `renewKey` | — | Owner | Renew the TSS key |
| `registerRouter` | `RouterContract{router_contract}` | Owner | Register the DEX router contract ID |

### Key Design Patterns

- **Map flow**: Incoming BTC tx → Merkle proof verification against stored block headers → UTXO indexed → instruction-based routing to VSC destination (URL-encoded params like `deposit_to`, `swap_to`, `destination_chain`)
- **Unmap flow**: Build withdrawal tx → calculate fee from `base_fee_rate * tx_size` → all checks (max_fee, balance, allowance) → TSS sign → broadcast
- **Address generation**: P2WSH with backup path using OP_CHECKSEQUENCEVERIFY (CSV timelock)
- **Admin vs Owner**: Admin is contract owner on testnet, fixed oracle address on mainnet; owner always equals deployer
- **Network mode** injected at compile time via ldflags: `main.NetworkMode`

### WASM Constraints

TinyGo/WASM environment restrictions (enforced throughout contract code):

- No goroutines, channels, or `defer`
- No panic recovery — panics halt execution
- Must import SDK package or build fails
- JSON serialization uses TinyJSON (not `encoding/json`) — run `make tinyjson` after adding `//tinyjson:json` struct tags

### Tests

Tests live in `tests/current/` and use the `vsc-node/lib/test_utils.ContractTest` framework with real Bitcoin block headers and transactions as fixtures. The local vsc-node dependency is replaced in `go.mod` to point at a sibling directory (`../../milo-go-vsc-node/`).
