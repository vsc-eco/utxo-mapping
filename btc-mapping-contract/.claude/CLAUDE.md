# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

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

Always use Docker-based compilation (consistent output):

```bash
USE_DOCKER=1 make dev
```

## Architecture

This is a **TinyGo WASM smart contract** that maps Bitcoin UTXOs to Magi/VSC Network. It compiles to WebAssembly via TinyGo and runs on the VSC contract runtime. This runtime deploys a Virtual Machine where the contract runs. There is no garbage collector in this runtime, the whole Virtual Machine is torn down after execution. Avoid excessive heap allocation.

### Contract Modules

**`contract/main.go`** — WASM entry point. Exports functions via `//go:wasmexport` and routes calls to handlers. Key exported actions: `map`, `unmap`, `transfer`, `transferFrom`, `addBlocks`, `seedBlocks`, `registerPublicKey`, `createKeyPair`.

**`contract/mapping/`** — Core logic. `handlers.go` handles `map`/`unmap` actions. `mapping.go` processes UTXOs and indexes addresses. `utils.go` builds P2WSH addresses with backup spending paths (CSV timelock). `proof.go` verifies Bitcoin Merkle inclusion proofs. `init.go` loads contract state from storage.

**`contract/blocklist/`** — Stores and validates Bitcoin block headers. Validates header chain continuity before appending.

**`contract/constants/constants.go`** — All state storage key prefixes and contract-wide constants.

**`contract/contracterrors/`** — Structured error type (`ContractError`) with `CustomAbort()` to revert transactions.

**`sdk/`** — WASM runtime bindings for state I/O (`StateSetObject`/`StateGetObject`), environment (`GetEnv` for caller/auth), and TSS signing.

### State Storage Keys

| Key                    | Content                                                    |
| ---------------------- | ---------------------------------------------------------- |
| `utxor`                | UTXO registry (JSON array of `[id, vout, amount]`)         |
| `utxo/<id>`            | Individual UTXO data                                       |
| `txspdr`               | Spent transaction IDs registry                             |
| `sply`                 | Supply tracking (`active`, `user`, `fee`, `base_fee_rate`) |
| `block/<height>`       | 80-byte block header (hex)                                 |
| `lsthgt`               | Last known block height                                    |
| `pubkey` / `backupkey` | ECDSA public keys for TSS                                  |
| `routerid`             | Router contract ID                                         |
| `bal/<address>`        | Account balance in satoshis                                |

### Key Design Patterns

- **Map flow**: Incoming BTC tx → Merkle proof verification against stored block headers → UTXO indexed → instruction-based routing to VSC destination (URL-encoded params like `deposit_to`, `swap_to`)
- **Unmap flow**: Build withdrawal tx → calculate fee from `base_fee_rate * tx_size` → TSS sign → broadcast
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
