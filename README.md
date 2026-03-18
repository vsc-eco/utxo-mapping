# UTXO Mapping Contracts

TinyGo WASM smart contracts that bridge UTXO-based blockchains to the VSC/Magi network.

## Supported Chains

| Chain | Block Time | CSV Timelock | Asset | Tests |
|-------|-----------|--------------|-------|-------|
| BTC   | 10 min    | 4320 blocks  | BTC   | 53    |
| LTC   | 2.5 min   | 17280 blocks | LTC   | 60    |
| DASH  | 2.5 min   | 17280 blocks | DASH  | 60    |
| DOGE  | 1 min     | 43200 blocks | DOGE  | 53    |
| BCH   | 10 min    | 4320 blocks  | BCH   | 53    |

All CSV timelocks target ~30 days. BTC is the reference implementation; others are kept in sync via `sync-tests.sh`.

## How It Works

Each contract verifies on-chain deposit proofs (SPV via merkle inclusion) and credits the depositor's VSC account with a wrapped token balance. Withdrawals (unmapping) construct and sign Bitcoin-style transactions via TSS, returning funds to the user's native chain address.

## Key Features

- SPV proof verification (block header + merkle proof)
- UTXO tracking (confirmed pool 64-255, unconfirmed pool 0-63)
- ERC-20 style allowances (approve / transferFrom / increaseAllowance / decreaseAllowance)
- DEX integration via Router contract calls (map → swap in one tx)
- Double-spend protection via observed UTXO markers
- Multi-signature withdrawal signing via TSS
- Address validation via `system.verify_address` runtime import

## Contract Actions (13 per chain)

| Action | Description |
|--------|-------------|
| `map` | Process incoming UTXO deposit with merkle proof |
| `unmap` | Initiate withdrawal to external chain |
| `transfer` | Transfer mapped tokens between VSC addresses |
| `transferFrom` | Transfer with ERC-20 style allowance |
| `approve` | Set spending allowance for a spender |
| `increaseAllowance` / `decreaseAllowance` | Modify existing allowance |
| `confirmSpend` | Confirm a withdrawal tx was broadcast (admin) |
| `seedBlocks` / `addBlocks` | Initialize and extend block header chain (admin) |
| `registerPublicKey` | Set TSS primary/backup keys (admin) |
| `createKeyPair` | Request new TSS key pair (admin) |
| `registerRouter` | Set the DEX router contract ID (admin) |

## Building

```bash
cd <chain>-mapping-contract

# Build WASM for dev/regtest
USE_DOCKER=1 make dev

# Build for mainnet
USE_DOCKER=1 make mainnet
```

## Testing

```bash
# Run all tests for one chain
cd <chain>-mapping-contract
make test

# Run a single test
make test FILTER=TestDoubleMapSameUtxo

# Run all 5 chains
cd /home/dockeruser/magi_contract_refactor
./run-tests.sh mapping
```

## Sync Tests Across Chains

After editing tests in `btc-mapping-contract`:

```bash
bash sync-tests.sh
```

This copies test files to all other chains, replacing only the module import path.
