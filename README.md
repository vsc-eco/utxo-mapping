# UTXO Mapping Contracts

Smart contracts for mapping UTXO-based cryptocurrency deposits to VSC (Vite Smart Contracts) balances.

## Supported Chains

- **BTC** — Bitcoin
- **LTC** — Litecoin
- **DASH** — Dash
- **DOGE** — Dogecoin
- **BCH** — Bitcoin Cash

## How It Works

Each contract verifies on-chain deposit proofs (SPV via merkle inclusion) and credits the depositor's VSC account with a wrapped token balance. Withdrawals (unmapping) construct and sign Bitcoin-style transactions via TSS, returning funds to the user's native chain address.

## Key Features

- SPV proof verification (block header + merkle proof)
- UTXO tracking (confirmed and unconfirmed pools)
- Allowance-based token spending (approve / transferFrom)
- DEX integration via Router contract calls
- Blocklist support for sanctioned addresses
- Multi-signature withdrawal signing via TSS oracle

## Building

Contracts are compiled with TinyGo targeting WASM:

```bash
cd <chain>-mapping-contract
make build
```

## Testing

```bash
cd <chain>-mapping-contract
go test ./tests/current/...
```
