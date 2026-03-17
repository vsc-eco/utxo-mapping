# BTC Mapping Contract — Actions

Overview of all actions implemented by the BTC mapping contract, including descriptions,
inputs, outputs, and logs.

All logs are designed to be parsed by the
[magi-mongo-indexer](https://github.com/vsc-eco/magi-mongo-indexer), using "|", "=", and
"," as the log, key, and array delimiters, respectively.

**Example**

```
<type>|<key>=<value>|<key>=<value>|...
```

---

## Operations

### 1. `seedBlocks` — Seed Initial Block Headers

Admin-only. Seeds the contract's block list with an initial block header and height, establishing the starting chain state. Requires the sender to be the contract administrator. On mainnet, this can only be called once, requiring all subsequent blocks to be added in order.

#### Input

[`SeedBlocksParams`](./instruction-schema.md#1-seedblocksparams)

---

### 2. `addBlocks` — Append Block Headers

Admin-only. Appends one or more new block headers to the contract's on-chain block list and updates the stored base fee rate. Requires the sender to be the contract administrator.

#### Input

[`AddBlocksParams`](./instruction-schema.md#2-addblocksparams)

---

### 3. `map` — Map an Incoming BTC Transaction

Verifies an incoming Bitcoin transaction against the stored block headers and processes the attached routing instructions. No caller authentication is required — the Merkle proof embedded in `tx_data` serves as the proof of inclusion.

#### Input

[`MapParams`](./instruction-schema.md#3-mapparams)

#### Logs

**Deposit Log**

| Parameter | Key        | Type   | Description                            |
| --------- | ---------- | ------ | -------------------------------------- |
| Type      | Positional | string | Operation type. Always "deposit"       |
| From      | `f`        | string | Source account in Magi did format      |
| To        | `t`        | string | Destination account in Magi did format |
| Amount    | `a`        | string | Amount in SATS                         |

---

### 4. `unmap` — Withdraw BTC (Unmap)

Initiates a withdrawal of mapped BTC back to a Bitcoin address by constructing and signing an outbound transaction. Requires a valid registered public key to be present in contract state.

#### Input

[`TransferParams`](./instruction-schema.md#4-transferparams)

#### Logs

**Fee Log**

| Parameter | Key        | Type   | Description                                                 |
| --------- | ---------- | ------ | ----------------------------------------------------------- |
| Type      | Positional | string | Operation type, always "fee"                                |
| Magi Fee  | `magi`     | string | Fee taken by the Magi protocol in SATS                      |
| BTC Fee   | `btc`      | string | Fee required to send the transaction on BTC mainnet in SATS |

---

### 5. `transfer` — Transfer Funds (from Caller)

Transfers funds sourced from the **immediate caller** of the contract — typically another contract in a contract-to-contract call chain. Uses the same input schema as `unmap`.

#### Input

[`TransferParams`](./instruction-schema.md#4-transferparams)

---

### 6. `transferFrom` — Transfer Funds (from "From")

Transfers funds sourced from the account specified, rather than the immediate caller.
The `from` field is required for this action.

#### Input

[`TransferParams`](./instruction-schema.md#4-transferparams)

---

### 7. `registerPublicKey` — Register ECDSA Public Key(s)

Owner-only. Registers the primary and/or backup ECDSA public keys used to verify and sign Bitcoin transactions. On mainnet, keys can only be set once and cannot be overwritten. On testnet, re-registration is permitted.

#### Input

[`PublicKeys`](./instruction-schema.md#5-publickeys)

---

### 8. `registerRouter` — Register Router Contract

Owner-only. Registers the ID of the router contract that decoded `map` instructions will be forwarded to. On mainnet, can only be set once. On testnet, re-registration is permitted.

#### Input

[`RouterContract`](./instruction-schema.md#6-routercontract)

---

### 9. `createKeyPair` — Create TSS Key Pair

Owner-only. Triggers the creation of a new threshold signature scheme (TSS) ECDSA key pair inside the contract runtime. The input is ignored entirely.

#### Input

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": ["object", "null"]
}
```

Pass `null` or an empty object `{}`. No fields are read.

---

## Notes

- **Admin vs Owner**: `seedBlocks` and `addBlocks` require the _admin_ (the contract owner on testnet, a fixed oracle address on mainnet). `registerPublicKey`, `registerRouter`, and `createKeyPair` always require the _contract owner_ regardless of network mode.
- **Immutability on mainnet**: Public keys and the router contract ID cannot be overwritten once set on mainnet. Attempts to re-register will return the existing value without error.
- **`omitempty` fields** (`from`, `primary_public_key`, `backup_public_key`) are excluded from `required` and will be absent in serialized output when empty or zero.
- **Public key validation**: Hex strings passed to `registerPublicKey` must decode to exactly 33 or 65 bytes. Compressed keys (33 bytes) must begin with `0x02` or `0x03`.
