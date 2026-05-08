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

**Map Log** — emitted once per UTXO processed

| Parameter | Key        | Type   | Description                            |
| --------- | ---------- | ------ | -------------------------------------- |
| Type      | Positional | string | Operation type. Always `map`           |
| To        | `t`        | string | Destination account in Magi did format |
| From      | `f`        | string | Source BTC address (or `many`)         |
| Amount    | `a`        | string | Amount in SATS                         |

---

### 4. `unmap` — Withdraw BTC (from Caller)

Withdraws mapped BTC from the caller's own balance to a Bitcoin address. The `from` field is ignored — unmaps always draw from the caller's balance. When `deduct_fee` is set, fees are subtracted from the amount rather than added on top. The optional `max_fee` field reverts the transaction if the total fee exceeds the specified cap.

All validation checks (max_fee, balance) are performed before TSS signing is requested.

#### Input

[`TransferParams`](./instruction-schema.md#4-transferparams) — only `amount`, `to`, `deduct_fee`, and `max_fee` are used.

---

### 4b. `unmapFrom` — Withdraw BTC (from "From")

Withdraws mapped BTC from a third-party account that has approved the caller. The `from` account must have a sufficient allowance for the caller. Otherwise identical to `unmap`.

#### Input

[`TransferParams`](./instruction-schema.md#4-transferparams) — `from` is required.

#### Logs

**Fee Log**

| Parameter | Key        | Type   | Description                                                 |
| --------- | ---------- | ------ | ----------------------------------------------------------- |
| Type      | Positional | string | Operation type, always `fee`                                |
| Magi Fee  | `m`        | string | Fee taken by the Magi protocol in SATS                      |
| BTC Fee   | `b`        | string | Fee required to send the transaction on BTC mainnet in SATS |

**Unmap Log**

| Parameter | Key        | Type   | Description                                         |
| --------- | ---------- | ------ | --------------------------------------------------- |
| Type      | Positional | string | Operation type, always `unmap`                      |
| Tx ID     | `id`       | string | The Bitcoin transaction ID of the withdrawal        |
| From      | `f`        | string | Account that funds were deducted from               |
| To        | `t`        | string | Destination BTC address                             |
| Deducted  | `d`        | string | Total amount deducted from the sender's balance     |
| Sent      | `s`        | string | Amount actually sent to the destination BTC address |

---

### 5. `transfer` — Transfer Funds (from Caller)

Transfers funds sourced from the **immediate caller** of the contract — typically another contract in a contract-to-contract call chain. The `from` field is ignored and always resolved to the caller. Uses the same input schema as `unmap` (only `amount` and `to` are used).

#### Input

[`TransferParams`](./instruction-schema.md#4-transferparams) — only `amount` and `to` are used.

#### Logs

**Transfer Log**

| Parameter | Key        | Type   | Description                            |
| --------- | ---------- | ------ | -------------------------------------- |
| Type      | Positional | string | Operation type, always `xfer`          |
| From      | `f`        | string | Source account                         |
| To        | `t`        | string | Destination account                    |
| Amount    | `a`        | string | Amount in SATS                         |

---

### 6. `transferFrom` — Transfer Funds (from "From")

Transfers funds sourced from the account specified, rather than the immediate caller.
The `from` account must have a sufficient allowance for the caller. The allowance is decremented by the transfer amount.

#### Input

[`TransferParams`](./instruction-schema.md#4-transferparams) — `from` is required.

#### Logs

Same as `transfer`.

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

### 9. `approve` — Set Spending Allowance

Sets the spending allowance for a spender to use the caller's tokens. The caller is the owner. Cannot approve self as spender.

#### Input

[`AllowanceParams`](./instruction-schema.md#7-allowanceparams)

---

### 10. `increaseAllowance` — Increase Spending Allowance

Increases the spender's existing allowance by the specified amount. Amount must be positive.

#### Input

[`AllowanceParams`](./instruction-schema.md#7-allowanceparams)

---

### 11. `decreaseAllowance` — Decrease Spending Allowance

Decreases the spender's existing allowance by the specified amount. Reverts if the result would go below zero. Amount must be positive.

#### Input

[`AllowanceParams`](./instruction-schema.md#7-allowanceparams)

---

### 12. `confirmSpend` — Confirm a Pending Spend Transaction

Permissionless. Verifies a Bitcoin spend transaction's Merkle inclusion proof against stored block headers, then promotes unconfirmed change UTXOs at the specified output indices to the confirmed pool. Cleans up the pending signing data for the transaction.

#### Input

[`ConfirmSpendParams`](./instruction-schema.md#8-confirmspendparams)

---

### 13. `getInfo` — Get Token Metadata

Permissionless. Returns static token metadata. No input required.

#### Output

```json
{"name": "Bitcoin", "symbol": "BTC", "decimals": "8"}
```

---

### 14. `createKey` — Create TSS Key

Owner-only. Triggers the creation of a new threshold signature scheme (TSS) ECDSA key inside the contract runtime. The input is ignored.

#### Input

Pass `null` or an empty object `{}`. No fields are read.

---

### 15. `renewKey` — Renew TSS Key

Owner-only. Renews the existing TSS key. The input is ignored.

#### Input

Pass `null` or an empty object `{}`. No fields are read.

---

### 16. `initPruning` — Initialize Block Header Pruning

Owner-only. Sets the prune floor for contracts deployed before pruning was added. Must be called once after a code upgrade. The floor should be the original seed height. After this, `addBlocks` will automatically prune old headers. Cannot be called again once set.

#### Input

Block height as an integer string (e.g. `"116087"`).

---

### 17. `prune` — Prune Old Block Headers

Admin-only. Removes old block headers beyond the retention window. Can be called independently of `addBlocks` to reduce state size.

#### Input

Pass `null` or an empty object `{}`. No fields are read.

---

### 18. `replaceBlock` — Replace a Block Header

Admin-only. Replaces a single block header. Input is the raw 80-byte block header encoded as a hex string (160 hex characters).

#### Input

Raw block header hex string (exactly 80 bytes / 160 hex characters).

---

## Notes

- **Admin vs Owner**: `seedBlocks`, `addBlocks`, `replaceBlock`, and `prune` require the _admin_ (the contract owner on testnet, a fixed oracle address on mainnet). `registerPublicKey`, `registerRouter`, `createKey`, `renewKey`, and `initPruning` always require the _contract owner_ regardless of network mode.
- **Immutability on mainnet**: Public keys and the router contract ID cannot be overwritten once set on mainnet. Attempts to re-register will return the existing value without error.
- **`omitempty` fields** (`from`, `deduct_fee`, `max_fee`, `primary_public_key`, `backup_public_key`) are excluded from `required` and will be absent in serialized output when empty or zero.
- **Public key validation**: Hex strings passed to `registerPublicKey` must decode to exactly 33 bytes. Compressed keys must begin with `0x02` or `0x03`.
