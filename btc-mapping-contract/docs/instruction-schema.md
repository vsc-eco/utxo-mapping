# BTC Mapping Contract — Instruction Schema

The instruction schema uses snake_case field names and follows JSON Schema Draft 2020-12.

### 1. `SeedBlocksParams`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/SeedBlocksParams",
  "$defs": {
    "SeedBlocksParams": {
      "type": "object",
      "required": ["block_header", "block_height"],
      "properties": {
        "block_header": { "type": "string" },
        "block_height": {
          "type": "integer",
          "minimum": 0,
          "maximum": 4294967295
        }
      }
    }
  }
}
```

#### Field Descriptions

**Required Fields**

- **`block_header`** (string): Raw block header data for the seed block, represented in hex.
- **`block_height`** (integer): The block height corresponding to the provided header. Must fit within `uint32` range (0–4,294,967,295).

---

### 2. `AddBlocksParams`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/AddBlocksParams",
  "$defs": {
    "AddBlocksParams": {
      "type": "object",
      "required": ["blocks", "latest_fee"],
      "properties": {
        "blocks": { "type": "string" },
        "latest_fee": { "type": "integer" }
      }
    }
  }
}
```

#### Field Descriptions

**Required Fields**

- **`blocks`** (string): Concatenated raw block header bytes, which the contract parses and divides into individual headers internally.
- **`latest_fee`** (integer): The current Bitcoin base fee rate (e.g. sat/vByte) to persist in contract state. Updated after blocks are added.

---

### 3. `MapParams`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/MapParams",
  "$defs": {
    "MappingParams": {
      "type": "object",
      "required": ["tx_data", "instructions"],
      "properties": {
        "tx_data": { "$ref": "#/$defs/VerificationRequest" },
        "instructions": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    },
    "VerificationRequest": {
      "type": "object",
      "required": [
        "block_height",
        "raw_tx_hex",
        "merkle_proof_hex",
        "tx_index"
      ],
      "properties": {
        "block_height": {
          "type": "integer",
          "minimum": 0,
          "maximum": 4294967295
        },
        "raw_tx_hex": { "type": "string" },
        "merkle_proof_hex": { "type": "string" },
        "tx_index": { "type": "integer", "minimum": 0, "maximum": 4294967295 }
      }
    }
  }
}
```

#### Field Descriptions — `MapParams`

**Required Fields**

- **`tx_data`** (object): The Bitcoin transaction and its Merkle inclusion proof. See `VerificationRequest` below.
- **`instructions`** (array of strings): Routing instructions encoded as URL query parameter strings (e.g. `"action=swap&asset_out=HBD&recipient=alice"`). Decoded and executed by the contract after the transaction is verified.

#### Field Descriptions — `VerificationRequest`

**Required Fields**

- **`block_height`** (integer): Height of the Bitcoin block containing the transaction. Used to retrieve the matching stored block header. Must fit within `uint32` range.
- **`raw_tx_hex`** (string): The complete raw Bitcoin transaction encoded as a hex string.
- **`merkle_proof_hex`** (string): The Merkle inclusion proof encoded as a hex string. Decoded internally as an array of 32-byte hashes proving the transaction's position in the block.
- **`tx_index`** (integer): Zero-based position of the transaction within the block. Must fit within `uint32` range.

---

### 4. `TransferParams`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/TransferParams",
  "$defs": {
    "TransferParams": {
      "type": "object",
      "required": ["amount", "to"],
      "properties": {
        "amount": { "type": "string" },
        "to": { "type": "string", "minLength": 26 },
        "from": { "type": "string" },
        "deduct_fee": { "type": "boolean" },
        "max_fee": { "type": "integer" }
      }
    }
  }
}
```

#### Field Descriptions

**Required Fields**

- **`amount`** (string): Amount in the asset's smallest unit, encoded as a decimal string (e.g. `"10000"`). Parsed as `int64` internally.
- **`to`** (string): Destination address. Can be either a BTC or Magi address
  depending on the action (BTC for `unmap`, Magi for `transfer` and `transferFrom`).

**Optional Fields**

- **`from`** (string): Address to draw funds from. Used by `transferFrom` and `unmap` to enable allowance-delegated spending. When set, the caller must have sufficient allowance from the `from` account. When omitted, defaults to the caller's own address.
- **`deduct_fee`** (boolean): When `true`, fees (both VSC protocol fee and BTC miner fee) are deducted from the `amount` rather than added on top. The recipient receives `amount - fees`. Only applicable to `unmap`. Defaults to `false`.
- **`max_fee`** (integer): Maximum total fee (VSC + BTC) in satoshis that the caller is willing to pay. If the computed total fee exceeds this value, the transaction reverts. Only applicable to `unmap`. When omitted, no fee cap is enforced.

---

### 5. `PublicKeys`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/PublicKeys",
  "$defs": {
    "PublicKeys": {
      "type": "object",
      "properties": {
        "primary_public_key": { "type": "string" },
        "backup_public_key": { "type": "string" }
      }
    }
  }
}
```

#### Field Descriptions

**Optional Fields** (at least one should be provided)

- **`primary_public_key`** (string): Hex-encoded ECDSA public key for the primary signing key. Must decode to exactly 33 bytes (compressed, prefix `0x02` or `0x03`) or 65 bytes (uncompressed).
- **`backup_public_key`** (string): Hex-encoded ECDSA public key for the backup/fallback signing key. Same format and length requirements as `primary_public_key`.

---

### 6. `RouterContract`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/RouterContract",
  "$defs": {
    "RouterContract": {
      "type": "object",
      "required": ["router_contract"],
      "properties": {
        "router_contract": { "type": "string" }
      }
    }
  }
}
```

#### Field Descriptions

**Required Fields**

- **`router_contract`** (string): The contract ID of the router to register. Stored in contract state and used by `map` to dispatch decoded instructions.

### 7. `AllowanceParams`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/AllowanceParams",
  "$defs": {
    "AllowanceParams": {
      "type": "object",
      "required": ["spender", "amount"],
      "properties": {
        "spender": { "type": "string", "minLength": 1 },
        "amount": { "type": "string" }
      }
    }
  }
}
```

#### Field Descriptions

**Required Fields**

- **`spender`** (string): The address of the account being authorized to spend on behalf of the caller. Cannot be the caller's own address.
- **`amount`** (string): The allowance amount in satoshis, encoded as a decimal string. For `approve`, this sets the allowance absolutely. For `increaseAllowance`/`decreaseAllowance`, this is the delta. Must be non-negative for `approve`, positive for increase/decrease.

---

### 8. `ConfirmSpendParams`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/ConfirmSpendParams",
  "$defs": {
    "ConfirmSpendParams": {
      "type": "object",
      "required": ["tx_data", "indices"],
      "properties": {
        "tx_data": { "$ref": "#/$defs/VerificationRequest" },
        "indices": {
          "type": "array",
          "items": {
            "type": "integer",
            "minimum": 0,
            "maximum": 4294967295
          }
        }
      }
    },
    "VerificationRequest": {
      "type": "object",
      "required": [
        "block_height",
        "raw_tx_hex",
        "merkle_proof_hex",
        "tx_index"
      ],
      "properties": {
        "block_height": {
          "type": "integer",
          "minimum": 0,
          "maximum": 4294967295
        },
        "raw_tx_hex": { "type": "string" },
        "merkle_proof_hex": { "type": "string" },
        "tx_index": { "type": "integer", "minimum": 0, "maximum": 4294967295 }
      }
    }
  }
}
```

#### Field Descriptions

**Required Fields**

- **`tx_data`** (object): The Bitcoin spend transaction and its Merkle inclusion proof. Same schema as `VerificationRequest` in `MapParams`.
- **`indices`** (array of integers): Output indices of the spend transaction that correspond to change UTXOs. These are promoted from the unconfirmed pool to the confirmed pool.

---

## Notes

- **`uint32` fields** (`block_height`, `tx_index`, `BlockHeight`) are represented as integers with `"minimum": 0, "maximum": 4294967295`.
- All integer `amount` fields are in SATS.
