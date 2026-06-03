# dash-mapping-contract — Deployment Runbook

This document is the operator-facing companion to
[`dash-is-login-integration.md`](./dash-is-login-integration.md) and
[`actions.md`](./actions.md). It walks through bringing a fresh deployment
of the contract up on testnet or mainnet, including the per-deploy admin
actions, the order they must run in, and the failure-recovery options.

Most user-facing actions (`map`, `unmap`, `transfer`, etc.) are covered
in `actions.md` — this file covers only the **operator** side: deployment,
initialisation, validator-set rotation, allow-list governance, and pause/
rollback.

> **Audience.** The deployer identity is `hive:magi.contracts` on testnet
> and the configured oracle account on mainnet (see `checkAdmin()` in
> `contract/main.go`). Any user with the deployer's posting authority on
> Hive L1 can run these — the contract enforces the gate, not the toolchain.

---

## 1. Deploy

```bash
cd dash-mapping-contract
USE_DOCKER=1 make testnet      # for testnet wasm
USE_DOCKER=1 make mainnet      # for mainnet wasm
```

Then deploy the resulting `bin/<network>.wasm` via the
[`magi-deployer`](https://docs.magi.eco/) workflow. Capture the resulting
contract ID (`vsc1...`) — every subsequent admin action targets it.

> **Note.** `bin/<network>.wasm` is gitignored; rebuild before deploy.
> The cross-repo test suite (`go test -tags cross_repo`) also depends on
> `bin/dev.wasm` being present locally (see DEVELOPING.md).

The contract code expects the network mode to be compiled into the binary
via `-X main.NetworkMode=<testnet|mainnet>` (the Makefile does this). Mixing
a `testnet` binary with a mainnet deploy is rejected by `init()` — the
contract panics on start.

---

## 2. Per-deploy admin actions

Run these in order. RC estimates are upper bounds for empty / freshly-
deployed state — actual usage scales with payload size + existing state
volume.

### 2.1 setForwarderContractId

```
action:  setForwarderContractId
payload: vsc1<forwarder-contract-id>
caller:  hive:magi.contracts  (testnet) | <oracle>  (mainnet)
RC:      ~500
```

Pins the canonical `dash-forwarder-contract` ID this mapping contract
trusts for the IS-login flow.

- **Required before any `mapInstantSendV2` call** — the contract rejects
  IS payloads when the forwarder is unset.
- **Immutable on mainnet after first write.** If you set the wrong ID,
  pause the contract before any user traffic, then escalate to a redeploy.
  Testnet can overwrite.
- `actions.md` documents the action signature.

### 2.2 seedBlocks

```
action:  seedBlocks
payload: <height>:<header_hex>|<header_hex>|...
caller:  admin
RC:      5000–10000
```

Seeds initial Dash block headers + height. Mainnet: one-shot, idempotent
(subsequent calls reject). Testnet: replaceable; the contract overwrites.

- Required before `setValidatorSet`. The contract reads `BlockHeight` from
  state when registering a validator set so it can record `registeredAt`.
- Headers must be canonical hex; the contract validates length but not
  PoW (PoW is checked at `addBlocks` time during normal operation).

### 2.3 setValidatorSet

```
action:  setValidatorSet
payload: <epoch>;<did1>=<pk1>=<pop1>=<acct1>|<did2>=<pk2>=<pop2>=<acct2>|...
caller:  admin
RC:      ~3000
```

Registers the BLS validator set for `<epoch>`. Each entry is a 4-field tuple:

- `did` — `did:key:z...` reference to the validator's BLS pubkey.
- `pk` — 48-byte (96 hex char) BLS12-381 pubkey.
- `pop` — 96-byte (192 hex char) BLS proof-of-possession over
  `domain || pkBytes || accountBytes`. **Account-bound** (Round-4 audit
  R4-CSM-01 critical fix); a PoP signed over a different account is
  rejected at `SaveValidatorSetForEpoch`.
- `acct` — the validator's Hive account name (3..16 chars, segmented).

**Build the payload via the CLI** — the announcer-side BLS PoP must match
exactly what the contract reconstructs:

```bash
go run ./cmd/gen-validator-set-payload \
  --epoch=N \
  --entry="did=$DID,pubkey=$PUBKEY_HEX,priv=$PRIV_HEX,account=$ACCOUNT" \
  [--entry=...]
```

(see `cmd/gen-validator-set-payload/` for full flag list)

**Cache TTL.** The IS service caches per-epoch validator sets for
`-validatorSetCacheTTLSeconds` (default 30s). After a successful
`setValidatorSet`, witnesses pick up the new set automatically at the
next TTL tick — no service restart needed.

**Failure modes:**

- `invalid Hive account ...` (`ErrInput`) — `<acct>` fails Hive consensus
  rules (length 3..16, segment shape, etc.). Re-build payload with a
  canonical account.
- `BLS PoP failed to verify for validator ...` (`ErrNoPermission`) — PoP
  doesn't match `(domain || pubkey || account)`. Common cause: wrong
  account in the payload, or `gen-validator-set-payload` invoked with a
  mismatched `--account`. Re-run the CLI with the correct account.
- `validator-set entry expects ...` (`ErrInput`) — payload shape is
  malformed (missing field, empty segment, bad pubkey length).

**Rollback / fix.** If you land a bad payload for epoch N, immediately
re-run `setValidatorSet` for the **same epoch** with the corrected
payload — the contract overwrites in place. Validator-set cache TTL bounds
how long stale state is observed by the IS service.

### 2.4 setMinAttestations

```
action:  setMinAttestations
payload: <n>
caller:  admin
RC:      ~200
```

Sets the N-of-M quorum threshold for the fast-path BLS aggregate verifier.

- **Default fallback is 1** — adequate for devnet bring-up but **must be
  raised** for mainnet to (at minimum) `floor(2M/3) + 1` before opening to
  users. Reading `DefaultMinAttestations = 1` from `constants.go`.
- Can be changed at any time; takes effect from the next `mapInstant-
  SendV2` call.

### 2.5 addAllowedTarget + commitAllowedTarget (governance timelock)

```
action:  addAllowedTarget       (admin, ~500 RC)
payload: <target-contract-id>:<unlock-block-height>

action:  commitAllowedTarget    (permissionless, ~300 RC)
payload: <target-contract-id>
```

Adds a contract to the `op=call` allow-list. The spec §5.2.7 mandates a
7-day timelock (86_400 blocks) on additions and removals.

1. Admin proposes via `addAllowedTarget`; the entry sits in `pendingAdd`
   with an unlock-block timestamp.
2. After the timelock elapses, **anyone** can call `commitAllowedTarget`
   to promote the entry into the active `allowedTargets` map.
3. Removal follows the same pattern via `removeAllowedTarget` →
   `commitRemoveAllowedTarget`.

v1 mainnet ships with **exactly one** target: the magi-dex router. Any
later additions go through this two-step flow.

#### 2.5.1 setAllowedTargetImmediate (regtest only)

```
action:  setAllowedTargetImmediate   (admin, ~300 RC)
payload: <target-contract-id>
```

**Regtest builds only** — the action wasmexport refuses to run
when `NetworkMode != regtest`. The contract used on a mainnet OR
real testnet deploy will reject the call. Per audit SEC-3 (R15)
real testnet now exercises the same add+commit timelock flow as
mainnet so the timelock pathway itself gets tested.

Writes directly into the active `allowedTargets` map, bypassing
the 7-day timelock. Required so devnet/CI regtest runs can
exercise the op=call dispatch path without burning 86,400 regtest
blocks of mining. **Testnet + mainnet allowlist mutations MUST go
through the symmetric add+commit pair above.**

---

## 3. Validator-set rotation cadence

Per the spec, the validator set rotates per epoch. To rotate cleanly:

1. **Ahead of the boundary** — build the payload for epoch N+1 via
   `gen-validator-set-payload`. Confirm each validator's PoP via the
   CLI's `--verify` mode (round-trip parity is covered by
   `tests/current/parity_cross_repo_test.go`).
2. **Submit `setValidatorSet(N+1, payload)`** BEFORE epoch N+1 begins.
3. **Verify with `getStateByKeys vs-<N+1>`** that the set landed.
4. **Cache TTL tick** — witness IS services pick up the new set within
   `-validatorSetCacheTTLSeconds` (default 30s).

**Grace window.** If you miss the boundary, the contract falls back to
epoch N's set for `ValidatorSetGraceBlocks` (1200 blocks ≈ 1 hour at
3s Hive blocks). Beyond that window, the fast-path verifier rejects all
attestations until `setValidatorSet(N+1, ...)` lands. Set up an alert
on `now - last_setValidatorSet > 1 epoch + 1200 blocks` to catch this
before the grace window closes.

---

## 4. Pause / rollback

The contract supports an admin `pause` action that flips `PausedKey` to
`"1"`. While paused, all user-facing actions return `ErrPaused`; admin
actions still run.

- **Use pause when**: a bad `setForwarderContractId` or `seedBlocks` lands
  on mainnet (where the action is immutable), and a redeploy is required.
- **Use pause when**: a critical bug surfaces post-launch and you need to
  freeze user state while a fixed contract is being deployed.
- **DO NOT use pause** for routine validator-set rotation issues — the
  grace window covers them.

To resume, call `unpause` (admin gate).

---

## 5. Verification checklist (post-deploy)

After completing steps 2.1–2.4:

```bash
# Confirm forwarder is wired:
magi-deployer findContractOutput <contract-id> forwarder
# expect: <forwarder-contract-id>

# Confirm seed:
magi-deployer findContractOutput <contract-id> h
# expect: <height>

# Confirm validator set for the current epoch:
magi-deployer findContractOutput <contract-id> vs-<epoch>
# expect: <registeredAt_block>#<did>=<pk>|<did>=<pk>|...

# Confirm min-attestations:
magi-deployer findContractOutput <contract-id> minAttestations
# expect: <threshold>
```

(Use `findContractOutput` per the magi-market deployment notes —
`getStateByKeys` returns the raw on-chain bytes which include framing.)

When all four return their expected values, the contract is ready to
accept user `mapInstantSendV2` traffic.

---

## 6. Open items for mainnet flip

- [ ] Replace dev `addressSignerSecret` (HMAC) with HSM/KMS asymmetric
      signer at the IS service layer (spec §5.7).
- [ ] `setMinAttestations(floor(2M/3)+1)` after the production validator
      set is registered.
- [ ] Validator-set rotation cron / runbook ownership assigned.
- [ ] `pause`/`unpause` rehearsal on testnet before mainnet flip.
- [ ] Operator dashboard wired (validator-set cache hit, forwardQueue
      depth, RC reimbursement balance).
