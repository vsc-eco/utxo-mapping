# Dash InstantSend Login — Mapping Contract Integration

Workstream 5 design notes for adding the Dash IS-login fast-path to
`dash-mapping-contract`. This document is the bridge between the design
spec (`magi/testnet/docs/superpowers/specs/2026-05-14-...-design.md`) and
the in-progress contract code.

## What changes in this contract

The existing `mapInstantSend(rawTxHex)` action is preserved unchanged for
backwards compatibility. A new action `mapInstantSendV2(rawTxHex,
instruction, epoch, attestations[])` is added alongside it. Once the
upstream IS Service rolls over, the v1 action can be removed (after a
deprecation window) — but until then, both paths coexist.

## New state schemas

### `forwardQueue` (key prefix `fq/`)

Per-txid record of forward-dispatch results. v1 value format is
pipe-delimited for parser simplicity; will move to tinyjson once the
schema settles.

Key:   `fq/<txid-hex>`
Value: `sender|instruction|callFunding|status`

- `sender` — DashDID of the IS payer
- `instruction` — canonical op=call;... string the address committed to
- `callFunding` — duffs routed to target (0 for value-less calls)
- `status` — one of `PENDING_FORWARD`, `FORWARDED`, `FORWARD_FAILED`,
  `FORWARD_FAILED_INSUFFICIENT_RC` (see `constants.go`)

### `allowedTargets` (key prefix `at/`)

Governance-managed allow-list of contract IDs invokable via `op=call`.
Spec §5.2.7 — v1 initial list is exactly the magi-dex router.

Key:   `at/<contract-id>`
Value: `"1"` if allowed; missing/empty otherwise.

Adding requires the 7-day `AllowListGovernanceTimelockBlocks` cooldown
via `addAllowedTarget` + `commitAllowedTarget` (both shipped; see
`deployment-runbook.md §2.5`). Removal follows the symmetric
`removeAllowedTarget` + `commitRemoveAllowedTarget` pair.

### Per-DashDID rate-limit counter (key prefix `rl/`)

Sliding-window counter to bound spam per authenticated user.

Key:   `rl/<dashDID>`
Value: `windowStart_be8|count_be4`

Window length = 600 seconds, max 30 ops per window (spec §5.2.7). Above
the cap, the contract still credits but skips forward dispatch.

### Internal HBD ledger (extends existing balance prefix)

The mapping contract already has `BalancePrefix` (`a/`) for mapped-DASH
balances. For the IS-login feature it also holds the user's INTERNAL HBD
that pays for RC reimbursement (spec §5.2.6).

To keep the asset axis explicit, extend with a per-asset prefix:

- `a/dash/<dashDID>` — mapped DASH balance (existing semantics)
- `a/hbd/<dashDID>` — internal HBD balance (new)

The mapping contract's native HBD self-balance backs the internal HBD
1:1. When sending RC reimbursement: `SendBalance(submitter, fee, "hbd")`
moves real HBD out of the contract's native account.

### Forwarder contract ID (single key)

`forwarder` → the canonical dash-forwarder-contract ID this mapping
trusts as its only valid receiver for forward dispatches. Set once at
deploy via admin action; immutable thereafter. Without it set, `op=call`
IS payments are rejected.

## New host-function dependencies

The mapping contract calls these from inside `HandleMapInstantSendV2`:

1. `crypto.bls_verify_aggregate(pubkeys_concat, msg, agg_sig)` — verifies
   the validator quorum signed the IS-lock attestation. From workstream
   4a (modules/wasm/sdk/sdk.go).

2. `contracts.call` to invoke `dash-forwarder-contract.execute(txid)` —
   existing host function; no change needed.

3. `hive.send_balance` to send RC reimbursement HBD to the L2 tx
   submitter — existing host function.

4. "Read validator set at epoch" — currently solved via the
   contract's own `validator_set` action: admin calls
   `setValidatorSet(epoch, payload)` to populate the at-epoch set;
   `verifyAttestationsAgainstValidatorSet` reads it back. The
   "elections-state host function" alternative remains spec'd for a
   future host change that would eliminate the admin-driven push.

## The HandleMapInstantSendV2 sequence

Implementation skeleton lives in
`contract/mapping/forwarder_integration.go`. The full sequence per spec
§5.2.3:

```
HandleMapInstantSendV2(rawTxHex, instruction, epoch, attestations):
    // ----- Verification -----
    1. Re-derive D = mapping.DepositAddress(primary, backup, instruction, net).
       Confirm D appears as an output in rawTxHex. Else reject.
    2. Compute canonical attestation msg = H(domain || chainId || epoch || txid || rawTxHash || instrHash).
    3. Look up validator set at `epoch` from Magi state.
    4. For each attestation: look up validator's BLS pubkey, accumulate.
    5. Call crypto.bls_verify_aggregate(pubkeys_concat, msg, agg_sig).
       Reject if false or count < 2M/3 + 1.
    6. Parse instruction. Reject if malformed.
    7. Resolve sender DashDID — strict all-inputs-same-address (§5.2.5).
       Reject multi-address tx.
    8. Read actualISAmount from rawTxHex's output to D.
    9. Apply amount rules (§5.2.4):
       - op=auth or value-less call: actualISAmount >= MinDustDuffs
       - value-bearing op=call: declared amount >= MinCallFundingDuffs

    // ----- Rate limit -----
    10. Read rl/<dashDID>; if count >= 30 in window, set "skipForward=true"
        but continue with credit (per §5.2.7).

    // ----- Credit -----
    11. incAccBalance(dashDID, actualISAmount).  // mapped-DASH ledger
    12. setIsLockedMarker(txid).                  // idempotency

    // ----- Forward dispatch (op=call only, !skipForward) -----
    13. If op=auth: done. Return success.
    14. If op=call:
        a. callFunding = min(actualISAmount, declared amount)
        b. Debit DashDID by callFunding, credit target by callFunding (intra-contract).
        c. Write forwardQueue[txid] = (sender, instruction, callFunding, PENDING_FORWARD).
        d. result = sdk.ContractCall(forwarder, "execute", txid, opts)
        e. If success:
            - Compute rcReimbursementHBD = StaticMaxRcCost(tx) / 1000
            - Debit dashDID's internal HBD by rcReimbursementHBD.
              If insufficient HBD AND target was a swap, deduct from swap output instead.
            - SendBalance(submitter, rcReimbursementHBD, "hbd") (mapping → submitter native HBD).
            - Mark forwardQueue[txid].status = FORWARDED.
        f. If failure:
            - Reverse step (b): refund target → sender.
            - Mark forwardQueue[txid].status = FORWARD_FAILED.
            - Credit from step 11 preserved (user keeps DASH).

    15. Per-block RC cap check: if mapping has consumed > N RC in this block,
        return success-with-warning for further mapInstantSendV2 calls.
        Bounds the cost of any single block's IS spam (§8.3 layer 3).
```

## Things deliberately deferred

- **Slow-path migration**: the existing `HandleMapInstantSend` (v1, oracle-
  callable) stays in place. No removal until the IS Service has been live
  for >30 days and ops can confirm v2 throughput dominates v1.

- **op=auth-only credit path**: for v1 we could pre-create a tighter
  "login-only credit, no value movement" path to save gas. Deferred until
  measurement shows it matters.

- **Allow-list governance contract**: spec §5.2.7 7-day timelock now
  shipped (addAllowedTarget + commitAllowedTarget; symmetric
  remove pair). v1 mainnet ships with a single admin signer; an
  on-chain multisig governance contract sitting in front of the
  admin gate is a future change tracked separately.

- **forwardQueue pruning**: terminal entries should be auto-pruned after
  ~3 days (constants.ForwardQueuePruneAgeBlocks). Add a maintenance call
  that callers can invoke opportunistically. Not strictly required for v1
  but state growth is a real concern at scale.

## Open questions for workstream-5 implementer

1. **Validator set lookup**: How does this contract read the at-epoch
   validator set? Magi exposes elections via state queries — does
   contracts.read work against the system elections module, or do we
   need a new host function?

2. **Internal HBD balance schema**: pipe-delimited like the rest, or
   move to tinyjson now? Internal HBD is the system asset for fee
   accounting; making it inspectable matters.

3. **RC cost formula**: `StaticMaxRcCost(tx) / 1000` is a rough mapping
   per params.go's comment "1000 RC ≈ 1 HBD equivalent". Confirm with
   the protocol team that this rate is canonical (params.go's RC_HIVE_FREE_AMOUNT
   suggests 2000 RC/HBD instead — pick one and document).

4. **Reentrancy from forwarder→target→mapping**: should the mapping
   contract take a reentrancy lock during HandleMapInstantSendV2? Magi
   VM might already prevent it but worth confirming.

## What I've committed in this scaffold

- `contract/constants/constants.go` — all new keys, status codes,
  amount floors, rate-limit constants. Aligned with
  dash-forwarder-contract's expectations.

- `contract/mapping/forwarder_integration.go` — the V2 entrypoint
  shape (`MapInstantSendV2Params`, `ValidatorAttestation`), the v2
  handler scaffold with the full step list as TODO comments, the
  instruction parser (mirrors forwarder's, can be used directly),
  and the attestation-message-hash stub.

- This doc — design rationale + open questions + sequence.

When the team picks up workstream 5 implementation, this is the
contract-by-contract integration map.
