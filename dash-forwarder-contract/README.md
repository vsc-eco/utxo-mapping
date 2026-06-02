# dash-forwarder-contract

Workstream 6 of the Dash InstantSend login feature. Trusted-forwarder
contract for the ERC-2771-style identity-spoofing pattern used by the
Dash IS-login flow.

## What this contract does

When a Dash user pays an InstantSend with `op=call;contract=X;method=M;args=A`,
the `dash-mapping-contract`:

1. Credits the user's `DashDID` (internal ledger).
2. Writes `(txid, sender, instruction, callFunding)` to its
   `forwardQueue[txid]` map with status `PENDING_FORWARD`.
3. Synchronously invokes `dash-forwarder-contract.execute(txid)`.

This contract's `execute(txid)`:

1. Verifies the caller is the registered `dash-mapping-contract`. Any
   other caller is rejected.
2. Reads `forwardQueue[txid]` from mapping-contract state.
3. Verifies `status == PENDING_FORWARD`.
4. Parses the instruction to extract `(target, method, args)`.
5. Verifies `target ∈ mapping.allowedTargets` (the governance-managed
   allow-list — see spec §5.2.7).
6. Invokes `sdk.ContractCallAs(target, method, args, DashDID(sender))`
   which uses the new `contracts.call_as` WASM host function added in
   workstream 2. The callee sees `effectiveCaller = DashDID(sender)`
   while the literal `caller` is still the forwarder.

This contract is the ONLY entry in `system-config.TrustedForwarders` for
the Dash feature. It MUST be tiny, audit-friendly, and have zero
authority over the mapped-DASH ledger. Bug here = identity-spoofing only,
not fund-minting (those privileges live in `dash-mapping-contract`).

## Status

**v1 scaffold (this commit)** — source structure + design in code, not
yet built/runtime-tested. To progress to v1.1:

1. Wire `sdk/sdk.go` `ContractCallAs` wrapper (requires the matching
   `//go:wasmimport sdk contracts.call_as` host import — done in
   workstream 2 of go-vsc-node-develop).
2. Add the `forwardQueue` schema reference to match the format
   `dash-mapping-contract` will write (workstream 5).
3. Add Magi `bls_verify_aggregate` calls in mapping contract (NOT here)
   to verify validator attestations before this contract is invoked.
4. Build the WASM via `make dev` once TinyGo is set up.
5. Run integration tests against the compiled WASM via
   `vsc-node/lib/test_utils`.

## Files

- `contract/main.go` — entry point with `execute` wasmexport.
- `contract/forwarder/forwarder.go` — execute logic + instruction parser.
- `contract/constants/constants.go` — key constants.
- `contract/contracterrors/errors.go` — error types.
- `sdk/` — vendored copy of the standard mapping-contract SDK shim,
  extended with `ContractCallAs` for the new `contracts.call_as` host
  function.
- `tests/current/` — test scaffolding using `vsc-node/lib/test_utils`.
- `Makefile` — TinyGo build config.
- `go.mod` — module setup mirroring the dash-mapping-contract pattern.
