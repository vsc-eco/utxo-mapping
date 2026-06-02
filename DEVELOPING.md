# Developing the Dash mapping + forwarder contracts

This repo's two contracts (`dash-mapping-contract/` + `dash-forwarder-contract/`) depend on **in-progress** changes in
`go-vsc-node`'s `develop` branch — specifically the `crypto.bls_verify_aggregate` and `contracts.call_as` host
functions added for the Dash InstantSend login feature.

Until those land in an upstream tagged release, **you must point the contracts at a local sibling checkout via
a `go.work` file**. Without it, the contract `replace vsc-node => ...` directive resolves to whichever upstream
snapshot the contract's `go.mod` pins — typically older than your local work — and the TinyGo wasm build will
fail with "unknown import" at runtime when the test harness loads the binary.

## Required directory layout

```
parent/
├── go-vsc-node-develop/                 # the in-progress vsc-eco/go-vsc-node clone
└── utxo-mapping/
    ├── dash-mapping-contract/
    │   └── go.work                      # gitignored
    └── dash-forwarder-contract/
        └── go.work                      # gitignored
```

The two `go.work` files are gitignored (see repo root `.gitignore`) so each developer points at their own
checkout. Without these files the contracts use the stable upstream snapshot, which is correct for CI builds of
released versions.

## Create the go.work files

```bash
cd /path/to/utxo-mapping/dash-mapping-contract
cat > go.work <<'EOF'
go 1.25.7
use (
    .
    ../../go-vsc-node-develop
)
EOF

cd ../dash-forwarder-contract
cat > go.work <<'EOF'
go 1.25.7
use (
    .
    ../../go-vsc-node-develop
)
EOF
```

The relative path to `go-vsc-node-develop` depends on where you clone it; the snippets above assume both repos
share a parent directory.

## Branch tracking

When working on the Dash IS-login feature, point at the matching feature branch:

```bash
cd ../../go-vsc-node-develop
git remote add tibfox https://github.com/tibfox/go-vsc-node.git 2>/dev/null || true
git fetch tibfox
git checkout tibfox/feat/dash-is-login
```

This branch includes:

* `modules/wasm/sdk/sdk.go` — `crypto.bls_verify`, `crypto.bls_verify_aggregate`, `contracts.call_as`
* `modules/contract/execution-context/` — `EffectiveCaller` env field + `WithTrustedForwarders` option
* `modules/state-processing/transactions.go` — production wiring that passes the system-config's
  `TrustedForwarders()` list into the execution context (required for `contracts.call_as` to actually trust
  forwarder contracts)
* `modules/islock-attestation/` — BLS attestation primitives, gossipsub topic schema

Without these, the contracts compile but `addAllowedTarget`/`mapInstantSendV2`/`commitAllowedTarget` paths will
abort at the host-fn-not-bound check.

## Building

```bash
cd dash-mapping-contract
USE_DOCKER=0 GOTOOLCHAIN=go1.25.10 make dev      # produces bin/dev.wasm
USE_DOCKER=0 GOTOOLCHAIN=go1.25.10 make tinyjson # regenerate marshalers when schema changes
```

The `GOTOOLCHAIN=go1.25.10` prefix is needed when the host system Go is 1.26+, because TinyGo 0.39.0 only
supports Go 1.19–1.25. See `~/.claude/projects/-home-dockeruser/memory/magi_nft_tinygo_go126.md` (or the
equivalent in your local memory) for the long-form note.

## Tests

```bash
cd dash-mapping-contract
go test ./tests/current/   # pure-Go tests + tinyjson + WASM integration
```

The WASM integration tests in `tests/current/` need `go.work` set up — they load the wasm binary into
`vsc-node/lib/test_utils` which itself pulls in the host functions from the linked `go-vsc-node-develop`.
Without `go.work`, the test framework registers an older set of host functions and any test that loads the
wasm fails with `wasm_init_error: failed to register wasm buffer: unknown import`.

## CI

Production CI uses the stable `replace vsc-node => github.com/vsc-eco/go-vsc-node v0.0.0-...` directive and
does NOT use `go.work`. Bump the replace target when promoting the upstream changes from develop to main.

### Cross-repo parity tests

Tests that import `vsc-node/modules/islock-attestation` or
`vsc-node/lib/islock-instruction` (currently only
`parity_cross_repo_test.go`) require a `go.work` pointing at a local
go-vsc-node-develop checkout that includes those modules — the upstream
`replace` target may predate them. These tests are behind the
`cross_repo` build tag so the default suite compiles without
go.work. Run them as:

```bash
go test -tags cross_repo ./tests/current/...
```

Round-3 audit OP-001 introduced this split — the previous default-tag
inclusion made the entire pure-Go suite fail to compile under
documented CI mode.

Round-4 audit R4-011 verified that the cross-repo lane will FAIL to
compile under `GOWORK=off` until the contract's `replace vsc-node =>`
target is bumped past the upstream commit introducing
lib/islock-instruction. The intended CI workflow is:

  1. Pure-Go default lane (`go test ./tests/current/...`) MUST be
     green at all times. It does NOT depend on cross-repo wiring.
  2. The cross-repo lane (`go test -tags cross_repo ...`) requires a
     gitignored `go.work` until the lib/islock-instruction commit is
     promoted upstream into vsc-eco/go-vsc-node and the replace
     pseudo-version is bumped past it. Developers running this lane
     locally must add `use ../../../go-vsc-node-develop` to their
     gitignored go.work alongside the contract repo `use .`.

Once the upstream replace target is bumped past the commit landing
lib/islock-instruction, the cross-repo lane will compile in CI without
a go.work file and the cross_repo build tag can be retired.

## Admin helper: gen-validator-set-payload

The R5-DRIFT-04 / round-6 `dash-mapping-contract/cmd/gen-validator-set-payload`
CLI composes the 4-field SetValidatorSet admin payload from announcer
outputs. Build + run:

```bash
cd dash-mapping-contract
go run ./cmd/gen-validator-set-payload \
    -epoch 42 \
    -entry 'did:key:bls:z...,<pk_hex_96>,<pop_base64_rawurl>,<account>' \
    -entry 'did:key:bls:z...,<pk_hex_96>,<pop_base64_rawurl>,<account>'
```

The CLI validates pk hex length (96), pop base64 → 96-byte length,
and the account against Hive consensus rules
(`ValidateHiveAccount` — round-6 R6-CORR-05/R6-CORR-06 mirror the
contract). Output goes to stdout; pipe into your deployer.

## IS-service operator flags

Round-5 / round-6 operator-tunable flags on `cmd/is-service`:

* `-validatorSetCacheTTLSeconds` (default 30s, R4-001 / R5-DRIFT-06 /
  R6-OP-04 — lower for faster admin-rotation reflection, higher to
  rate-limit upstream GraphQL). Must be > 0.
* `-drainTimeoutSeconds` (default 240s, R3-05). MUST be >=
  CollectTimeout + SubmitTimeout + reconcileL2 budget.
* `-trustedProxies` (TC2-06). Honour X-Forwarded-For only from this
  list (+ loopback). IPv6 / mixed-case automatically normalized
  (R4-SEC-05).

The full operator list is also visible via `is-service -help`.

### Monitoring signal: `roster divergence`

Round-5 audit R5-ADV-01 / round-6 R6-OP-01 added a structured
`slog.Error` named `"validator-set / libp2p roster divergence"`
that fires when every libp2p attestation responder is rejected by
the L2 GraphQL validator-set lookup. The log includes
`validatorSetSource` (the configured `-l2GqlURL` value, sanitised
to scheme://host so embedded credentials never reach log shippers —
R7-OP-01-logleak). Treat this signal as **L2 GraphQL endpoint
returns a wrong or stale validator set**; investigate that
upstream first.

Do not embed credentials in `-l2GqlURL` — production endpoints
should be reached via a network-trust boundary, not bearer-in-URL.

## Known test-coverage gaps

Round-2 audit TC2-09 identified that `dispatchForward` (the C4 fix path with 6 sequenced
state mutations + 2 external calls) has zero functional tests. The pure-Go helpers it
calls (`incInternalBalance`, `decInternalBalance`, `checkAndBumpRateLimit`,
`isAlreadyProcessed`) ARE unit-tested, but the orchestrated flow is not.

A full integration test requires:

* A valid `MapInstantSendV2ParamsFull` payload (real rawTx + BLS aggregate)
* A registered validator set in state (use the `setValidatorSet` admin action)
* Pre-funded sender HBD balance
* An allow-listed target contract that supports `call_as`

This work is tracked as a follow-up. Until it lands, the C4 invariant
(`sum(internal HBD) == native HBD held by contract` after dispatchForward) is
verified by inspection only — any future refactor of `dispatchForward` must be
hand-audited against the audit's `post-forward-rc-rollback-drains-target` rubric.
