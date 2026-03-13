---
name: build_convention
description: Never run go build/vet directly — always use make targets for the btc-mapping-contract repo
type: feedback
---

Do NOT run `go build`, `go vet`, `go run`, or any direct Go toolchain commands in this repo.

Always use the Makefile targets documented in CLAUDE.md:
- `make dev` — build WASM (default, uses TinyGo)
- `make test` — run all tests
- `make test FILTER=<name>` — run a single test by name

Reason: This is a TinyGo WASM project. Standard `go build` fails or gives misleading errors because TinyGo has a different build pipeline. The user explicitly corrected this multiple times and it is documented in CLAUDE.md.
