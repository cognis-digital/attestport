# ATTESTPORT language ports

Original, dependency-free ports of `attestport`'s core CLI surface — `sbom`,
`attest`, and `verify` — in **Node.js**, **Go**, and **Rust**. Each port uses
the *same* canonical-JSON + HMAC-SHA256 scheme as the primary Python tool, so an
attestation produced by one implementation verifies under any other on a shared
key. All three are standard-library / zero-dependency, so they build and run on
a disconnected air-gapped runner.

| Port | Path | Commands | Tests | Deps |
|------|------|----------|-------|------|
| Node | [`node/attestport.mjs`](node/attestport.mjs) | `sbom`, `attest`, `verify`, `--version` | `node --test` (8 tests) | none (`node:crypto`/`node:fs`) |
| Go   | [`go/attestport.go`](go/attestport.go)       | `sbom`, `attest`, `verify`, `--version` | `go test ./...` (7 tests) | none (stdlib `crypto`) |
| Rust | [`rust/src/main.rs`](rust/src/main.rs)       | `sbom`, `attest`, `verify`, `--version` | `cargo test` (6 tests) | none (vendored SHA-256/HMAC) |

CI builds and tests every port on each push — see
[`.github/workflows/ports.yml`](../.github/workflows/ports.yml). The Node job
additionally proves **cross-implementation interop**: it has the Python tool
sign an attestation and the Node port verify it with the same key.

## Run them

```bash
# Node
node ports/node/attestport.mjs sbom demos/01-basic/demoproj
node ports/node/attestport.mjs attest demos/01-basic/demoproj --key secret --out att.json
node ports/node/attestport.mjs verify demos/01-basic/demoproj att.json --key secret

# Go
cd ports/go && go run . sbom ../../demos/01-basic/demoproj

# Rust
cd ports/rust && cargo run -- sbom ../../demos/01-basic/demoproj
```

## Why ports

The Python implementation is the reference and carries the full feature set
(gate, vuln-matching against the bundled OSV DB, MCP server). The ports exist so
the **trust-critical primitives** — deterministic SBOM hashing and signed
provenance — are available natively in a Go or Rust build pipeline without a
Python runtime, and so the canonical-JSON/HMAC contract is independently
validated by three more implementations.
