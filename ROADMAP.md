# ATTESTPORT — Roadmap

> Air-gap software supply-chain gate — SBOM, SLSA/in-toto-style provenance, CI policy gate

## Now (v0.1.x)
- `sbom` / `attest` / `verify` / `gate` CLI with table / JSON / SARIF output.
- Lockfile parsers: PyPI, npm (v1/v2/v3), Go modules, Cargo.
- Detached HMAC-SHA256 provenance signature; bundled demo + tests.
- MCP server (stdio) exposing `sbom`, `verify`, `gate`.

## Next (v0.2)
- More ecosystems: `poetry.lock`, `pnpm-lock.yaml`, `yarn.lock`, `composer.lock`.
- Pluggable asymmetric signing backend (Ed25519) behind the same interface.
- SPDX-format SBOM output alongside CycloneDX.
- Map gate rules to SLSA build levels.

## Later (v1.0)
- Offline vulnerability overlay from a bundled, periodically-snapshotted advisory db.
- Stable rule/plugin API and PyPI packaging.
- Pro tier + commercial support (see `licensing@cognis.digital`).

Want something prioritized? Open an issue or a PR — see [CONTRIBUTING.md](CONTRIBUTING.md).
