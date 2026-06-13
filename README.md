# ATTESTPORT — air-gap software supply-chain gate

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `dev-supply-chain`

[![PyPI](https://img.shields.io/pypi/v/cognis-attestport.svg)](https://pypi.org/project/cognis-attestport/)
[![CI](https://github.com/cognis-digital/attestport/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/attestport/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)
[![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

**SBOM (CycloneDX-style) + SLSA/in-toto-style provenance, signature, and a CI policy gate — built for air-gapped pipelines.**

*Developer & Supply-Chain Security — knowing what you ship, and proving it, without phoning home.*

## Usage — step by step

1. **Install** from source (Python 3.9+):
   ```bash
   pip install .
   ```
2. **Generate** a CycloneDX-style SBOM for a project directory:
   ```bash
   attestport sbom ./myproject --out sbom.json
   ```
3. **Attest** the artifact, binding in the SBOM (SLSA/in-toto-style provenance):
   ```bash
   attestport attest ./dist --builder ci@example.com --sbom sbom.json --out attestation.json
   ```
4. **Verify** an artifact against its attestation:
   ```bash
   attestport verify ./dist attestation.json --format json
   ```
5. **Gate in CI** — policy gate over the project, failing on severity:
   ```bash
   attestport gate ./myproject --attestation attestation.json --format sarif --fail-on high --out gate.sarif
   ```
   Signing keys come from `--key`, the `ATTESTPORT_KEY` env var, or a demo key. Also: `attestport mcp`.

## Why

Most supply-chain tooling assumes a network: a transparency log to talk to, a key service to fetch, a registry to query. In an air-gapped or high-assurance CI runner you have none of that. `attestport` does the whole loop **offline with nothing but the Python standard library** — no pip install, no daemon, no network:

1. **Inventory** what a build contains (an SBOM).
2. **Bind** that to the built artifact with a signed provenance statement.
3. **Verify** the binding later, anywhere.
4. **Gate** the pipeline on a policy you control.

It targets the public, open formats the ecosystem already speaks — **CycloneDX**, **in-toto**, and **SLSA** — but the implementation is original and self-contained.

<!-- cognis:domains:start -->
## Domains

**Primary domain:** AI & ML  ·  **JTF MERIDIAN division:** ATHENA-PRIME · SAGE

**Topics:** `cognis` `ai` `llm` `machine-learning` `sbom`

Part of the **Cognis Neural Suite** — 300+ source-available tools organized across 12 domains under the JTF MERIDIAN command structure. See the [suite on GitHub](https://github.com/cognis-digital) and [jtf-meridian](https://github.com/cognis-digital/jtf-meridian) for how the pieces fit together.
<!-- cognis:domains:end -->

## Install

```bash
# no dependencies; runs from a checkout
pip install -e ".[dev]"      # only to get pytest for the test suite
# or just:
python -m attestport --help
```

## Quick start

```bash
attestport --version

# 1. Generate a CycloneDX-style SBOM (detects requirements.txt, package-lock.json, go.sum, Cargo.lock)
attestport sbom demos/01-basic/demoproj --out sbom.json

# 2. Produce a signed SLSA/in-toto-style provenance attestation that binds the SBOM
attestport attest demos/01-basic/demoproj --sbom sbom.json --out att.json

# 3. Verify the artifact against its attestation (PASS; fails if either is tampered)
attestport verify demos/01-basic/demoproj att.json

# 4. Gate a CI pipeline on a policy (exits non-zero on a violation)
attestport gate demos/01-basic/demoproj --policy demos/01-basic/policy.json --fail-on high

# expose the engine to agents over MCP (stdio):
attestport mcp
```

## Commands

| Command | What it does |
|---------|--------------|
| `sbom <dir>`      | Walk a project, detect dependencies from lockfiles, hash files, emit a CycloneDX-style SBOM. |
| `attest <artifact>` | Build an in-toto `Statement` + SLSA-style provenance predicate (subject digest, builder, materials, bound SBOM digest) and attach a detached signature. |
| `verify <artifact> <attestation>` | Recompute the subject digest, check the signature, optionally enforce a component policy. Non-zero on any mismatch. |
| `gate <dir> --policy policy.json` | CI gate: fail on banned licenses, known-bad components, unpinned deps, or a missing/invalid attestation. `table` / `json` / `sarif` output + `--fail-on`. |
| `mcp` | Run as a local MCP server (stdio JSON-RPC) exposing `sbom`, `verify`, `gate`. |

## Supported lockfiles

`requirements.txt` (PyPI) · `package-lock.json` (npm, v1/v2/v3) · `go.sum` (Go modules) · `Cargo.lock` (crates.io). Each component is emitted with a [Package-URL](https://github.com/package-url/purl-spec) (`purl`), a pinned/unpinned flag, and any integrity hash carried in the lockfile.

## Signing model (read this)

The detached signature is a **keyed HMAC-SHA256** over the canonical statement bytes (`signature.algorithm = "hmac-sha256"`). This gives integrity + authenticity against a shared secret with nothing beyond `hashlib`/`hmac`, so it works on a bare air-gapped runner.

It is intentionally **not** a public-key scheme. For production you should:

- set a real secret via `ATTESTPORT_KEY` (or `--key`) instead of the built-in demo key (the tool warns loudly when the demo key is in use), and
- ideally swap in an asymmetric signing scheme or an HSM at the integration boundary.

The canonicalization (`sort_keys`, no insignificant whitespace, UTF-8) is what makes digests and signatures byte-for-byte reproducible across machines.

## Policy file

```json
{
  "banned_licenses": ["GPL-3.0", "AGPL-3.0", "SSPL-1.0"],
  "banned_components": ["left-pad", "evil-pkg@1.0.0"],
  "allowed_components": null,
  "require_pinned": true,
  "require_attestation": false
}
```

`allowed_components` (when set) turns the gate into an allowlist. `banned_components` entries match either a bare name or `name@version`.

## Opt-in AI risk summary

`attestport sbom <dir> --ai` adds a natural-language risk summary to the SBOM **only if** a LOCAL Cognis AI backend is configured (`COGNIS_AI_BACKEND`). It is **off by default**, never required, and nothing leaves the box — with no backend configured the SBOM is byte-identical to a normal run.

## Built-in demo

See [`demos/01-basic/SCENARIO.md`](demos/01-basic/SCENARIO.md) for the full sbom → attest → verify → gate walkthrough.

## Output formats

- **Table** (default) — human-readable terminal summary
- **JSON** — machine-readable SBOM / gate findings for pipelines
- **SARIF** — drops into GitHub code-scanning / IDE problem panes

## Originality / clean-room

This is a **100% original, clean-room** implementation. It does not fork, vendor, or copy any third-party supply-chain project. It deliberately *targets* the public open specifications (SPDX/CycloneDX/in-toto/SLSA) — those are open standards anyone may emit — but every parser, hasher, signer, and gate rule here was written from scratch using only the Python standard library.

## How it fits the Cognis Neural Suite

`attestport` is one tool in the [Cognis Neural Suite](https://github.com/cognis-digital). Every tool ships an MCP server, so [Cognis.Studio](https://cognis.studio) agents can call them as scoped capabilities.

**Sibling tools in `dev-supply-chain`:** [`depgraph`](https://github.com/cognis-digital/depgraph), [`ossaudit`](https://github.com/cognis-digital/ossaudit), [`secretsweep`](https://github.com/cognis-digital/secretsweep), [`pipewatch-pro`](https://github.com/cognis-digital/pipewatch-pro)

## Architecture & roadmap

- Design notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Planned work: [`ROADMAP.md`](ROADMAP.md)

## Contributing

PRs, new lockfile parsers, and demo scenarios are welcome under the collaboration-pull model. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
