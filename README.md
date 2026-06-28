# ATTESTPORT — air-gap software supply-chain gate

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `dev-supply-chain`

[![PyPI](https://img.shields.io/pypi/v/cognis-attestport.svg)](https://pypi.org/project/cognis-attestport/)
[![CI](https://github.com/cognis-digital/attestport/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/attestport/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)
[![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

**SBOM (CycloneDX-style) + SLSA/in-toto-style provenance, signature, and a CI policy gate — built for air-gapped pipelines.**

*Developer & Supply-Chain Security — knowing what you ship, and proving it, without phoning home.*


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ attestport-emit --version
attestport 0.1.0
```

```console
$ attestport-emit --help
usage: attestport [-h] [--version]
                  {sbom,attest,verify,gate,match,vulndb,mcp} ...

Air-gap software supply-chain gate — SBOM (CycloneDX), SLSA/in-toto-style
provenance + signature, CI policy gate.

positional arguments:
  {sbom,attest,verify,gate,match,vulndb,mcp}
    sbom                Generate a CycloneDX-style SBOM for a project.
    attest              Produce a signed SLSA/in-toto-style provenance
                        attestation for an artifact.
    verify              Verify an artifact against its attestation.
    gate                CI policy gate over a project directory.
    match               Match a project's components against the bundled
                        offline vulnerability DB.
    vulndb              Query the bundled offline vulnerability DB.
    mcp                 Run as an MCP server (stdio JSON-RPC).

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
```

> Blocks above are real `attestport` output — reproduce them from a clone.

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
"findings": [
    {
        "id": "123456",
        "title": "Suspicious Activity",
        "description": "Potential malicious activity detected",
        "created_by": "John Doe",
        "created_at": "2023-02-20T14:30:00Z"
    },
    {
        "id": "789012",
        "title": "Malware Detection",
        "description": "Malicious software identified",
        "created_by": "Jane Smith",
        "created_at": "2023-02-21T10:45:00Z"
    }
]
}
```

<!-- cognis:example:end -->

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
6. **Match components against known CVEs — fully offline:**
   ```bash
   attestport match ./myproject                       # human table
   attestport gate ./myproject --vuln --fail-on high  # fold CVE findings into the gate
   ```
   Signing keys come from `--key`, the `ATTESTPORT_KEY` env var, or a demo key. Also: `attestport vulndb`, `attestport mcp`.

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

# 5. Match the project's components against the bundled offline CVE database
attestport match demos/01-basic/demoproj

# ...or fold component-CVE findings straight into the gate:
attestport gate demos/01-basic/demoproj --vuln --fail-on high

# expose the engine to agents over MCP (stdio):
attestport mcp
```

## Commands

| Command | What it does |
|---------|--------------|
| `sbom <dir>`      | Walk a project, detect dependencies from lockfiles, hash files, emit a CycloneDX-style SBOM. |
| `attest <artifact>` | Build an in-toto `Statement` + SLSA-style provenance predicate (subject digest, builder, materials, bound SBOM digest) and attach a detached signature. |
| `verify <artifact> <attestation>` | Recompute the subject digest, check the signature, optionally enforce a component policy. Non-zero on any mismatch. |
| `gate <dir> --policy policy.json` | CI gate: fail on banned licenses, known-bad components, unpinned deps, or a missing/invalid attestation. Add `--vuln` to also match components against the bundled CVE DB. `table` / `json` / `sarif` output + `--fail-on`. |
| `match <dir>` | Match the project's components against the bundled offline vulnerability DB (262k real OSV/GHSA records). `table` / `json`; `--fail-on-match` for CI. |
| `vulndb {count,cve,package,search}` | Query the bundled offline vuln DB directly — e.g. `attestport vulndb cve CVE-2021-44228`. |
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

## Offline component → CVE matching (bundled vuln DB)

`attestport` ships a consolidated, compressed **OSV/GHSA corpus** —
`attestport/cognis_vulndb.jsonl.gz`, **~262,000 real vulnerability records**
across PyPI, npm, Go, Maven, crates.io, RubyGems, and NuGet. The match stage
takes the components your build *declares* and resolves them against that corpus
**with the standard library and no network** — exactly what an air-gapped runner
needs. Nothing here is fabricated: every finding is backed by a real record in
the bundle.

```bash
# Look up the canonical log4shell advisory straight from the bundle:
$ attestport vulndb cve CVE-2021-44228
[
  {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "aliases": ["CVE-2021-44228"],
    "ecosystem": "Maven",
    "summary": "Remote code injection in Log4j",
    "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H",
    "packages": ["org.apache.logging.log4j:log4j-core", "..."]
  }
]

# Match a whole project's components (worked example, real output trimmed):
$ attestport match demos/01-basic/demoproj
ATTESTPORT vuln match — demos/01-basic/demoproj
====================================================================
urllib3@2.2.1 [pypi] — 34 vuln(s)
    - GHSA-34jh-p97f-mpxf (CVE-2024-37891)
        urllib3's Proxy-Authorization header isn't stripped on cross-origin redirect
    - GHSA-48p4-8xcf-vxj5 (CVE-2025-50182)
        urllib3 does not control redirects in browsers and Node.js
requests@2.31.0 [pypi] — 13 vuln(s)
    ...
--------------------------------------------------------------------
components=3 vulnerable=3 vulns=...
```

Other queries:

```bash
attestport vulndb count                                    # -> 262351
attestport vulndb package lodash --ecosystem npm           # vulns for a package
attestport vulndb search deserialization --limit 10        # summary substring search
attestport match ./proj --format json --out cve.json       # machine-readable
attestport gate ./proj --vuln --format sarif --out gate.sarif   # CVE findings as SARIF
```

Severity for each matched vuln is derived deterministically from the record's
CVSS field and bucketed to `critical/high/medium/low/info`, so `--vuln` plays
cleanly with `--fail-on`.

## Edge / air-gap intel refresh

The bundled DB is the **offline baseline** — the tool is fully useful the moment
it's cloned, with no network. To keep it current on connected gear (and then
sneakernet the refresh into a disconnected enclave), `attestport` includes a
keyless feed catalog ([`attestport/data_feeds_2026.json`](attestport/data_feeds_2026.json))
and an edge-deployable ingester ([`attestport/datafeeds.py`](attestport/datafeeds.py)):

```bash
# List catalogued real, mostly-keyless intel feeds (CISA KEV, EPSS, OSV, NVD, GHSA, ...)
python -m attestport.datafeeds list --domain vuln

# On a CONNECTED host: refresh + cache feeds, or bulk-harvest CVEs from NVD/GHSA
python -m attestport.datafeeds update cisa-kev epss osv
python -m attestport.datafeeds bulk nvd-cve --max 200000

# Package the cache for transfer, then import it inside the air gap (no network):
python -m attestport.datafeeds snapshot-export feeds.tar.gz
#   --- carry feeds.tar.gz across the gap ---
python -m attestport.datafeeds snapshot-import feeds.tar.gz
python -m attestport.datafeeds get cisa-kev --offline       # serves the cache only
```

Design for the edge: standard library only (`urllib`), a disk cache with
per-feed freshness metadata (`COGNIS_FEEDS_CACHE`), an `offline=True` mode that
never touches the network, and tar snapshots for sneakernet. **Refresh is the
only step that uses the network, it is explicit and operator-initiated, and it
only ever fetches public advisory data — the tool itself never phones home and
performs no active scanning.**

## Language ports (Node / Go / Rust)

The trust-critical primitives — deterministic SBOM hashing and signed
provenance — are also implemented natively in **Node.js**, **Go**, and **Rust**
under [`ports/`](ports/), each zero-dependency and air-gap-buildable. They share
`attestport`'s canonical-JSON + HMAC-SHA256 contract, so an attestation signed by
one verifies under any other on a shared key. CI
([`.github/workflows/ports.yml`](.github/workflows/ports.yml)) builds and tests
all three on every push and proves Python→Node cross-verification. See
[`ports/README.md`](ports/README.md).

```bash
node ports/node/attestport.mjs sbom ./myproject
cd ports/go   && go run . sbom ../../myproject
cd ports/rust && cargo run -- sbom ../../myproject
```

## Scope, authorization & safety

`attestport` is a **defensive, passive, offline** tool. It reads files you point
it at, hashes them, and matches declared components against a bundled, real CVE
corpus. It does **not** perform active or network scanning, it sends no exploit
traffic, and it never contacts a target system. The only optional network use is
the operator-initiated **intel refresh** above, which fetches public advisory
feeds (NVD/OSV/GHSA/CISA KEV) and nothing else. Use it on code and artifacts you
are authorized to inspect.

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

`attestport` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## Integrations

Forward `attestport`'s findings to STIX/MISP/Sigma/Splunk/Elastic/Slack/webhooks via
[`cognis-connect`](https://github.com/cognis-digital/cognis-connect). See **[INTEGRATIONS.md](INTEGRATIONS.md)**.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
