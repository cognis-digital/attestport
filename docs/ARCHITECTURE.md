# ATTESTPORT — Architecture

ATTESTPORT is a single Python package (`attestport/`) with no third-party
dependencies. Everything is computed locally so it runs in an air-gapped CI
runner.

```
attestport/
  core.py        # the engine: parsers, hashing, SBOM, attest/verify, gate, SARIF
  cli.py         # argparse front end (sbom / attest / verify / gate / mcp)
  mcp_server.py  # stdio JSON-RPC MCP server exposing sbom / verify / gate
  ai.py          # opt-in, off-by-default local AI risk summary (degrades to None)
  __main__.py    # `python -m attestport`
```

## Data flow

```
            lockfiles + files                  artifact
                  │                                │
                  ▼                                ▼
   detect_components() + hash_tree()        sha256_file / merkle_digest
                  │                                │
                  ▼                                ▼
            generate_sbom()  ─────bind────►  build_statement()
            (CycloneDX-style)                (in-toto + SLSA predicate)
                                                   │
                                                   ▼
                                            sign_statement()
                                            (detached HMAC-SHA256
                                             over canonical bytes)
                                                   │
                          ┌────────────────────────┴───────────────┐
                          ▼                                          ▼
                      verify()                                   gate(policy)
            (recompute digest + check sig)            (banned licenses / components,
                                                       unpinned deps, attestation)
```

## Determinism

`canonical_bytes()` serializes JSON with sorted keys, no insignificant
whitespace, and UTF-8. Every digest and signature is derived from these bytes,
so two runs on two machines over the same inputs produce identical output —
essential for reproducible, portable attestations.

## Why HMAC for signing

A keyed HMAC needs only `hashlib`/`hmac` (no key infrastructure, no network),
which is exactly the constraint of an air-gapped runner. It provides integrity
and authenticity against a shared secret. The signature block records the
algorithm and a key hint and binds the exact signed payload digest, so `verify`
is unambiguous. Production deployments should set `ATTESTPORT_KEY` and, at the
integration boundary, move to an asymmetric scheme or an HSM — see the README.

## Extending

- **New lockfile**: add a parser returning `List[Component]` and register it in
  `_LOCKFILES` / `_PARSERS`.
- **New gate rule**: append a `Finding` inside `gate()`.
- **New signer**: replace `sign_statement` / the HMAC in `verify` behind the
  same `(statement, key) -> envelope` shape.
