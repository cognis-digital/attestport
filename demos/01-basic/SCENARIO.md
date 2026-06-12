# Demo 01 — SBOM, attestation, and a failing CI gate

This scenario walks the full ATTESTPORT loop against `demoproj/`, a small
project carrying a Python `requirements.txt` and an npm `package-lock.json`
that are deliberately not airtight.

## 1. Generate an SBOM

```bash
python -m attestport sbom demos/01-basic/demoproj
```

Emits a CycloneDX-style JSON document: components detected from both lockfiles
(`requests`, `urllib3`, `flask`, `pyyaml`, `leftpad-clone`, `left-pad`,
`lodash`), each with a purl, pinned flag, and any lockfile integrity hash, plus
a deterministic `source-digest` over the hashed file inventory.

## 2. Attest the project

```bash
python -m attestport sbom demos/01-basic/demoproj --out sbom.json
python -m attestport attest demos/01-basic/demoproj --sbom sbom.json --out att.json
```

Produces an in-toto `Statement` with an SLSA-style provenance predicate
(subject digest + builder + bound SBOM digest) and a detached HMAC-SHA256
signature. (The demo uses an insecure built-in key and warns about it; set
`ATTESTPORT_KEY` or pass `--key` for real use, and an HSM/asymmetric key in
production.)

## 3. Verify — PASS, then FAIL on tamper

```bash
python -m attestport verify demos/01-basic/demoproj att.json        # PASS
# Now mutate any file in demoproj/ and re-run — the subject digest no longer
# matches, so verify FAILS and exits non-zero.
```

## 4. Gate the project — FAILS the policy

```bash
python -m attestport gate demos/01-basic/demoproj --policy demos/01-basic/policy.json
```

| Domain     | Issue                                                          | Severity |
|------------|----------------------------------------------------------------|----------|
| Component  | `left-pad` / `leftpad-clone` are on the known-bad ban list      | critical |
| Dependency | `flask` and `leftpad-clone` are not pinned to exact versions    | medium   |

Because a critical finding is present, the gate exits non-zero, failing any CI
pipeline that wraps it. Add `--format sarif` to feed GitHub code-scanning.
