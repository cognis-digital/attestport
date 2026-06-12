"""Core engine for ATTESTPORT — air-gap software supply-chain attestation.

ATTESTPORT is a clean-room, original implementation. It *targets* the public,
open specifications that the supply-chain ecosystem has standardized on
(SPDX, CycloneDX, in-toto, SLSA) — those are open standards anyone may emit —
but the code here is written from scratch: no third-party scanner, signer, or
provenance library is forked, vendored, or copied.

Four capabilities, all computed locally with the Python standard library so the
tool runs inside an air-gapped CI runner with no network and no pip install:

  * sbom    — walk a project, detect declared dependencies from common
              lockfiles, hash every file, and emit a CycloneDX-style SBOM.
  * attest  — produce an in-toto/SLSA-style provenance statement (subject
              digest + builder + materials) plus a detached keyed signature
              (HMAC-SHA256 over the canonical statement bytes).
  * verify  — recompute the subject digest, check the signature, and confirm
              the SBOM components satisfy an allow policy.
  * gate    — a CI policy gate: fail on banned licenses, known-bad components,
              unpinned dependencies, or a missing/invalid attestation.

Signing model: the detached signature is a keyed HMAC over the canonical
statement bytes. This gives integrity + authenticity against a shared secret
and needs nothing beyond ``hashlib``/``hmac``. It is intentionally *not* a
public-key scheme — production deployments should swap in real asymmetric keys
or an HSM. This is documented in the README and surfaced in the statement's
``signature.algorithm`` field as ``hmac-sha256``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

# Tool identity (re-exported from the package __init__).
TOOL_NAME = "attestport"
TOOL_VERSION = "0.1.0"

# CycloneDX-style document constants we target (the format is an open spec).
CYCLONEDX_VERSION = "1.5"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

# Severity ordering, highest first — used for gate exit-code policy + sorting.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Lockfiles we know how to parse, mapped to (ecosystem, parser-name).
_LOCKFILES = {
    "requirements.txt": "pypi",
    "package-lock.json": "npm",
    "go.sum": "golang",
    "Cargo.lock": "cargo",
}

# Files/dirs we never treat as project content when hashing.
_SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build",
    ".pytest_cache", ".mypy_cache", "target", ".idea", ".vscode",
}

# A version string that is *not* a single pinned version (ranges/wildcards).
_UNPINNED_RE = re.compile(r"[<>~^*]|\bx\b|,| - |\|\|")


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #
class AttestError(ValueError):
    """Raised on malformed input, bad attestations, or policy-load failures."""


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Component:
    """A single SBOM component (CycloneDX-style)."""
    name: str
    version: str
    ecosystem: str
    purl: str = ""
    license: str = ""
    pinned: bool = True
    hashes: List[Dict[str, str]] = field(default_factory=list)

    def to_cyclonedx(self) -> Dict[str, Any]:
        comp: Dict[str, Any] = {
            "type": "library",
            "name": self.name,
            "version": self.version,
            "bom-ref": self.purl or f"{self.ecosystem}:{self.name}@{self.version}",
        }
        if self.purl:
            comp["purl"] = self.purl
        if self.license:
            comp["licenses"] = [{"license": {"id": self.license}}]
        if self.hashes:
            comp["hashes"] = self.hashes
        comp["properties"] = [
            {"name": "attestport:ecosystem", "value": self.ecosystem},
            {"name": "attestport:pinned", "value": "true" if self.pinned else "false"},
        ]
        return comp


@dataclass
class Finding:
    """A policy-gate finding."""
    rule: str
    severity: str
    message: str
    component: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GateReport:
    source: str
    findings: List[Finding] = field(default_factory=list)

    @property
    def counts(self) -> Dict[str, int]:
        c = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    @property
    def failed(self) -> bool:
        c = self.counts
        return c["critical"] > 0 or c["high"] > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "failed": self.failed,
            "counts": self.counts,
            "findings": [f.to_dict() for f in self.findings],
        }


# --------------------------------------------------------------------------- #
# Canonicalization + hashing helpers
# --------------------------------------------------------------------------- #
def canonical_bytes(obj: Any) -> bytes:
    """Deterministic JSON encoding used for hashing and signing.

    Keys sorted, no insignificant whitespace, UTF-8. Two semantically equal
    objects always produce identical bytes, which is what makes the digest and
    signature reproducible across machines (and air-gapped runners).
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# Lockfile parsers (original implementations)
# --------------------------------------------------------------------------- #
def _purl(ecosystem: str, name: str, version: str) -> str:
    """Build a Package-URL (purl) string — an open, vendor-neutral spec."""
    eco = {"pypi": "pypi", "npm": "npm", "golang": "golang", "cargo": "cargo"}.get(
        ecosystem, ecosystem)
    safe = name.replace("@", "%40")
    return f"pkg:{eco}/{safe}@{version}" if version else f"pkg:{eco}/{safe}"


def _parse_requirements(text: str) -> List[Component]:
    comps: List[Component] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        # Drop environment markers / extras for the component identity.
        line = line.split(";", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(\[[^\]]*\])?\s*(.*)$", line)
        if not m:
            continue
        name = m.group(1)
        spec = (m.group(3) or "").strip()
        pinned = spec.startswith("==") and not _UNPINNED_RE.search(spec[2:])
        version = spec[2:].strip() if spec.startswith("==") else spec.lstrip("=<>~!^ ")
        comps.append(Component(name=name, version=version, ecosystem="pypi",
                               purl=_purl("pypi", name, version if pinned else ""),
                               pinned=pinned))
    return comps


def _parse_package_lock(text: str) -> List[Component]:
    comps: List[Component] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AttestError(f"package-lock.json is not valid JSON: {exc}") from exc
    # lockfileVersion 2/3: "packages" map keyed by node_modules path.
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict):
                continue  # "" is the root project itself
            name = path.split("node_modules/")[-1]
            version = str(meta.get("version", ""))
            integrity = str(meta.get("integrity", ""))
            comp = Component(name=name, version=version, ecosystem="npm",
                             purl=_purl("npm", name, version), pinned=bool(version))
            if integrity:
                comp.hashes = [_integrity_to_hash(integrity)]
            comps.append(comp)
        if comps:
            return comps
    # lockfileVersion 1: flat "dependencies" map.
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            version = str(meta.get("version", ""))
            comps.append(Component(name=name, version=version, ecosystem="npm",
                                   purl=_purl("npm", name, version),
                                   pinned=bool(version)))
    return comps


def _integrity_to_hash(integrity: str) -> Dict[str, str]:
    """Map an npm SRI 'sha512-<base64>' / 'sha256-...' string to a CycloneDX hash."""
    alg, _, _ = integrity.partition("-")
    alg_map = {"sha512": "SHA-512", "sha256": "SHA-256", "sha1": "SHA-1"}
    return {"alg": alg_map.get(alg, alg.upper()), "content": integrity}


def _parse_go_sum(text: str) -> List[Component]:
    comps: List[Component] = []
    seen: set = set()
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) < 3:
            continue
        module, version = parts[0], parts[1]
        # go.sum lists both the module zip and its go.mod; collapse to one.
        version = version.replace("/go.mod", "")
        key = (module, version)
        if key in seen:
            continue
        seen.add(key)
        comps.append(Component(name=module, version=version, ecosystem="golang",
                               purl=_purl("golang", module, version),
                               pinned=bool(version),
                               hashes=[{"alg": "go-h1", "content": parts[2]}]))
    return comps


def _parse_cargo_lock(text: str) -> List[Component]:
    """Minimal TOML parser for Cargo.lock's [[package]] tables (stdlib only)."""
    comps: List[Component] = []
    name = version = checksum = ""
    in_pkg = False

    def flush():
        nonlocal name, version, checksum
        if name:
            comp = Component(name=name, version=version, ecosystem="cargo",
                             purl=_purl("cargo", name, version),
                             pinned=bool(version))
            if checksum:
                comp.hashes = [{"alg": "SHA-256", "content": checksum}]
            comps.append(comp)
        name = version = checksum = ""

    for raw in text.splitlines():
        line = raw.strip()
        if line == "[[package]]":
            if in_pkg:
                flush()
            in_pkg = True
            continue
        if line.startswith("[") and line != "[[package]]":
            if in_pkg:
                flush()
            in_pkg = False
            continue
        if not in_pkg:
            continue
        m = re.match(r'^(\w+)\s*=\s*"([^"]*)"', line)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        if key == "name":
            name = val
        elif key == "version":
            version = val
        elif key == "checksum":
            checksum = val
    if in_pkg:
        flush()
    return comps


_PARSERS = {
    "pypi": _parse_requirements,
    "npm": _parse_package_lock,
    "golang": _parse_go_sum,
    "cargo": _parse_cargo_lock,
}


def detect_components(directory: str) -> List[Component]:
    """Detect declared dependencies from any known lockfiles in *directory*."""
    if not os.path.isdir(directory):
        raise AttestError(f"not a directory: {directory}")
    comps: List[Component] = []
    for fname, ecosystem in _LOCKFILES.items():
        path = os.path.join(directory, fname)
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        try:
            comps.extend(_PARSERS[ecosystem](text))
        except AttestError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            raise AttestError(f"failed parsing {fname}: {exc}") from exc
    # De-dup on (ecosystem, name, version), keep first (richest) occurrence.
    out: List[Component] = []
    seen: set = set()
    for c in comps:
        key = (c.ecosystem, c.name, c.version)
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    out.sort(key=lambda c: (c.ecosystem, c.name.lower(), c.version))
    return out


# --------------------------------------------------------------------------- #
# File inventory (for the SBOM "files" view + the attest subject merkle)
# --------------------------------------------------------------------------- #
def hash_tree(directory: str) -> List[Dict[str, str]]:
    """Hash every regular file under *directory*, skipping noise dirs."""
    files: List[Dict[str, str]] = []
    for root, dirs, names in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for nm in names:
            full = os.path.join(root, nm)
            try:
                rel = os.path.relpath(full, directory).replace(os.sep, "/")
                files.append({"path": rel, "sha256": sha256_file(full)})
            except OSError:
                continue
    files.sort(key=lambda f: f["path"])
    return files


def merkle_digest(files: List[Dict[str, str]]) -> str:
    """A single deterministic digest over the (path, sha256) inventory."""
    return sha256_bytes(canonical_bytes(
        [[f["path"], f["sha256"]] for f in files]))


# --------------------------------------------------------------------------- #
# SBOM (CycloneDX-style)
# --------------------------------------------------------------------------- #
def generate_sbom(directory: str, include_files: bool = True) -> Dict[str, Any]:
    components = detect_components(directory)
    files = hash_tree(directory) if include_files else []
    root_name = os.path.basename(os.path.abspath(directory)) or "project"
    serial = "urn:uuid:" + _deterministic_uuid(root_name, merkle_digest(files))

    bom: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_VERSION,
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "tools": [{"vendor": "Cognis Digital", "name": TOOL_NAME,
                       "version": TOOL_VERSION}],
            "component": {
                "type": "application",
                "name": root_name,
                "bom-ref": f"root:{root_name}",
            },
            "properties": [
                {"name": "attestport:file-count", "value": str(len(files))},
                {"name": "attestport:source-digest", "value": merkle_digest(files)},
            ],
        },
        "components": [c.to_cyclonedx() for c in components],
    }
    if include_files:
        # Files are not standard CycloneDX components; carry them under a
        # namespaced property block so consumers that only read `components`
        # are unaffected, while `attest` can still bind the full inventory.
        bom["properties"] = [{
            "name": "attestport:files",
            "value": json.dumps(files, separators=(",", ":")),
        }]
    return bom


def _deterministic_uuid(*parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return "-".join([digest[0:8], digest[8:12], digest[12:16],
                     digest[16:20], digest[20:32]])


def sbom_components(sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
    comps = sbom.get("components")
    return comps if isinstance(comps, list) else []


# --------------------------------------------------------------------------- #
# Attestation (in-toto / SLSA-style provenance + detached keyed signature)
# --------------------------------------------------------------------------- #
def _resolve_key(key: Optional[str]) -> bytes:
    """Resolve the signing/verifying key.

    Precedence: explicit ``key`` arg → ``ATTESTPORT_KEY`` env → a clearly
    labeled, insecure demo key (so demos run with zero setup). The demo key is
    never silent: callers print a warning when it is in force.
    """
    if key:
        return key.encode("utf-8")
    env = os.environ.get("ATTESTPORT_KEY")
    if env:
        return env.encode("utf-8")
    return b"attestport-insecure-demo-key"


def using_demo_key(key: Optional[str]) -> bool:
    return not key and not os.environ.get("ATTESTPORT_KEY")


def build_statement(artifact: str, builder: str = "",
                    sbom: Optional[Dict[str, Any]] = None,
                    materials: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
    """Build the unsigned in-toto Statement + SLSA-style provenance predicate."""
    if not os.path.exists(artifact):
        raise AttestError(f"artifact not found: {artifact}")
    if os.path.isdir(artifact):
        files = hash_tree(artifact)
        digest = merkle_digest(files)
        subj_name = os.path.basename(os.path.abspath(artifact))
    else:
        digest = sha256_file(artifact)
        subj_name = os.path.basename(artifact)

    predicate: Dict[str, Any] = {
        "buildType": "https://cognis.digital/attestport/buildtype/v1",
        "builder": {"id": builder or "attestport:local"},
        "invocation": {"configSource": {}},
        "materials": materials or [],
    }
    if sbom is not None:
        predicate["sbomDigest"] = sha256_bytes(canonical_bytes(sbom))
        predicate["componentCount"] = len(sbom_components(sbom))

    return {
        "_type": INTOTO_STATEMENT_TYPE,
        "predicateType": SLSA_PREDICATE_TYPE,
        "subject": [{"name": subj_name, "digest": {"sha256": digest}}],
        "predicate": predicate,
    }


def sign_statement(statement: Dict[str, Any], key: Optional[str] = None) -> Dict[str, Any]:
    """Attach a detached HMAC-SHA256 signature over the canonical statement."""
    payload = canonical_bytes(statement)
    sig = hmac.new(_resolve_key(key), payload, hashlib.sha256).hexdigest()
    envelope = dict(statement)
    envelope["signature"] = {
        "algorithm": "hmac-sha256",
        "value": sig,
        "keyHint": "env:ATTESTPORT_KEY" if not using_demo_key(key) else "demo",
        # Bind the exact bytes that were signed so verify is unambiguous.
        "payloadSha256": sha256_bytes(payload),
    }
    return envelope


def attest(artifact: str, builder: str = "",
           sbom: Optional[Dict[str, Any]] = None,
           materials: Optional[List[Dict[str, str]]] = None,
           key: Optional[str] = None) -> Dict[str, Any]:
    """Convenience: build + sign an attestation for *artifact*."""
    statement = build_statement(artifact, builder=builder, sbom=sbom,
                                materials=materials)
    return sign_statement(statement, key=key)


# --------------------------------------------------------------------------- #
# Verify
# --------------------------------------------------------------------------- #
def verify(artifact: str, attestation: Dict[str, Any],
           key: Optional[str] = None,
           policy: Optional[Dict[str, Any]] = None) -> Tuple[bool, List[str]]:
    """Verify digest + signature (+ optional component policy) for *artifact*.

    Returns ``(ok, problems)``. ``ok`` is True only when every check passes.
    """
    problems: List[str] = []

    sig = attestation.get("signature")
    if not isinstance(sig, dict) or "value" not in sig:
        return False, ["attestation has no signature block"]

    # 1. Signature integrity: recompute HMAC over the statement (minus the
    #    signature block) and compare in constant time.
    statement = {k: v for k, v in attestation.items() if k != "signature"}
    payload = canonical_bytes(statement)
    expected = hmac.new(_resolve_key(key), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(sig.get("value", ""))):
        problems.append("signature mismatch (wrong key or tampered statement)")
    # Cross-check the bound payload digest if present.
    bound = sig.get("payloadSha256")
    if bound and bound != sha256_bytes(payload):
        problems.append("payload digest mismatch (statement was modified)")

    # 2. Subject digest: recompute the artifact digest and compare.
    subjects = attestation.get("subject")
    if not isinstance(subjects, list) or not subjects:
        problems.append("attestation has no subject")
    else:
        claimed = str(subjects[0].get("digest", {}).get("sha256", ""))
        if not os.path.exists(artifact):
            problems.append(f"artifact not found: {artifact}")
        else:
            if os.path.isdir(artifact):
                actual = merkle_digest(hash_tree(artifact))
            else:
                actual = sha256_file(artifact)
            if claimed != actual:
                problems.append(
                    f"subject digest mismatch: attestation={claimed[:16]}… "
                    f"artifact={actual[:16]}…")

    # 3. Optional component policy (allowlist of name@version, banned set).
    if policy:
        comps = policy.get("_components")
        if isinstance(comps, list):
            pol_problems = _check_component_policy(comps, policy)
            problems.extend(pol_problems)

    return (len(problems) == 0), problems


def _check_component_policy(components: List[Dict[str, Any]],
                            policy: Dict[str, Any]) -> List[str]:
    problems: List[str] = []
    allowed = policy.get("allowed_components")
    banned = {b.lower() for b in policy.get("banned_components", [])}
    for comp in components:
        name = str(comp.get("name", ""))
        version = str(comp.get("version", ""))
        ident = f"{name}@{version}".lower()
        if banned and (name.lower() in banned or ident in banned):
            problems.append(f"banned component present: {name}@{version}")
        if isinstance(allowed, list) and allowed:
            allow_set = {a.lower() for a in allowed}
            if name.lower() not in allow_set and ident not in allow_set:
                problems.append(f"component not on allowlist: {name}@{version}")
    return problems


# --------------------------------------------------------------------------- #
# Gate (CI policy)
# --------------------------------------------------------------------------- #
DEFAULT_POLICY: Dict[str, Any] = {
    "banned_licenses": ["GPL-3.0", "AGPL-3.0", "SSPL-1.0"],
    "banned_components": [],
    "require_pinned": True,
    "require_attestation": False,
}


def load_policy(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return dict(DEFAULT_POLICY)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise AttestError(f"could not load policy {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise AttestError("policy file must be a JSON object")
    merged = dict(DEFAULT_POLICY)
    merged.update(data)
    return merged


def gate(directory: str, policy: Dict[str, Any],
         attestation: Optional[Dict[str, Any]] = None) -> GateReport:
    """Evaluate a project against the supply-chain policy."""
    report = GateReport(source=directory)
    sbom = generate_sbom(directory, include_files=False)
    components = detect_components(directory)

    banned_lic = {x.lower() for x in policy.get("banned_licenses", [])}
    banned_comp = {x.lower() for x in policy.get("banned_components", [])}
    allowed_comp = policy.get("allowed_components")
    require_pinned = bool(policy.get("require_pinned", False))

    for c in components:
        ident = f"{c.name}@{c.version}".lower()
        if c.license and c.license.lower() in banned_lic:
            report.findings.append(Finding(
                rule="license.banned", severity="high",
                message=f"component '{c.name}' uses banned license {c.license}",
                component=ident,
                remediation="Replace the dependency or obtain a commercial exception."))
        if banned_comp and (c.name.lower() in banned_comp or ident in banned_comp):
            report.findings.append(Finding(
                rule="component.banned", severity="critical",
                message=f"known-bad component present: {c.name}@{c.version}",
                component=ident,
                remediation="Remove or replace this component immediately."))
        if isinstance(allowed_comp, list) and allowed_comp:
            allow_set = {a.lower() for a in allowed_comp}
            if c.name.lower() not in allow_set and ident not in allow_set:
                report.findings.append(Finding(
                    rule="component.not_allowlisted", severity="high",
                    message=f"component not on allowlist: {c.name}@{c.version}",
                    component=ident,
                    remediation="Add to the policy allowlist after review."))
        if require_pinned and not c.pinned:
            report.findings.append(Finding(
                rule="dependency.unpinned", severity="medium",
                message=f"dependency '{c.name}' is not pinned to an exact version "
                        f"(spec: {c.version or '<none>'})",
                component=ident,
                remediation="Pin to an exact version (e.g. name==1.2.3)."))

    if policy.get("require_attestation"):
        if attestation is None:
            report.findings.append(Finding(
                rule="attestation.missing", severity="high",
                message="policy requires an attestation but none was supplied",
                remediation="Run `attestport attest` and pass --attestation."))
        else:
            ok, probs = verify(directory, attestation)
            if not ok:
                report.findings.append(Finding(
                    rule="attestation.invalid", severity="critical",
                    message="supplied attestation failed verification: "
                            + "; ".join(probs),
                    remediation="Re-attest the artifact with a trusted key."))

    if not components and policy.get("require_components", False):
        report.findings.append(Finding(
            rule="sbom.empty", severity="medium",
            message="no dependencies detected from any known lockfile",
            remediation="Add a supported lockfile or relax require_components."))

    report.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return report


# --------------------------------------------------------------------------- #
# Renderers
# --------------------------------------------------------------------------- #
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def _security_severity(sev: str) -> str:
    return {"critical": "9.5", "high": "8.0", "medium": "5.0",
            "low": "3.0", "info": "0.0"}.get(sev, "5.0")


def to_sarif(report: GateReport) -> Dict[str, Any]:
    """Render a gate report as a SARIF 2.1.0 log (GitHub code-scanning ready)."""
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for f in report.findings:
        if f.rule not in rules:
            rules[f.rule] = {
                "id": f.rule,
                "name": f.rule,
                "shortDescription": {"text": f.rule},
                "fullDescription": {"text": f.remediation or f.message},
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL.get(f.severity, "warning")},
                "properties": {"security-severity": _security_severity(f.severity)},
            }
        results.append({
            "ruleId": f.rule,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message
                        + (f"\nRemediation: {f.remediation}" if f.remediation else "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": report.source.replace(os.sep, "/")},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"fullyQualifiedName": f.component or "project"}],
            }],
            "properties": {"severity": f.severity, "component": f.component},
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": "https://github.com/cognis-digital/attestport",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
