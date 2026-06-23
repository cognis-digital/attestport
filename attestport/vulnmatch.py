"""vulnmatch — offline SBOM-component CVE matching for ATTESTPORT.

Bridges the SBOM/gate engine to the bundled, fully-offline vulnerability
database (``vulndb_local.VulnDB`` over ``cognis_vulndb.jsonl.gz`` — ~262k real
OSV/GHSA records across PyPI, npm, Go, Maven, crates.io, RubyGems, NuGet).

The whole match runs with the Python standard library and **no network** — it
is the air-gap supply-chain gate's component-CVE stage: take what a build
declares (SBOM components / package names / CVE refs) and resolve it against the
bundled corpus, on a disconnected runner, with zero fabricated data.

Public surface:

    from attestport.vulnmatch import (
        normalize_ecosystem, match_component, match_components,
        match_sbom, lookup_cve, vuln_findings,
    )

Nothing here performs active scanning or network I/O. Refreshing/extending the
corpus is a separate, explicit, online step documented under ``datafeeds`` and
in the README's "Edge / air-gap refresh" section.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from attestport.core import Finding, sbom_components
from attestport.vulndb_local import VulnDB

# --------------------------------------------------------------------------- #
# Ecosystem normalization
# --------------------------------------------------------------------------- #
# The SBOM/lockfile layer speaks purl-style ecosystems (pypi, npm, golang,
# cargo). The bundled OSV corpus uses the OSV ecosystem spelling (PyPI, npm,
# Go, crates.io, ...). Map both ways so a component matches regardless of which
# spelling the caller used.
_ECO_TO_OSV = {
    "pypi": "PyPI",
    "npm": "npm",
    "golang": "Go",
    "go": "Go",
    "cargo": "crates.io",
    "crates.io": "crates.io",
    "crates": "crates.io",
    "maven": "Maven",
    "rubygems": "RubyGems",
    "gem": "RubyGems",
    "nuget": "NuGet",
}

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{3,}$", re.IGNORECASE)
_GHSA_RE = re.compile(r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$", re.IGNORECASE)


def normalize_ecosystem(ecosystem: Optional[str]) -> Optional[str]:
    """Map a purl-style ecosystem to the OSV spelling used by the bundled DB.

    Returns the canonical OSV ecosystem string, or ``None`` when the input is
    empty/unknown (an unknown ecosystem simply widens the match to all
    ecosystems rather than failing).
    """
    if not ecosystem:
        return None
    return _ECO_TO_OSV.get(ecosystem.strip().lower())


def is_cve_id(text: str) -> bool:
    return bool(_CVE_RE.match((text or "").strip()))


def is_ghsa_id(text: str) -> bool:
    return bool(_GHSA_RE.match((text or "").strip()))


# --------------------------------------------------------------------------- #
# Package-name candidates
# --------------------------------------------------------------------------- #
def _name_candidates(name: str, ecosystem: Optional[str]) -> List[str]:
    """Generate the package-name spellings to probe in the DB index.

    Different layers carry a dependency's name differently:
      * Maven uses ``group:artifact`` while a lockfile/CLI user might pass just
        ``artifact`` (e.g. ``log4j-core``).
      * Go modules are full import paths; the short final segment is a useful
        fallback.
    We probe the exact name first, then conservative fallbacks.
    """
    name = (name or "").strip()
    if not name:
        return []
    cands = [name]
    low = name.lower()
    # Maven group:artifact -> artifact
    if ":" in name:
        cands.append(name.split(":")[-1])
    # Go/import path final segment
    if "/" in name:
        cands.append(name.rstrip("/").split("/")[-1])
    # de-dup, preserve order
    seen: set = set()
    out: List[str] = []
    for c in cands:
        cl = c.lower()
        if cl and cl not in seen:
            seen.add(cl)
            out.append(c)
    return out


def _record_brief(rec: Dict[str, Any]) -> Dict[str, Any]:
    """A compact, JSON-serializable view of a DB record for output."""
    return {
        "id": rec.get("id", ""),
        "aliases": list(rec.get("aliases") or []),
        "ecosystem": rec.get("ecosystem", ""),
        "summary": rec.get("summary", ""),
        "severity": rec.get("severity", ""),
        "published": rec.get("published", ""),
        "modified": rec.get("modified", ""),
        "packages": list(rec.get("packages") or []),
        "ref_count": rec.get("ref_count", 0),
    }


# --------------------------------------------------------------------------- #
# Severity inference (CVSS vector / score -> attestport severity bucket)
# --------------------------------------------------------------------------- #
_CVSS_SCORE_RE = re.compile(r"(\d+(?:\.\d+)?)")


def severity_bucket(severity_field: str) -> str:
    """Map an OSV severity string (CVSS vector or numeric) to a bucket.

    Returns one of ``critical/high/medium/low/info``. An empty or
    unparseable severity yields ``"medium"`` (a known vuln with unknown score
    is still actionable, but we do not inflate it to high/critical).
    """
    s = (severity_field or "").strip()
    if not s:
        return "medium"
    score: Optional[float] = None
    # CVSS:3.x vector -> derive a coarse score from the impact metrics. We do
    # NOT fully recompute CVSS (no fabricated precision); we bucket on the
    # impact letters, which is deterministic and conservative.
    up = s.upper()
    if up.startswith("CVSS:"):
        high_impact = up.count(":H")
        if "/C:H" in up and "/I:H" in up and "/A:H" in up:
            return "critical" if "/S:C" in up else "high"
        if high_impact >= 2:
            return "high"
        if high_impact == 1 or "/C:L" in up or "/I:L" in up or "/A:L" in up:
            return "medium"
        return "low"
    # numeric score
    m = _CVSS_SCORE_RE.search(s)
    if m:
        try:
            score = float(m.group(1))
        except ValueError:
            score = None
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


# --------------------------------------------------------------------------- #
# Component matching
# --------------------------------------------------------------------------- #
# Lazy short-name index: maps the final segment of a Maven group:artifact or a
# Go import path to the records whose package list contains a name ending in
# that segment. Built once per VulnDB instance, on first use, so an artifact
# passed by its short name (e.g. ``log4j-core`` for
# ``org.apache.logging.log4j:log4j-core``) still resolves offline.
_SHORT_INDEX_CACHE: Dict[int, Dict[str, List[dict]]] = {}


def _short_index(db: VulnDB) -> Dict[str, List[dict]]:
    key = id(db)
    cached = _SHORT_INDEX_CACHE.get(key)
    if cached is not None:
        return cached
    idx: Dict[str, List[dict]] = {}
    for rec in db.load():
        for pkg in (rec.get("packages") or []):
            if not pkg:
                continue
            for sep in (":", "/"):
                if sep in pkg:
                    short = pkg.rsplit(sep, 1)[-1].lower()
                    if short and short != pkg.lower():
                        idx.setdefault(short, []).append(rec)
    _SHORT_INDEX_CACHE[key] = idx
    return idx


def match_component(name: str, ecosystem: Optional[str] = None,
                    db: Optional[VulnDB] = None) -> List[Dict[str, Any]]:
    """Return brief records for vulns affecting *name* in *ecosystem*.

    Matching is offline and exact on package name first, then conservative
    group/path short-name fallbacks (Maven ``group:artifact``, Go import
    paths). When *ecosystem* is given and recognized, results are filtered to
    that OSV ecosystem; otherwise all ecosystems are returned.
    """
    db = db or VulnDB()
    osv_eco = normalize_ecosystem(ecosystem)
    hits: List[Dict[str, Any]] = []
    seen_ids: set = set()

    def _add(rec: dict) -> None:
        rid = rec.get("id", "")
        if rid in seen_ids:
            return
        if osv_eco and rec.get("ecosystem", "").lower() != osv_eco.lower():
            return
        seen_ids.add(rid)
        hits.append(_record_brief(rec))

    candidates = _name_candidates(name, ecosystem)
    # 1. exact package-name index
    for cand in candidates:
        for rec in db.by_package(cand, ecosystem=osv_eco):
            _add(rec)
    # 2. short-name fallback (group:artifact / import-path tail) — only when the
    #    exact lookup found nothing, to avoid over-broad matches.
    if not hits:
        short_idx = _short_index(db)
        for cand in candidates:
            for rec in short_idx.get(cand.lower(), []):
                _add(rec)

    hits.sort(key=lambda r: r.get("id", ""))
    return hits


def match_components(components: List[Dict[str, Any]],
                     db: Optional[VulnDB] = None) -> List[Dict[str, Any]]:
    """Match a list of SBOM/CycloneDX components against the bundled DB.

    Each input component is a dict with at least ``name``; ``version`` and an
    ecosystem (CycloneDX property ``attestport:ecosystem`` or a ``purl``) are
    used when present. Returns a list of ``{component, ecosystem, version,
    vulns:[...]}`` entries — only components with >=1 match are included.
    """
    db = db or VulnDB()
    out: List[Dict[str, Any]] = []
    for comp in components:
        name = str(comp.get("name", ""))
        if not name:
            continue
        version = str(comp.get("version", ""))
        eco = _component_ecosystem(comp)
        vulns = match_component(name, ecosystem=eco, db=db)
        if vulns:
            out.append({
                "component": name,
                "ecosystem": eco or "",
                "version": version,
                "vuln_count": len(vulns),
                "vulns": vulns,
            })
    out.sort(key=lambda e: (-e["vuln_count"], e["component"].lower()))
    return out


def _component_ecosystem(comp: Dict[str, Any]) -> Optional[str]:
    """Pull an ecosystem from a CycloneDX component (property or purl)."""
    for prop in comp.get("properties", []) or []:
        if prop.get("name") == "attestport:ecosystem":
            return str(prop.get("value", "")) or None
    purl = str(comp.get("purl", ""))
    if purl.startswith("pkg:"):
        rest = purl[4:]
        return rest.split("/", 1)[0] or None
    return None


def match_sbom(sbom: Dict[str, Any],
               db: Optional[VulnDB] = None) -> List[Dict[str, Any]]:
    """Match every component in a generated SBOM against the bundled DB."""
    return match_components(sbom_components(sbom), db=db)


# --------------------------------------------------------------------------- #
# Direct CVE / advisory lookup
# --------------------------------------------------------------------------- #
def lookup_cve(cve_or_ghsa: str,
               db: Optional[VulnDB] = None) -> List[Dict[str, Any]]:
    """Resolve a CVE or GHSA id to brief records from the bundled DB."""
    db = db or VulnDB()
    return [_record_brief(r) for r in db.by_cve(cve_or_ghsa)]


# --------------------------------------------------------------------------- #
# Gate integration — turn matches into attestport Findings
# --------------------------------------------------------------------------- #
def vuln_findings(components: List[Dict[str, Any]],
                  db: Optional[VulnDB] = None,
                  max_per_component: int = 25) -> List[Finding]:
    """Produce gate ``Finding`` objects for vulnerable components.

    Severity is inferred per-vuln from the OSV CVSS field. This is the
    component-CVE stage of the air-gap gate; it never fabricates a vuln — every
    Finding is backed by a real record in the bundled corpus.
    """
    db = db or VulnDB()
    findings: List[Finding] = []
    for entry in match_components(components, db=db):
        comp_id = f"{entry['component']}@{entry['version']}" if entry["version"] \
            else entry["component"]
        for vuln in entry["vulns"][:max_per_component]:
            sev = severity_bucket(vuln.get("severity", ""))
            ident = vuln.get("id", "")
            aliases = vuln.get("aliases") or []
            cve = next((a for a in aliases if is_cve_id(a)), ident)
            findings.append(Finding(
                rule="vuln.known",
                severity=sev,
                message=f"{entry['component']}@{entry['version']}: {cve} — "
                        + (vuln.get("summary", "") or "known vulnerability"),
                component=comp_id,
                remediation=f"Review advisory {ident} and upgrade past the "
                            f"affected version range.",
            ))
    return findings
