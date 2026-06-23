"""Command-line interface for ATTESTPORT."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from attestport import TOOL_NAME, TOOL_VERSION
from attestport.core import (
    AttestError,
    Finding,
    GateReport,
    SEVERITY_ORDER,
    attest,
    detect_components,
    gate,
    generate_sbom,
    load_policy,
    sbom_components,
    to_sarif,
    using_demo_key,
    verify,
)

_SEV_LABEL = {"critical": "CRIT", "high": "HIGH", "medium": "MED ",
              "low": "LOW ", "info": "INFO"}


def _emit(text: str, out: Optional[str]) -> None:
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        print(f"wrote {out}", file=sys.stderr)
    else:
        print(text)


def _read_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- #
# sbom
# --------------------------------------------------------------------------- #
def _run_sbom(args: argparse.Namespace) -> int:
    try:
        bom = generate_sbom(args.directory, include_files=not args.no_files)
    except (OSError, AttestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.ai:
        from attestport import ai
        summary = None
        try:
            summary = ai.summarize_sbom_risk(bom)
        except Exception:
            summary = None
        if summary:
            bom.setdefault("metadata", {}).setdefault("properties", []).append(
                {"name": "attestport:ai-risk-summary", "value": summary})
        else:
            print("note: --ai requested but no local AI backend is configured "
                  "(set COGNIS_AI_BACKEND); SBOM is unchanged.", file=sys.stderr)
    _emit(json.dumps(bom, indent=2), args.out)
    return 0


# --------------------------------------------------------------------------- #
# attest
# --------------------------------------------------------------------------- #
def _run_attest(args: argparse.Namespace) -> int:
    sbom = None
    if args.sbom:
        try:
            sbom = _read_json(args.sbom)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read SBOM {args.sbom}: {exc}", file=sys.stderr)
            return 2
    try:
        envelope = attest(args.artifact, builder=args.builder, sbom=sbom,
                          key=args.key)
    except (OSError, AttestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if using_demo_key(args.key):
        print("warning: signing with the INSECURE demo key. Set ATTESTPORT_KEY "
              "or pass --key for real attestations (production: use asymmetric "
              "keys / an HSM).", file=sys.stderr)
    _emit(json.dumps(envelope, indent=2), args.out)
    return 0


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #
def _run_verify(args: argparse.Namespace) -> int:
    try:
        attestation = _read_json(args.attestation)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read attestation: {exc}", file=sys.stderr)
        return 2

    policy = None
    if args.policy:
        try:
            policy = load_policy(args.policy)
        except AttestError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        # Bind the live SBOM components so the policy can be checked at verify.
        try:
            if os.path.isdir(args.artifact):
                policy["_components"] = sbom_components(
                    generate_sbom(args.artifact, include_files=False))
            else:
                policy["_components"] = []
        except (OSError, AttestError):
            policy["_components"] = []

    ok, problems = verify(args.artifact, attestation, key=args.key, policy=policy)
    if args.format == "json":
        _emit(json.dumps({"ok": ok, "problems": problems}, indent=2), args.out)
    else:
        if ok:
            print("VERIFY: PASS — signature valid and subject digest matches.")
        else:
            print("VERIFY: FAIL")
            for p in problems:
                print(f"  - {p}")
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# gate
# --------------------------------------------------------------------------- #
def _render_gate_table(report: GateReport) -> str:
    lines: List[str] = []
    lines.append(f"ATTESTPORT gate — {report.source}")
    lines.append("=" * 68)
    if not report.findings:
        lines.append("No findings. Project passes the supply-chain policy.")
    else:
        for f in report.findings:
            label = _SEV_LABEL.get(f.severity, f.severity.upper())
            lines.append(f"[{label}] {f.rule}")
            lines.append(f"        {f.message}")
            if f.component:
                lines.append(f"        component: {f.component}")
            if f.remediation:
                lines.append(f"        fix: {f.remediation}")
    c = report.counts
    lines.append("-" * 68)
    lines.append(f"critical={c['critical']} high={c['high']} medium={c['medium']} "
                 f"low={c['low']} info={c['info']}")
    lines.append("RESULT: " + ("FAIL" if report.failed else "PASS"))
    return "\n".join(lines)


def _fails_gate(report: GateReport, fail_on: Optional[str]) -> bool:
    if not fail_on:
        return report.failed
    threshold = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER.get(f.severity, 99) <= threshold
               for f in report.findings)


def _run_gate(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
    except AttestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    attestation = None
    if args.attestation:
        try:
            attestation = _read_json(args.attestation)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read attestation: {exc}", file=sys.stderr)
            return 2

    try:
        report = gate(args.directory, policy, attestation=attestation)
    except (OSError, AttestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Optional component-CVE stage: enrich the gate with offline matches from
    # the bundled vulnerability DB. Purely local, no network.
    if getattr(args, "vuln", False):
        try:
            from attestport.vulnmatch import vuln_findings
            comps = [c.to_cyclonedx() for c in detect_components(args.directory)]
            extra = vuln_findings(comps)
            report.findings.extend(extra)
            report.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        except (OSError, AttestError) as exc:
            print(f"error: vuln matching failed: {exc}", file=sys.stderr)
            return 2

    if args.format == "json":
        _emit(json.dumps(report.to_dict(), indent=2), args.out)
    elif args.format == "sarif":
        _emit(json.dumps(to_sarif(report), indent=2), args.out)
    else:
        _emit(_render_gate_table(report), args.out)

    return 1 if _fails_gate(report, args.fail_on) else 0


# --------------------------------------------------------------------------- #
# match — offline SBOM-component CVE matching against the bundled vuln DB
# --------------------------------------------------------------------------- #
def _run_match(args: argparse.Namespace) -> int:
    from attestport.vulnmatch import match_components

    try:
        comps = [c.to_cyclonedx() for c in detect_components(args.directory)]
    except (OSError, AttestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    matches = match_components(comps)
    total = sum(m["vuln_count"] for m in matches)

    if args.format == "json":
        _emit(json.dumps({
            "source": args.directory,
            "components_scanned": len(comps),
            "vulnerable_components": len(matches),
            "total_vulns": total,
            "matches": matches,
        }, indent=2), args.out)
    else:
        lines: List[str] = [f"ATTESTPORT vuln match — {args.directory}",
                            "=" * 68]
        if not matches:
            lines.append(f"No known vulnerabilities for {len(comps)} component(s) "
                         f"in the bundled DB.")
        else:
            for m in matches:
                lines.append(f"{m['component']}@{m['version']} "
                             f"[{m['ecosystem'] or '?'}] — {m['vuln_count']} vuln(s)")
                for v in m["vulns"][:args.limit]:
                    aliases = ", ".join(v["aliases"][:3]) or v["id"]
                    lines.append(f"    - {v['id']} ({aliases})")
                    if v["summary"]:
                        lines.append(f"        {v['summary'][:96]}")
        lines.append("-" * 68)
        lines.append(f"components={len(comps)} vulnerable={len(matches)} "
                     f"vulns={total}")
        _emit("\n".join(lines), args.out)
    return 1 if (matches and args.fail_on_match) else 0


# --------------------------------------------------------------------------- #
# vulndb — query the bundled offline vulnerability database directly
# --------------------------------------------------------------------------- #
def _run_vulndb(args: argparse.Namespace) -> int:
    from attestport.vulndb_local import VulnDB
    from attestport.vulnmatch import lookup_cve, match_component

    db = VulnDB()
    if args.vulndb_command == "count":
        print(db.count())
        return 0
    if args.vulndb_command == "cve":
        recs = lookup_cve(args.id, db=db)
        _emit(json.dumps(recs, indent=2), args.out)
        return 0 if recs else 1
    if args.vulndb_command == "package":
        recs = match_component(args.name, ecosystem=args.ecosystem, db=db)
        _emit(json.dumps(recs, indent=2), args.out)
        return 0 if recs else 1
    if args.vulndb_command == "search":
        recs = db.search(args.text, limit=args.limit)
        brief = [{"id": r.get("id"), "ecosystem": r.get("ecosystem"),
                  "summary": r.get("summary"), "packages": r.get("packages")}
                 for r in recs]
        _emit(json.dumps(brief, indent=2), args.out)
        return 0 if brief else 1
    print("usage: attestport vulndb {count,cve,package,search}", file=sys.stderr)
    return 2


# --------------------------------------------------------------------------- #
# mcp
# --------------------------------------------------------------------------- #
def _run_mcp() -> int:
    from attestport.mcp_server import run_mcp_server
    run_mcp_server()
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Air-gap software supply-chain gate — SBOM (CycloneDX), "
                    "SLSA/in-toto-style provenance + signature, CI policy gate.")
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    sb = sub.add_parser("sbom", help="Generate a CycloneDX-style SBOM for a project.")
    sb.add_argument("directory", help="Project directory to inventory.")
    sb.add_argument("--out", help="Write output to this file instead of stdout.")
    sb.add_argument("--no-files", action="store_true",
                    help="Skip the file-hash inventory (components only).")
    sb.add_argument("--ai", action="store_true",
                    help="Add an AI risk summary using a LOCAL backend (opt-in, "
                         "off by default; requires COGNIS_AI_BACKEND).")

    at = sub.add_parser("attest", help="Produce a signed SLSA/in-toto-style "
                                       "provenance attestation for an artifact.")
    at.add_argument("artifact", help="File or directory to attest.")
    at.add_argument("--builder", default="", help="Builder identity to record.")
    at.add_argument("--sbom", help="SBOM JSON to bind into the provenance.")
    at.add_argument("--key", help="Signing key (else ATTESTPORT_KEY env, else demo key).")
    at.add_argument("--out", help="Write attestation to this file.")

    vf = sub.add_parser("verify", help="Verify an artifact against its attestation.")
    vf.add_argument("artifact", help="File or directory to verify.")
    vf.add_argument("attestation", help="Attestation JSON produced by `attest`.")
    vf.add_argument("--key", help="Verification key (else ATTESTPORT_KEY / demo).")
    vf.add_argument("--policy", help="Optional policy JSON for component checks.")
    vf.add_argument("--format", choices=("text", "json"), default="text")
    vf.add_argument("--out", help="Write output to this file.")

    gt = sub.add_parser("gate", help="CI policy gate over a project directory.")
    gt.add_argument("directory", help="Project directory to gate.")
    gt.add_argument("--policy", help="Policy JSON (else built-in defaults).")
    gt.add_argument("--attestation", help="Attestation JSON (for require_attestation).")
    gt.add_argument("--format", choices=("table", "json", "sarif"), default="table")
    gt.add_argument("--out", help="Write output to this file.")
    gt.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default=None,
                    help="Exit non-zero if a finding at/above this severity exists.")
    gt.add_argument("--vuln", action="store_true",
                    help="Also match components against the bundled offline "
                         "vulnerability DB (262k real OSV/GHSA records).")

    mt = sub.add_parser("match", help="Match a project's components against the "
                                      "bundled offline vulnerability DB.")
    mt.add_argument("directory", help="Project directory to inventory + match.")
    mt.add_argument("--format", choices=("table", "json"), default="table")
    mt.add_argument("--out", help="Write output to this file.")
    mt.add_argument("--limit", type=int, default=10,
                    help="Max vulns to print per component (table mode).")
    mt.add_argument("--fail-on-match", action="store_true",
                    help="Exit non-zero if any component has a known vuln.")

    vd = sub.add_parser("vulndb", help="Query the bundled offline vulnerability DB.")
    vsub = vd.add_subparsers(dest="vulndb_command")
    vsub.add_parser("count", help="Print the number of records in the DB.")
    vc = vsub.add_parser("cve", help="Look up a CVE/GHSA id.")
    vc.add_argument("id"); vc.add_argument("--out")
    vp = vsub.add_parser("package", help="Look up vulns for a package name.")
    vp.add_argument("name"); vp.add_argument("--ecosystem"); vp.add_argument("--out")
    vs = vsub.add_parser("search", help="Substring search over vuln summaries.")
    vs.add_argument("text"); vs.add_argument("--limit", type=int, default=25)
    vs.add_argument("--out")

    sub.add_parser("mcp", help="Run as an MCP server (stdio JSON-RPC).")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "sbom":
        return _run_sbom(args)
    if args.command == "attest":
        return _run_attest(args)
    if args.command == "verify":
        return _run_verify(args)
    if args.command == "gate":
        return _run_gate(args)
    if args.command == "match":
        return _run_match(args)
    if args.command == "vulndb":
        return _run_vulndb(args)
    if args.command == "mcp":
        return _run_mcp()
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
