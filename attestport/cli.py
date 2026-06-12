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
    GateReport,
    SEVERITY_ORDER,
    attest,
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

    if args.format == "json":
        _emit(json.dumps(report.to_dict(), indent=2), args.out)
    elif args.format == "sarif":
        _emit(json.dumps(to_sarif(report), indent=2), args.out)
    else:
        _emit(_render_gate_table(report), args.out)

    return 1 if _fails_gate(report, args.fail_on) else 0


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
    if args.command == "mcp":
        return _run_mcp()
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
