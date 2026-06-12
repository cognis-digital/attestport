"""ATTESTPORT MCP server.

Exposes the supply-chain engine as an MCP capability over stdio using
newline-delimited JSON-RPC 2.0. Standard library only — no SDK — so it runs
anywhere Python does (including air-gapped runners) and can be wired into
Cognis.Studio, Claude Desktop, or Cursor as a local MCP server:

    {"command": "python", "args": ["-m", "attestport", "mcp"]}

Implemented methods:
  * initialize  — handshake, advertises the tools capability
  * tools/list  — describes the `sbom`, `verify`, and `gate` tools
  * tools/call  — runs a tool and returns the result as JSON text

Each line on stdin is one JSON-RPC request; each response is one JSON line on
stdout.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional

from attestport import TOOL_NAME, TOOL_VERSION
from attestport.core import (
    AttestError,
    gate,
    generate_sbom,
    load_policy,
    sbom_components,
    verify,
)

PROTOCOL_VERSION = "2024-11-05"

_TOOLS = [
    {
        "name": "sbom",
        "description": "Generate a CycloneDX-style SBOM for a project directory "
                       "by parsing known lockfiles and hashing files. Air-gap "
                       "safe; no network.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "directory": {"type": "string",
                              "description": "Project directory to inventory."},
                "include_files": {"type": "boolean",
                                  "description": "Include the file-hash inventory."},
            },
            "required": ["directory"],
            "additionalProperties": False,
        },
    },
    {
        "name": "verify",
        "description": "Verify an artifact against an in-toto/SLSA-style "
                       "attestation: recompute the subject digest and check the "
                       "detached signature. Returns ok + problems.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "artifact": {"type": "string",
                             "description": "File or directory to verify."},
                "attestation": {"type": "object",
                                "description": "Attestation JSON from `attest`."},
            },
            "required": ["artifact", "attestation"],
            "additionalProperties": False,
        },
    },
    {
        "name": "gate",
        "description": "Run the CI supply-chain policy gate over a project: "
                       "banned licenses, known-bad components, unpinned deps, "
                       "and missing attestation. Returns prioritized findings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "directory": {"type": "string",
                              "description": "Project directory to gate."},
                "policy_path": {"type": "string",
                                "description": "Optional path to a policy JSON."},
            },
            "required": ["directory"],
            "additionalProperties": False,
        },
    },
]


def _result(req_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _call_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if name == "sbom":
        directory = arguments.get("directory")
        if not isinstance(directory, str) or not directory:
            raise ValueError("`directory` (string path) is required")
        include = bool(arguments.get("include_files", True))
        payload = generate_sbom(directory, include_files=include)
        is_error = False
    elif name == "verify":
        artifact = arguments.get("artifact")
        attestation = arguments.get("attestation")
        if not isinstance(artifact, str) or not artifact:
            raise ValueError("`artifact` (string path) is required")
        if not isinstance(attestation, dict):
            raise ValueError("`attestation` (object) is required")
        ok, problems = verify(artifact, attestation)
        payload = {"ok": ok, "problems": problems}
        is_error = not ok
    elif name == "gate":
        directory = arguments.get("directory")
        if not isinstance(directory, str) or not directory:
            raise ValueError("`directory` (string path) is required")
        policy = load_policy(arguments.get("policy_path"))
        report = gate(directory, policy)
        payload = report.to_dict()
        is_error = report.failed
    else:
        raise ValueError(f"unknown tool: {name}")

    return {
        "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
        "isError": is_error,
    }


def handle_request(req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Dispatch a single JSON-RPC request. Returns None for notifications."""
    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params") or {}
    is_notification = "id" not in req

    if method == "initialize":
        res = _result(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": TOOL_NAME, "version": TOOL_VERSION},
        })
        return None if is_notification else res

    if method in ("notifications/initialized", "initialized"):
        return None

    if method == "ping":
        return None if is_notification else _result(req_id, {})

    if method == "tools/list":
        return _result(req_id, {"tools": _TOOLS})

    if method == "tools/call":
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        try:
            return _result(req_id, _call_tool(name, arguments))
        except (ValueError, OSError, AttestError) as exc:
            return _error(req_id, -32602, str(exc))
        except Exception as exc:  # pragma: no cover - defensive
            return _error(req_id, -32603, f"internal error: {exc}")

    if is_notification:
        return None
    return _error(req_id, -32601, f"method not found: {method}")


def run_mcp_server(stdin=None, stdout=None) -> None:
    """Read newline-delimited JSON-RPC from stdin, write responses to stdout."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            stdout.write(json.dumps(_error(None, -32700, "parse error")) + "\n")
            stdout.flush()
            continue
        response = handle_request(req)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()


if __name__ == "__main__":
    run_mcp_server()
