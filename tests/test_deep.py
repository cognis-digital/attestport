"""Deeper tests for ATTESTPORT: parsers, canonicalization, MCP, SARIF."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attestport import core
from attestport.core import (
    attest,
    canonical_bytes,
    detect_components,
    gate,
    generate_sbom,
    load_policy,
    merkle_digest,
    sign_statement,
    to_sarif,
    verify,
)
from attestport.mcp_server import handle_request


def _mkproj(tmp, files):
    for name, content in files.items():
        path = os.path.join(tmp, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    return tmp


class TestParsers(unittest.TestCase):
    def test_requirements_pinning(self):
        comps = core._parse_requirements(
            "a==1.0\nb>=2\nc\n# comment\nd==3.0 ; python_version<'3.9'\n")
        by = {c.name: c for c in comps}
        self.assertTrue(by["a"].pinned)
        self.assertFalse(by["b"].pinned)
        self.assertFalse(by["c"].pinned)
        self.assertTrue(by["d"].pinned)

    def test_go_sum_dedup(self):
        text = ("github.com/x/y v1.2.0 h1:AAA=\n"
                "github.com/x/y v1.2.0/go.mod h1:BBB=\n")
        comps = core._parse_go_sum(text)
        self.assertEqual(len(comps), 1)
        self.assertEqual(comps[0].version, "v1.2.0")

    def test_cargo_lock(self):
        text = (
            '[[package]]\nname = "serde"\nversion = "1.0.0"\n'
            'checksum = "abc123"\n\n'
            '[[package]]\nname = "anyhow"\nversion = "1.0.70"\n')
        comps = {c.name: c for c in core._parse_cargo_lock(text)}
        self.assertEqual(comps["serde"].version, "1.0.0")
        self.assertEqual(comps["serde"].hashes[0]["content"], "abc123")
        self.assertEqual(comps["anyhow"].version, "1.0.70")

    def test_package_lock_v1(self):
        text = json.dumps({"dependencies": {"foo": {"version": "1.2.3"}}})
        comps = core._parse_package_lock(text)
        self.assertEqual(comps[0].name, "foo")
        self.assertEqual(comps[0].version, "1.2.3")


class TestCanonical(unittest.TestCase):
    def test_canonical_is_order_independent(self):
        a = {"x": 1, "y": [3, 2, 1]}
        b = {"y": [3, 2, 1], "x": 1}
        self.assertEqual(canonical_bytes(a), canonical_bytes(b))

    def test_merkle_changes_on_content(self):
        with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
            _mkproj(t1, {"a.txt": "hello"})
            _mkproj(t2, {"a.txt": "world"})
            d1 = merkle_digest(core.hash_tree(t1))
            d2 = merkle_digest(core.hash_tree(t2))
            self.assertNotEqual(d1, d2)


class TestAttestDetails(unittest.TestCase):
    def test_statement_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = os.path.join(tmp, "artifact.bin")
            with open(f, "wb") as fh:
                fh.write(b"payload")
            env = attest(f, builder="ci://demo")
            self.assertEqual(env["predicateType"], core.SLSA_PREDICATE_TYPE)
            self.assertEqual(env["_type"], core.INTOTO_STATEMENT_TYPE)
            self.assertEqual(env["predicate"]["builder"]["id"], "ci://demo")
            self.assertEqual(env["signature"]["algorithm"], "hmac-sha256")

    def test_key_matters(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = os.path.join(tmp, "a.bin")
            with open(f, "wb") as fh:
                fh.write(b"x")
            env = attest(f, key="key-A")
            ok, _ = verify(f, env, key="key-A")
            self.assertTrue(ok)
            ok2, probs = verify(f, env, key="key-B")
            self.assertFalse(ok2)
            self.assertTrue(any("signature" in p for p in probs))

    def test_sbom_bound_into_statement(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mkproj(tmp, {"requirements.txt": "x==1.0\n"})
            bom = generate_sbom(tmp)
            env = attest(tmp, sbom=bom)
            self.assertIn("sbomDigest", env["predicate"])
            self.assertEqual(env["predicate"]["componentCount"], 1)


class TestGatePolicy(unittest.TestCase):
    def test_unpinned_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mkproj(tmp, {"requirements.txt": "good==1.0\nbad>=2\n"})
            report = gate(tmp, {"require_pinned": True})
            rules = [f.rule for f in report.findings]
            self.assertIn("dependency.unpinned", rules)
            self.assertFalse(report.failed)  # medium only

    def test_banned_component_is_critical(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mkproj(tmp, {"requirements.txt": "evil==1.0\n"})
            report = gate(tmp, {"banned_components": ["evil"]})
            self.assertTrue(report.failed)
            self.assertEqual(report.findings[0].severity, "critical")

    def test_require_attestation_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mkproj(tmp, {"requirements.txt": "a==1.0\n"})
            report = gate(tmp, {"require_attestation": True})
            self.assertIn("attestation.missing", {f.rule for f in report.findings})

    def test_require_attestation_valid_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mkproj(tmp, {"requirements.txt": "a==1.0\n"})
            env = attest(tmp)
            report = gate(tmp, {"require_attestation": True}, attestation=env)
            self.assertNotIn("attestation.invalid",
                             {f.rule for f in report.findings})

    def test_clean_project_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mkproj(tmp, {"requirements.txt": "a==1.0\nb==2.0\n"})
            report = gate(tmp, load_policy(None))
            self.assertFalse(report.failed)


class TestSarif(unittest.TestCase):
    def test_sarif_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mkproj(tmp, {"requirements.txt": "evil==1.0\n"})
            report = gate(tmp, {"banned_components": ["evil"]})
            sarif = to_sarif(report)
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertTrue(sarif["runs"][0]["results"])


class TestMcp(unittest.TestCase):
    def test_initialize(self):
        resp = handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(resp["result"]["serverInfo"]["name"], "attestport")

    def test_tools_list(self):
        resp = handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in resp["result"]["tools"]}
        self.assertEqual(names, {"sbom", "verify", "gate"})

    def test_tools_call_sbom(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mkproj(tmp, {"requirements.txt": "a==1.0\n"})
            resp = handle_request({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "sbom", "arguments": {"directory": tmp}}})
            payload = json.loads(resp["result"]["content"][0]["text"])
            self.assertEqual(payload["bomFormat"], "CycloneDX")

    def test_tools_call_gate_iserror(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mkproj(tmp, {"requirements.txt": "evil==1.0\n"})
            pol = os.path.join(tmp, "pol.json")
            with open(pol, "w") as fh:
                json.dump({"banned_components": ["evil"]}, fh)
            resp = handle_request({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {"name": "gate",
                           "arguments": {"directory": tmp, "policy_path": pol}}})
            self.assertTrue(resp["result"]["isError"])

    def test_unknown_method(self):
        resp = handle_request({"jsonrpc": "2.0", "id": 5, "method": "nope"})
        self.assertIn("error", resp)


if __name__ == "__main__":
    unittest.main()
