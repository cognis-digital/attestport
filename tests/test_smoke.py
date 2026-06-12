"""Smoke tests for ATTESTPORT. Standard library only, no network."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attestport import (
    TOOL_NAME,
    TOOL_VERSION,
    attest,
    detect_components,
    gate,
    generate_sbom,
    load_policy,
    verify,
)
from attestport.cli import main

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(REPO_ROOT, "demos", "01-basic", "demoproj")
POLICY = os.path.join(REPO_ROOT, "demos", "01-basic", "policy.json")


class TestMetadata(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "attestport")
        self.assertTrue(TOOL_VERSION)


class TestSbom(unittest.TestCase):
    def test_demo_sbom_is_cyclonedx(self):
        bom = generate_sbom(DEMO)
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertTrue(bom["specVersion"])
        names = {c["name"] for c in bom["components"]}
        self.assertIn("requests", names)
        self.assertIn("lodash", names)

    def test_components_detected_from_both_lockfiles(self):
        comps = detect_components(DEMO)
        ecos = {c.ecosystem for c in comps}
        self.assertIn("pypi", ecos)
        self.assertIn("npm", ecos)

    def test_pinned_detection(self):
        comps = {c.name: c for c in detect_components(DEMO)}
        self.assertTrue(comps["requests"].pinned)
        self.assertFalse(comps["flask"].pinned)


class TestAttestVerify(unittest.TestCase):
    def test_roundtrip_pass(self):
        att = attest(DEMO)
        ok, problems = verify(DEMO, att)
        self.assertTrue(ok, problems)

    def test_tampered_artifact_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = os.path.join(tmp, "x.txt")
            with open(f, "w") as fh:
                fh.write("original")
            att = attest(f)
            with open(f, "w") as fh:
                fh.write("tampered")
            ok, problems = verify(f, att)
            self.assertFalse(ok)
            self.assertTrue(any("digest mismatch" in p for p in problems))

    def test_tampered_signature_fails(self):
        att = attest(DEMO)
        att["signature"]["value"] = "0" * 64
        ok, problems = verify(DEMO, att)
        self.assertFalse(ok)


class TestGate(unittest.TestCase):
    def test_demo_gate_fails_policy(self):
        report = gate(DEMO, load_policy(POLICY))
        self.assertTrue(report.failed)
        rules = {f.rule for f in report.findings}
        self.assertIn("component.banned", rules)
        self.assertIn("dependency.unpinned", rules)


class TestCli(unittest.TestCase):
    def test_version_exits(self):
        with self.assertRaises(SystemExit) as ctx:
            main(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_sbom_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "sbom.json")
            rc = main(["sbom", DEMO, "--out", out])
            self.assertEqual(rc, 0)
            with open(out) as fh:
                bom = json.load(fh)
            self.assertEqual(bom["bomFormat"], "CycloneDX")

    def test_gate_cli_nonzero(self):
        rc = main(["gate", DEMO, "--policy", POLICY])
        self.assertEqual(rc, 1)

    def test_verify_cli_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            att = os.path.join(tmp, "att.json")
            self.assertEqual(main(["attest", DEMO, "--out", att]), 0)
            self.assertEqual(main(["verify", DEMO, att]), 0)

    def test_subprocess_version(self):
        out = subprocess.run(
            [sys.executable, "-m", "attestport", "--version"],
            cwd=REPO_ROOT, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0)
        self.assertIn("attestport", out.stdout)


if __name__ == "__main__":
    unittest.main()
