"""Offline tests for the SBOM-component CVE matching stage.

Every assertion runs against the bundled vulnerability DB
(``cognis_vulndb.jsonl.gz``, ~262k real OSV/GHSA records) with the Python
standard library and no network. The canonical proof is that the real
CVE-2021-44228 / log4j advisory resolves from the bundle.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attestport import (
    detect_components,
    generate_sbom,
)
from attestport.cli import main
from attestport.vulndb_local import VulnDB
from attestport.vulnmatch import (
    is_cve_id,
    is_ghsa_id,
    lookup_cve,
    match_component,
    match_components,
    match_sbom,
    normalize_ecosystem,
    severity_bucket,
    vuln_findings,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(REPO_ROOT, "demos", "01-basic", "demoproj")

# A single shared DB instance keeps the suite fast (index built once).
_DB = VulnDB()


class TestDbBundle(unittest.TestCase):
    def test_db_is_large(self):
        self.assertGreaterEqual(_DB.count(), 100000)

    def test_record_schema(self):
        rec = next(iter(_DB))
        for field in ("id", "aliases", "ecosystem", "summary", "severity",
                      "packages"):
            self.assertIn(field, rec)

    def test_db_path_exists(self):
        self.assertTrue(_DB.path.exists())
        self.assertTrue(str(_DB.path).endswith(".jsonl.gz"))


class TestLog4jCanonical(unittest.TestCase):
    """The load-bearing proof: the real log4shell advisory is in the bundle."""

    def test_cve_2021_44228_resolves(self):
        recs = _DB.by_cve("CVE-2021-44228")
        self.assertTrue(recs)

    def test_log4shell_is_log4j(self):
        recs = lookup_cve("CVE-2021-44228", db=_DB)
        self.assertTrue(recs)
        rec = recs[0]
        self.assertIn("log4j", " ".join(rec["packages"]).lower())
        self.assertIn("CVE-2021-44228", rec["aliases"])

    def test_log4shell_summary_mentions_log4j(self):
        rec = lookup_cve("CVE-2021-44228", db=_DB)[0]
        self.assertIn("log4j", rec["summary"].lower())

    def test_log4shell_is_critical(self):
        rec = lookup_cve("CVE-2021-44228", db=_DB)[0]
        self.assertEqual(severity_bucket(rec["severity"]), "critical")

    def test_log4shell_by_package(self):
        hits = match_component("org.apache.logging.log4j:log4j-core",
                               ecosystem="maven", db=_DB)
        ids = {h["id"] for h in hits} | {
            a for h in hits for a in h["aliases"]}
        self.assertIn("CVE-2021-44228", ids)

    def test_log4shell_by_short_artifact_name(self):
        # Maven group:artifact fallback should still find it via 'log4j-core'.
        hits = match_component("log4j-core", ecosystem="maven", db=_DB)
        ids = {a for h in hits for a in h["aliases"]}
        self.assertIn("CVE-2021-44228", ids)

    def test_case_insensitive_cve(self):
        self.assertTrue(lookup_cve("cve-2021-44228", db=_DB))


class TestGhsaLookup(unittest.TestCase):
    def test_ghsa_id_resolves(self):
        rec = lookup_cve("CVE-2021-44228", db=_DB)[0]
        ghsa = rec["id"]
        self.assertTrue(is_ghsa_id(ghsa))
        self.assertTrue(lookup_cve(ghsa, db=_DB))

    def test_unknown_cve_empty(self):
        self.assertEqual(lookup_cve("CVE-0000-00000", db=_DB), [])


class TestNormalizeEcosystem(unittest.TestCase):
    def test_purl_to_osv(self):
        self.assertEqual(normalize_ecosystem("pypi"), "PyPI")
        self.assertEqual(normalize_ecosystem("npm"), "npm")
        self.assertEqual(normalize_ecosystem("golang"), "Go")
        self.assertEqual(normalize_ecosystem("cargo"), "crates.io")
        self.assertEqual(normalize_ecosystem("maven"), "Maven")
        self.assertEqual(normalize_ecosystem("rubygems"), "RubyGems")
        self.assertEqual(normalize_ecosystem("nuget"), "NuGet")

    def test_case_insensitive(self):
        self.assertEqual(normalize_ecosystem("PyPI"), "PyPI")
        self.assertEqual(normalize_ecosystem("GoLang"), "Go")

    def test_unknown_and_empty(self):
        self.assertIsNone(normalize_ecosystem(""))
        self.assertIsNone(normalize_ecosystem(None))
        self.assertIsNone(normalize_ecosystem("cobol"))


class TestSeverityBucket(unittest.TestCase):
    def test_cvss_critical(self):
        self.assertEqual(
            severity_bucket("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
            "critical")

    def test_cvss_high_scope_unchanged(self):
        self.assertEqual(
            severity_bucket("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            "high")

    def test_numeric_scores(self):
        self.assertEqual(severity_bucket("9.8"), "critical")
        self.assertEqual(severity_bucket("7.5"), "high")
        self.assertEqual(severity_bucket("5.0"), "medium")
        self.assertEqual(severity_bucket("2.1"), "low")
        self.assertEqual(severity_bucket("0.0"), "info")

    def test_empty_defaults_medium(self):
        self.assertEqual(severity_bucket(""), "medium")
        self.assertEqual(severity_bucket(None), "medium")

    def test_garbage_defaults_medium(self):
        self.assertEqual(severity_bucket("not-a-score"), "medium")


class TestCveIdHelpers(unittest.TestCase):
    def test_is_cve_id(self):
        self.assertTrue(is_cve_id("CVE-2021-44228"))
        self.assertTrue(is_cve_id("cve-2021-44228"))
        self.assertFalse(is_cve_id("GHSA-jfh8-c2jp-5v3q"))
        self.assertFalse(is_cve_id("lodash"))

    def test_is_ghsa_id(self):
        self.assertTrue(is_ghsa_id("GHSA-jfh8-c2jp-5v3q"))
        self.assertFalse(is_ghsa_id("CVE-2021-44228"))


class TestMatchComponent(unittest.TestCase):
    def test_known_vulnerable_pypi_packages(self):
        # urllib3 and requests both have a long, real OSV history.
        for name in ("urllib3", "requests"):
            hits = match_component(name, ecosystem="pypi", db=_DB)
            self.assertTrue(hits, f"expected vulns for {name}")

    def test_known_vulnerable_npm_package(self):
        hits = match_component("lodash", ecosystem="npm", db=_DB)
        self.assertTrue(hits)

    def test_clean_name_no_matches(self):
        hits = match_component("definitely-not-a-real-package-xyz-123",
                               ecosystem="pypi", db=_DB)
        self.assertEqual(hits, [])

    def test_ecosystem_filtering(self):
        # urllib3 vulns are PyPI; asking for npm should not return them.
        py = match_component("urllib3", ecosystem="pypi", db=_DB)
        npm = match_component("urllib3", ecosystem="npm", db=_DB)
        self.assertTrue(py)
        for h in npm:
            self.assertEqual(h["ecosystem"], "npm")

    def test_results_have_brief_shape(self):
        hits = match_component("lodash", ecosystem="npm", db=_DB)
        h = hits[0]
        for key in ("id", "aliases", "ecosystem", "summary", "severity",
                    "packages"):
            self.assertIn(key, h)

    def test_results_deduped_by_id(self):
        hits = match_component("requests", ecosystem="pypi", db=_DB)
        ids = [h["id"] for h in hits]
        self.assertEqual(len(ids), len(set(ids)))

    def test_results_sorted(self):
        hits = match_component("requests", ecosystem="pypi", db=_DB)
        ids = [h["id"] for h in hits]
        self.assertEqual(ids, sorted(ids))


class TestMatchComponents(unittest.TestCase):
    def setUp(self):
        self.comps = [c.to_cyclonedx() for c in detect_components(DEMO)]

    def test_demo_has_vulnerable_components(self):
        matches = match_components(self.comps, db=_DB)
        self.assertTrue(matches)
        names = {m["component"] for m in matches}
        # requests/urllib3 from requirements.txt; lodash from package-lock.
        self.assertTrue({"requests", "urllib3", "lodash"} & names)

    def test_match_entry_shape(self):
        m = match_components(self.comps, db=_DB)[0]
        for key in ("component", "ecosystem", "version", "vuln_count", "vulns"):
            self.assertIn(key, m)
        self.assertEqual(m["vuln_count"], len(m["vulns"]))

    def test_sorted_by_vuln_count_desc(self):
        matches = match_components(self.comps, db=_DB)
        counts = [m["vuln_count"] for m in matches]
        self.assertEqual(counts, sorted(counts, reverse=True))

    def test_empty_component_list(self):
        self.assertEqual(match_components([], db=_DB), [])

    def test_component_without_name_skipped(self):
        self.assertEqual(match_components([{"version": "1.0"}], db=_DB), [])

    def test_match_sbom_equivalent(self):
        bom = generate_sbom(DEMO, include_files=False)
        via_sbom = match_sbom(bom, db=_DB)
        via_comps = match_components(self.comps, db=_DB)
        self.assertEqual({m["component"] for m in via_sbom},
                         {m["component"] for m in via_comps})


class TestVulnFindings(unittest.TestCase):
    def setUp(self):
        self.comps = [c.to_cyclonedx() for c in detect_components(DEMO)]

    def test_produces_findings(self):
        findings = vuln_findings(self.comps, db=_DB)
        self.assertTrue(findings)

    def test_findings_are_vuln_known_rule(self):
        for f in vuln_findings(self.comps, db=_DB):
            self.assertEqual(f.rule, "vuln.known")

    def test_findings_have_valid_severity(self):
        valid = {"critical", "high", "medium", "low", "info"}
        for f in vuln_findings(self.comps, db=_DB):
            self.assertIn(f.severity, valid)

    def test_findings_reference_real_cve_or_ghsa(self):
        for f in vuln_findings(self.comps, db=_DB)[:20]:
            # message embeds the CVE/GHSA id; remediation embeds the advisory.
            self.assertTrue("CVE-" in f.message or "GHSA-" in f.message)

    def test_max_per_component_caps(self):
        capped = vuln_findings(self.comps, db=_DB, max_per_component=1)
        # at most one finding per vulnerable component
        per_comp = {}
        for f in capped:
            per_comp[f.component] = per_comp.get(f.component, 0) + 1
        for n in per_comp.values():
            self.assertLessEqual(n, 1)

    def test_no_fabricated_findings(self):
        # Every finding references a real advisory id (CVE/GHSA/PYSEC/RUSTSEC/
        # OSV/...). The message embeds the preferred CVE alias when present,
        # else the advisory id; both must resolve in the bundled DB.
        import re
        idre = re.compile(r"(CVE-\d{4}-\d+|[A-Z]+-\d{4}-[0-9A-Za-z-]+|"
                          r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})")
        for f in vuln_findings(self.comps, db=_DB)[:30]:
            m = idre.search(f.message)
            self.assertIsNotNone(m, f.message)
            self.assertTrue(lookup_cve(m.group(1), db=_DB),
                            f"id {m.group(1)} should resolve in the bundle")


class TestMatchCli(unittest.TestCase):
    def test_match_table(self):
        rc = main(["match", DEMO])
        self.assertEqual(rc, 0)

    def test_match_json_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "m.json")
            rc = main(["match", DEMO, "--format", "json", "--out", out])
            self.assertEqual(rc, 0)
            with open(out, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertIn("matches", data)
            self.assertGreater(data["total_vulns"], 0)
            self.assertGreater(data["vulnerable_components"], 0)

    def test_match_fail_on_match(self):
        rc = main(["match", DEMO, "--fail-on-match"])
        self.assertEqual(rc, 1)  # demo has known-vulnerable deps

    def test_gate_with_vuln_flag_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "g.json")
            main(["gate", DEMO, "--vuln", "--format", "json", "--out", out])
            with open(out, encoding="utf-8") as fh:
                data = json.load(fh)
            rules = {f["rule"] for f in data["findings"]}
            self.assertIn("vuln.known", rules)


class TestVulndbCli(unittest.TestCase):
    def test_count(self):
        rc = main(["vulndb", "count"])
        self.assertEqual(rc, 0)

    def test_cve_lookup_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "c.json")
            rc = main(["vulndb", "cve", "CVE-2021-44228", "--out", out])
            self.assertEqual(rc, 0)
            with open(out, encoding="utf-8") as fh:
                recs = json.load(fh)
            self.assertTrue(recs)
            self.assertIn("log4j", " ".join(recs[0]["packages"]).lower())

    def test_cve_lookup_not_found(self):
        rc = main(["vulndb", "cve", "CVE-0000-00000"])
        self.assertEqual(rc, 1)

    def test_package_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "p.json")
            rc = main(["vulndb", "package", "lodash", "--ecosystem", "npm",
                       "--out", out])
            self.assertEqual(rc, 0)
            with open(out, encoding="utf-8") as fh:
                recs = json.load(fh)
            self.assertTrue(recs)

    def test_search(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "s.json")
            rc = main(["vulndb", "search", "deserialization", "--limit", "5",
                       "--out", out])
            self.assertEqual(rc, 0)
            with open(out, encoding="utf-8") as fh:
                recs = json.load(fh)
            self.assertTrue(recs)
            self.assertLessEqual(len(recs), 5)


if __name__ == "__main__":
    unittest.main()
