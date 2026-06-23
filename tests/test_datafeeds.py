"""Offline tests for the bundled data-feed catalog + edge cache.

No network is touched: we exercise catalog loading, the offline cache contract,
and the sneakernet snapshot export/import round-trip against a temp cache dir.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attestport import datafeeds

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestCatalog(unittest.TestCase):
    def test_catalog_loads(self):
        cat = datafeeds.load_catalog()
        self.assertIn("feeds", cat)
        self.assertTrue(cat["feeds"])

    def test_feeds_have_required_fields(self):
        for f in datafeeds.list_feeds():
            self.assertIn("id", f)
            self.assertIn("url", f)
            self.assertTrue(f["url"].startswith("http"))

    def test_known_vuln_feeds_present(self):
        ids = {f["id"] for f in datafeeds.list_feeds()}
        # The catalog should advertise real vuln/advisory sources for refresh.
        self.assertTrue(ids)
        self.assertTrue(any("kev" in i or "osv" in i or "nvd" in i or "epss" in i
                            or "ghsa" in i or "advisor" in i for i in ids))

    def test_domain_filter(self):
        all_feeds = datafeeds.list_feeds()
        domains = {f.get("domain") for f in all_feeds if f.get("domain")}
        if domains:
            d = next(iter(domains))
            filtered = datafeeds.list_feeds(domain=d)
            self.assertTrue(all(f.get("domain") == d for f in filtered))


class TestOfflineContract(unittest.TestCase):
    def _temp_cache(self):
        tmp = tempfile.mkdtemp()
        os.environ["COGNIS_FEEDS_CACHE"] = tmp
        return tmp

    def test_offline_with_empty_cache_raises(self):
        self._temp_cache()
        feed = datafeeds.list_feeds()[0]["id"]
        with self.assertRaises(FileNotFoundError):
            datafeeds.get(feed, offline=True)

    def test_cached_age_none_when_absent(self):
        self._temp_cache()
        self.assertIsNone(datafeeds.cached_age_hours("nonexistent-feed"))

    def test_snapshot_roundtrip(self):
        tmp = self._temp_cache()
        # seed a fake cached feed (no network)
        data_path = os.path.join(tmp, "demo.data")
        meta_path = os.path.join(tmp, "demo.meta.json")
        with open(data_path, "w", encoding="utf-8") as fh:
            fh.write('{"hello":"world"}')
        with open(meta_path, "w", encoding="utf-8") as fh:
            fh.write('{"feed":"demo","fetched_at":0}')
        with tempfile.TemporaryDirectory() as snapdir:
            snap = os.path.join(snapdir, "feeds.tar.gz")
            n = datafeeds.snapshot_export(snap)
            self.assertGreaterEqual(n, 1)
            # import into a fresh cache dir
            os.environ["COGNIS_FEEDS_CACHE"] = tempfile.mkdtemp()
            imported = datafeeds.snapshot_import(snap)
            self.assertGreaterEqual(imported, 1)

    def tearDown(self):
        os.environ.pop("COGNIS_FEEDS_CACHE", None)


if __name__ == "__main__":
    unittest.main()
