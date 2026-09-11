import json
import os
import tempfile
import unittest

from pyrasec.core.models import FileRecord, Finding, Remediation, Severity
from pyrasec.engine.cache import ScanCache, ruleset_fingerprint


class TestScanCache(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cache_path = os.path.join(self.temp_dir.name, "cache.json")
        self.cache = ScanCache(self.cache_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _make_record(self, path="foo.py", sha256="abc123"):
        return FileRecord(path=path, abs_path="/tmp/" + path, size=10, mode=0o644, depth=1, sha256=sha256)

    def test_fingerprint(self):
        fp = ruleset_fingerprint()
        self.assertIsInstance(fp, str)
        self.assertGreater(len(fp), 0)

    def test_empty_cache_get(self):
        rec = self._make_record()
        self.assertIsNone(self.cache.get(rec))

    def test_cache_no_sha(self):
        rec = self._make_record(sha256="")
        self.assertIsNone(self.cache.get(rec))
        self.cache.put(rec, [])
        self.assertIsNone(self.cache.get(rec))

    def test_put_save_and_reload(self):
        rec = self._make_record(sha256="hash123")
        finding = Finding(
            rule_id="RULE-01",
            title="Test Finding",
            severity=Severity.HIGH,
            path="foo.py",
            description="desc",
            remediation=Remediation(summary="fix it", example="sample"),
            line=5,
            confidence=1.0,
        )
        self.cache.put(rec, [finding])
        self.cache.save()

        # Reload cache from disk
        new_cache = ScanCache(self.cache_path)
        cached_findings = new_cache.get(rec)
        self.assertIsNotNone(cached_findings)
        self.assertEqual(len(cached_findings), 1)
        self.assertEqual(cached_findings[0].rule_id, "RULE-01")
        self.assertEqual(cached_findings[0].severity, Severity.HIGH)

    def test_cache_miss_on_sha_change(self):
        rec1 = self._make_record(sha256="hash1")
        self.cache.put(rec1, [])
        rec2 = self._make_record(sha256="hash2")
        self.assertIsNone(self.cache.get(rec2))

    def test_corrupted_cache_file(self):
        with open(self.cache_path, "w") as f:
            f.write("invalid-json{{{")
        loaded = ScanCache(self.cache_path)
        self.assertEqual(loaded._data, {})

    def test_stale_ruleset_cache_file(self):
        with open(self.cache_path, "w") as f:
            json.dump({"version": 2, "ruleset": "outdated_fingerprint", "entries": {"foo": {}}}, f)
        loaded = ScanCache(self.cache_path)
        self.assertEqual(loaded._data, {})

    def test_clear_cache(self):
        rec = self._make_record(sha256="hash1")
        self.cache.put(rec, [])
        self.cache.clear()
        self.assertIsNone(self.cache.get(rec))
