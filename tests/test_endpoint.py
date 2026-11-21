import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from kingshield.endpoint import audit_local, load_report, summarize, validate


class EndpointTests(unittest.TestCase):
    def sample(self, status="pass"):
        return {"schema_version": 1, "checks": {"firewall": {"status": status, "detail": "example"}}}

    def test_validation(self):
        self.assertEqual(validate(self.sample())["schema_version"], 1)

    def test_reject_invalid(self):
        with self.assertRaises(ValueError):
            validate(self.sample("broken"))

    def test_fleet(self):
        result = summarize([self.sample("fail"), self.sample("pass")])
        self.assertEqual(result["machines_with_failures"], 1)
        self.assertEqual(result["total_machines"], 2)

    def test_load(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "audit.json"
            path.write_text('{"schema_version":1,"checks":{"firewall":{"status":"pass","detail":"ok"}}}', encoding="utf-8")
            self.assertEqual(load_report(path)["checks"]["firewall"]["status"], "pass")

    def test_non_windows(self):
        with patch("kingshield.endpoint.sys.platform", "linux"):
            with self.assertRaises(RuntimeError):
                audit_local()
