import unittest
from unittest.mock import patch
from kingshield.collector import collect_local


class CollectorTests(unittest.TestCase):
    def test_reject_invalid_limit(self):
        with patch("kingshield.collector.sys.platform", "win32"):
            with self.assertRaises(ValueError):
                collect_local(0)

    def test_unsupported_platform(self):
        with patch("kingshield.collector.sys.platform", "linux"):
            with self.assertRaises(RuntimeError):
                collect_local()
