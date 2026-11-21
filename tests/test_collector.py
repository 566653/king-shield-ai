import subprocess
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

    def test_permissions_error_is_actionable(self):
        fake = subprocess.CompletedProcess(args=[], returncode=2, stdout="", stderr="denied")
        with patch("kingshield.collector.sys.platform", "win32"):
            with patch("kingshield.collector.subprocess.run", return_value=fake):
                with self.assertRaisesRegex(RuntimeError, "authorized"):
                    collect_local()

    def test_timeout_is_actionable(self):
        with patch("kingshield.collector.sys.platform", "win32"):
            with patch("kingshield.collector.subprocess.run", side_effect=subprocess.TimeoutExpired("powershell", 60)):
                with self.assertRaisesRegex(RuntimeError, "timed out"):
                    collect_local()
