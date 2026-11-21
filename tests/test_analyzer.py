import json
import tempfile
import unittest
from pathlib import Path
from kingshield.analyzer import analyze
from kingshield.__main__ import load_events, main


class AnalyzerTests(unittest.TestCase):
    def test_privileged_group(self):
        result = analyze([{"event_id": 4728, "group": "Domain Admins"}])
        self.assertEqual(result[0]["severity"], "high")

    def test_non_privileged_group(self):
        self.assertEqual(analyze([{"event_id": 4728, "group": "staff"}])[0]["severity"], "medium")

    def test_failed_logons(self):
        self.assertEqual(len(analyze([{"event_id": 4625, "source": "demo"}] * 5)), 1)

    def test_failed_logons_below_threshold(self):
        self.assertEqual(analyze([{"event_id": 4625}] * 4), [])

    def test_no_alert(self):
        self.assertEqual(analyze([{"event_id": 4624}]), [])

    def test_audit_log_cleared(self):
        self.assertEqual(analyze([{"event_id": 1102}])[0]["severity"], "critical")

    def test_invalid_event(self):
        with self.assertRaises(ValueError):
            analyze([{"event_id": "invalid"}])

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            analyze([], threshold=0)

    def test_jsonl_input(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "events.jsonl"
            path.write_text('{"event_id":4720}\n', encoding="utf-8")
            self.assertEqual(len(load_events(path)), 1)

    def test_invalid_jsonl(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad.jsonl"
            path.write_text("{bad}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "line 1"):
                load_events(path)

    def test_cli_report(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "events.jsonl"
            out = Path(temp) / "report.json"
            path.write_text('{"event_id":1102}\n', encoding="utf-8")
            self.assertEqual(main([str(path), "--output", str(out)]), 0)
            self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["events_processed"], 1)
