import unittest
from kingshield.__main__ import analyze

class AnalyzerTests(unittest.TestCase):
    def test_privileged_group(self):
        self.assertEqual(analyze([{'event_id': 4728}])[0]['severity'], 'high')
    def test_failed_logons(self):
        self.assertEqual(len(analyze([{'event_id': 4625, 'source': 'demo'}] * 5)), 1)
    def test_no_alert(self):
        self.assertEqual(analyze([{'event_id': 4624}]), [])
