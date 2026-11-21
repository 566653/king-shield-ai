import unittest
from kingshield.anomaly import score_sources


class AnomalyTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(score_sources([]), [])

    def test_single_source_not_anomaly(self):
        self.assertEqual(score_sources([{"event_id": 4625, "source": "one"}] * 10), [])

    def test_outlier(self):
        events = []
        for source, count in [("a", 3), ("b", 3), ("c", 3), ("d", 20)]:
            events.extend([{"event_id": 4625, "source": source}] * count)
        self.assertEqual(score_sources(events)[0]["source"], "d")

    def test_minimum(self):
        with self.assertRaises(ValueError):
            score_sources([], minimum=0)
