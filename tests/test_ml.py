import tempfile
import unittest
from pathlib import Path
from kingshield.ml import train, predict, save, load


class ModelTests(unittest.TestCase):
    def normal(self):
        return [{"event_id": 4624, "source": f"host-{i}"} for i in range(8)]

    def test_train(self):
        model = train(self.normal())
        self.assertEqual(model["samples"], 8)

    def test_detect_outlier(self):
        model = train(self.normal())
        events = [{"event_id": 4625, "source": "attacker"}] * 20
        self.assertEqual(predict(events, model)[0]["source"], "attacker")

    def test_save_load(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "model.json"
            model = train(self.normal())
            save(model, path)
            self.assertEqual(load(path), model)

    def test_insufficient_data(self):
        with self.assertRaises(ValueError):
            train([{"event_id": 4624, "source": "one"}])
