# Optional offline trained anomaly model

The `kingshield.ml` module trains a simple diagonal Gaussian statistical baseline from events representing **normal, authorized** activity. It is a genuinely fitted model, but it is not a neural network, LLM, or production-grade machine-learning detector.

Training requires at least five distinct event sources. Features per source are log-scaled failed logons, sensitive changes, and total events. Scores measure standardized distance from training means. Use labeled, representative data, evaluate false positives, and keep model files private.

## Example (Python)

```python
from kingshield.__main__ import load_events
from kingshield.ml import train, save, load, predict

baseline = train(load_events("normal-training.jsonl"))
save(baseline, "private-model.json")
alerts = predict(load_events("sample-events.jsonl"), load("private-model.json"))
print(alerts)
```

Never train on public or confidential logs without proper authorization. No training data is bundled and no model is automatically trained from production events. Model files are JSON data only; no pickle execution.
