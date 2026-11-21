"""Optional trained, explainable, offline anomaly model with no dependencies."""
import json
from collections import Counter
from math import log1p
from pathlib import Path

MODEL_VERSION = 1


def features(events):
    """Per-source failed logons, total events and security-sensitive changes."""
    grouped = {}
    for event in events:
        source = str(event.get("source") or "unknown")[:128]
        record = grouped.setdefault(source, {"failed": 0, "changes": 0, "total": 0})
        record["total"] += 1
        event_id = int(event.get("event_id", 0))
        record["failed"] += event_id == 4625
        record["changes"] += event_id in (4720, 4724, 4726, 4728, 4732, 4756, 4719, 1102)
    return {source: [log1p(row["failed"]), log1p(row["changes"]), log1p(row["total"])]
            for source, row in grouped.items()}


def train(events):
    """Fit a diagonal Gaussian baseline from labeled-as-normal input batches.

    This is an elementary trained statistical model, not a neural network.
    """
    rows = list(features(events).values())
    if len(rows) < 5:
        raise ValueError("training requires at least five distinct sources")
    means = [sum(row[i] for row in rows) / len(rows) for i in range(3)]
    variances = [sum((row[i] - means[i]) ** 2 for row in rows) / len(rows) for i in range(3)]
    return {"version": MODEL_VERSION, "method": "diagonal-gaussian",
            "samples": len(rows), "means": means,
            "variances": [max(value, 0.01) for value in variances]}


def validate_model(model):
    if not isinstance(model, dict) or model.get("version") != MODEL_VERSION or model.get("method") != "diagonal-gaussian":
        raise ValueError("unsupported model format")
    for key in ("means", "variances"):
        values = model.get(key)
        if not isinstance(values, list) or len(values) != 3 or not all(isinstance(v, (int, float)) for v in values):
            raise ValueError("invalid model parameters")
    if any(value <= 0 for value in model["variances"]):
        raise ValueError("invalid variances")


def predict(events, model, threshold=4.0):
    validate_model(model)
    if threshold <= 0:
        raise ValueError("threshold must be positive")
    result = []
    for source, row in sorted(features(events).items()):
        score = sum(((row[i] - model["means"][i]) ** 2) / model["variances"][i] for i in range(3)) ** 0.5
        if score >= threshold:
            result.append({"source": source, "score": round(score, 3),
                           "reason": "Feature vector differs from trained normal baseline"})
    return result


def save(model, path):
    validate_model(model)
    Path(path).write_text(json.dumps(model, indent=2) + "\n", encoding="utf-8")


def load(path):
    file = Path(path)
    if file.stat().st_size > 100_000:
        raise ValueError("model file too large")
    model = json.loads(file.read_text(encoding="utf-8"))
    validate_model(model)
    return model
