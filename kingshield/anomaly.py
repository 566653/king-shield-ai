"""Transparent offline anomaly scoring, not a trained AI model."""
from collections import Counter
from math import sqrt


def score_sources(events, minimum=3):
    """Identify unusually high failed-login counts using a robust count baseline.

    Uses median and median absolute deviation across observed sources.
    Scores are heuristic and meaningful only for comparable sources/batches.
    """
    if minimum < 1:
        raise ValueError("minimum must be positive")
    counts = Counter()
    for event in events:
        if int(event.get("event_id", 0)) == 4625:
            counts[str(event.get("source") or "unknown")[:128]] += 1
    if not counts:
        return []
    values = sorted(counts.values())
    def median(seq):
        n = len(seq)
        return (seq[(n - 1) // 2] + seq[n // 2]) / 2
    baseline = median(values)
    mad = median(sorted(abs(value - baseline) for value in values))
    results = []
    for source, count in sorted(counts.items()):
        if count < minimum:
            continue
        robust_z = (count - baseline) / (1.4826 * mad) if mad else 0.0
        if count >= max(minimum, baseline * 3) and (robust_z >= 3 or mad == 0):
            results.append({"source": source, "failed_logons": count,
                            "baseline_median": baseline, "robust_z": round(robust_z, 2),
                            "reason": "Failed logons exceed peer-source batch baseline"})
    return results
