"""Explainable, offline detection of selected Windows security events."""
from collections import Counter
from datetime import datetime, timezone

RULES = {
    4728: ("high", "Member added to a global security group"),
    4732: ("high", "Member added to a local security group"),
    4756: ("high", "Member added to a universal security group"),
    4720: ("medium", "User account created"),
    4726: ("medium", "User account deleted"),
    4724: ("high", "Password reset attempted"),
    4719: ("high", "System audit policy changed"),
    1102: ("critical", "Security audit log cleared"),
}
PRIVILEGED_GROUPS = {"domain admins", "enterprise admins", "schema admins", "administrators"}
MAX_SOURCE_LENGTH = 128


def analyze(events, threshold=5):
    """Return deterministic alerts for a batch of normalized event dictionaries."""
    if not isinstance(threshold, int) or threshold < 1:
        raise ValueError("threshold must be a positive integer")
    failures = Counter()
    findings = []
    for index, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            raise ValueError(f"event {index}: expected object")
        try:
            event_id = int(event.get("event_id", 0))
        except (ValueError, TypeError):
            raise ValueError(f"event {index}: invalid event_id") from None
        source = str(event.get("source") or "unknown")[:MAX_SOURCE_LENGTH]
        group = str(event.get("group") or "").casefold().strip()
        if event_id == 4625:
            failures[source] += 1
        if event_id in RULES:
            severity, reason = RULES[event_id]
            if event_id in (4728, 4732, 4756) and group not in PRIVILEGED_GROUPS:
                severity = "medium"
                reason = "Member added to security group"
            findings.append({"severity": severity, "event_id": event_id, "source": source, "reason": reason})
    for source, count in sorted(failures.items()):
        if count >= threshold:
            findings.append({"severity": "medium", "event_id": 4625, "source": source,
                             "reason": f"{count} failed logons in input batch"})
    return findings
