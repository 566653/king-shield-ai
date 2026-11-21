import json
import sys
from collections import Counter
from pathlib import Path

RULES = {4728: ('high', 'Member added to privileged global group'), 4732: ('high', 'Member added to local security group'), 4720: ('medium', 'User account created')}

def analyze(events):
    failures = Counter()
    findings = []
    for event in events:
        event_id = int(event.get('event_id', 0))
        source = str(event.get('source', 'unknown'))[:128]
        if event_id == 4625:
            failures[source] += 1
        if event_id in RULES:
            severity, reason = RULES[event_id]
            findings.append({'severity': severity, 'event_id': event_id, 'source': source, 'reason': reason})
    for source, count in failures.items():
        if count >= 5:
            findings.append({'severity': 'medium', 'event_id': 4625, 'source': source, 'reason': f'{count} failed logons in input batch'})
    return findings

def main():
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python -m kingshield events.jsonl')
    path = Path(sys.argv[1])
    if path.stat().st_size > 10_000_000:
        raise SystemExit('Input exceeds 10 MB limit')
    with path.open(encoding='utf-8') as stream:
        events = [json.loads(line) for line in stream if line.strip()]
    print(json.dumps({'findings': analyze(events)}, indent=2))

if __name__ == '__main__':
    main()
