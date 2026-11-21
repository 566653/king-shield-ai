"""Command line entry point for offline security-event analysis."""
import argparse
import json
import sys
from pathlib import Path
from .analyzer import analyze

MAX_BYTES = 10_000_000
MAX_EVENTS = 100_000


def load_events(path):
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("input exceeds 10 MB limit")
    events = []
    with path.open(encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {line_number}: invalid JSON: {exc.msg}") from exc
            if not isinstance(item, dict):
                raise ValueError(f"line {line_number}: expected JSON object")
            events.append(item)
            if len(events) > MAX_EVENTS:
                raise ValueError("too many events")
    return events


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline Windows security event analysis")
    parser.add_argument("input", type=Path, nargs="?", help="Normalized JSONL input")
    parser.add_argument("--collect-local", action="store_true", help="Read local Windows Security log (authorized use only)")
    parser.add_argument("--max-events", type=int, default=250, help="Maximum events for local collection")
    parser.add_argument("--anomalies", action="store_true", help="Include explainable statistical anomaly scores")
    parser.add_argument("--threshold", type=int, default=5, help="Failed logons per source (default: 5)")
    parser.add_argument("--output", type=Path, help="Write report to JSON file")
    args = parser.parse_args(argv)
    if args.collect_local == (args.input is not None):
        parser.error("provide exactly one of input JSONL or --collect-local")
    try:
        if args.collect_local:
            from .collector import collect_local
            events = collect_local(args.max_events)
        else:
            events = load_events(args.input)
        report = {"schema_version": 1, "events_processed": len(events),
                  "findings": analyze(events, args.threshold)}
        if args.anomalies:
            from .anomaly import score_sources
            report["anomalies"] = score_sources(events)
        result = json.dumps(report, indent=2, ensure_ascii=False)
        if args.output:
            args.output.write_text(result + "\n", encoding="utf-8")
        else:
            print(result)
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
