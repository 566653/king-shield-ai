"""Local-only, read-only Windows endpoint posture checks and offline fleet summaries."""
import json
from pathlib import Path
import subprocess
import sys

VALID_STATUSES = {"pass", "warn", "fail", "unknown"}
MAX_REPORT_BYTES = 100_000


def validate(report):
    if not isinstance(report, dict) or report.get("schema_version") != 1:
        raise ValueError("unsupported endpoint report schema")
    checks = report.get("checks")
    if not isinstance(checks, dict) or not checks:
        raise ValueError("missing endpoint checks")
    for name, check in checks.items():
        if not isinstance(name, str) or not isinstance(check, dict):
            raise ValueError("invalid endpoint check")
        if check.get("status") not in VALID_STATUSES or not isinstance(check.get("detail"), str):
            raise ValueError("invalid check status or detail")
    return report


def audit_local():
    """Inspect current Windows machine. No privilege escalation or remediation."""
    if sys.platform != "win32":
        raise RuntimeError("Windows endpoint audit requires Windows")
    script = Path(__file__).resolve().parent.parent / "scripts" / "Get-EndpointPosture.ps1"
    if not script.is_file():
        raise RuntimeError("endpoint PowerShell script is missing")
    try:
        process = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(script)],
            capture_output=True, text=True, timeout=45, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("endpoint audit timed out") from exc
    if process.returncode:
        raise RuntimeError("endpoint audit could not execute: Windows PowerShell script execution may be restricted by policy. Review organizational policy; no settings were changed")
    try:
        report = json.loads(process.stdout.lstrip("\ufeff").strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError("endpoint audit returned invalid JSON") from exc
    return validate(report)


def summarize(reports):
    """Aggregate sanitized reports from multiple computers without network access."""
    machines = []
    for index, report in enumerate(reports, 1):
        validate(report)
        counts = {status: 0 for status in sorted(VALID_STATUSES)}
        for check in report["checks"].values():
            counts[check["status"]] += 1
        machines.append({"machine": f"endpoint-{index}", "checks": counts})
    return {"schema_version": 1, "machines": machines,
            "total_machines": len(machines),
            "machines_with_failures": sum(machine["checks"]["fail"] > 0 for machine in machines)}


def load_report(path):
    path = Path(path)
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("endpoint report exceeds 100 KB")
    return validate(json.loads(path.read_text(encoding="utf-8-sig")))


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description="KING SHIELD AI read-only endpoint protection audit")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--audit", action="store_true", help="Audit this Windows computer")
    group.add_argument("--fleet", nargs="+", metavar="REPORT", help="Aggregate JSON reports from several computers")
    parser.add_argument("--output", type=Path, help="Save JSON report locally")
    args = parser.parse_args(argv)
    try:
        result = audit_local() if args.audit else summarize([load_report(p) for p in args.fleet])
        serialized = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            args.output.write_text(serialized, encoding="utf-8")
        else:
            print(serialized, end="")
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Endpoint audit error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

