"""Opt-in, local-only Windows Security log collection."""
from pathlib import Path
import subprocess
import sys
import tempfile


def collect_local(max_events=250):
    """Read selected Security events from the current Windows host only."""
    if sys.platform != "win32":
        raise RuntimeError("local Windows event collection requires Windows")
    if not isinstance(max_events, int) or not 1 <= max_events <= 5000:
        raise ValueError("max_events must be 1..5000")
    script = Path(__file__).resolve().parent.parent / "scripts" / "Export-SecurityEvents.ps1"
    if not script.is_file():
        raise RuntimeError("PowerShell export script not found")
    from .__main__ import load_events
    with tempfile.TemporaryDirectory(prefix="kingshield-") as folder:
        target = Path(folder) / "events.jsonl"
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(script),
                 "-OutputPath", str(target), "-MaxEvents", str(max_events)],
                capture_output=True, text=True, timeout=60, check=False)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Security log export timed out after 60 seconds") from exc
        if result.returncode:
            raise RuntimeError(
                "Unable to read the local Windows Security log. Run under an account "
                "authorized to read this log; check that matching events exist. "
                "No permissions have been changed.")
        if not target.is_file():
            raise RuntimeError("Security log exporter did not produce an output file")
        return load_events(target)
