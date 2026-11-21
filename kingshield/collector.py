"""Opt-in, local-only Windows Security log collection."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def collect_local(max_events=250):
    """Return normalized events from the local Security log only.

    Requires Windows and permission to read the Security log.
    No remote host, LDAP, domain credentials, or network access is used.
    """
    if sys.platform != "win32":
        raise RuntimeError("local Windows event collection requires Windows")
    if not 1 <= max_events <= 5000:
        raise ValueError("max_events must be 1..5000")
    script = Path(__file__).resolve().parent.parent / "scripts" / "Export-SecurityEvents.ps1"
    if not script.is_file():
        raise RuntimeError("PowerShell export script not found")
    from .__main__ import load_events
    with tempfile.TemporaryDirectory(prefix="kingshield-") as folder:
        target = Path(folder) / "events.jsonl"
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(script),
             "-OutputPath", str(target), "-MaxEvents", str(max_events)],
            capture_output=True, text=True, timeout=60, check=False)
        if result.returncode:
            raise RuntimeError("Windows Security log export failed: check permissions and event availability")
        return load_events(target)
