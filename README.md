# KING SHIELD AI

**DR Disso King** | Open-source defensive Windows and Active Directory event analysis | v0.3.0

KING SHIELD AI is a local, offline security-event analysis prototype. It includes explainable rules, a **statistical anomaly heuristic**, a **Tkinter desktop GUI**, and optional **read-only local Windows Security log collection**.

**Important:** It is not a trained AI model, a production SIEM, an agent for remote domain-controller administration, or a guarantee of intrusion detection.

## Features

- Analyze normalized JSONL Windows Security events (max 10 MB / 100,000 events)
- Explainable alerts for events 4625, 4720, 4724, 4726, 4728, 4732, 4756, 4719 and 1102
- Optional robust peer-source anomaly scoring for failed logons (median/MAD heuristic)
- Desktop GUI with sortable event table (Tkinter)
- Optional local-only, read-only PowerShell Security log exporter
- JSON reports, Python packaging, automated unit tests, Apache 2.0 license
- No cloud services, remote access, credentials or telemetry

## Quick start

Requires Python 3.9+; GUI requires Tkinter (normally bundled with Windows Python).

```powershell
py -3.11 -m unittest discover -s tests -v
py -3.11 -m kingshield sample-events.jsonl --anomalies
py -3.11 -m kingshield.gui
```

To collect events from **your own authorized Windows computer** (Security log read permission required):

```powershell
py -3.11 -m kingshield --collect-local --max-events 250 --output report.json
```

Optional installation: `python -m pip install .` then `king-shield sample-events.jsonl`.

## JSONL format

One object per line, with `event_id`, `source` and optional `group`:

```json
{"event_id":4728,"source":"lab-dc-01","group":"Domain Admins"}
```

## Documentation

- [Active Directory event coverage](docs/ACTIVE_DIRECTORY.md)
- [Architecture and threat model](docs/ARCHITECTURE.md)
- [Contribution guidelines](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Limitations

The failed-logon rule counts per **input batch**, not per time window. Anomaly scoring compares sources within the same batch; small or non-comparable batches may mislead. Windows export depends on Security log permissions and event availability. The GUI loads JSONL only; it does not directly connect to domain controllers. Always investigate alerts manually.

## License

Apache License 2.0 — see [LICENSE](LICENSE). Copyright 2026 DR Disso King.
