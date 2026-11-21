# KING SHIELD AI

**DR Disso King** | Open-source defensive security event analyzer | v0.2.0

KING SHIELD AI is an **offline, rule-based prototype** for analyzing normalized Windows Security events, including events often observed on Active Directory domain controllers. It is **not** a trained AI model, live domain controller monitor, SIEM replacement, or autonomous protection system.

## Features

- JSONL event ingestion with validation, size and event-count limits
- Explainable alerts for account creation/deletion, password reset attempts, group membership changes, audit-policy changes and cleared security logs
- Batch threshold for failed logons (event 4625)
- JSON report output suitable for downstream tooling
- Standard-library-only runtime; no network access or privileged permissions required
- Optional Windows Security Log export script for authorized local administrators

## Run

Requires Python 3.9+.

```powershell
py -3.11 -m unittest discover -s tests -v
py -3.11 -m kingshield sample-events.jsonl
py -3.11 -m kingshield sample-events.jsonl --threshold 3 --output report.json
```

Install as a package (optional): `python -m pip install .`, then run `king-shield sample-events.jsonl`.

## Input schema

One JSON object per line, with `event_id` (integer), `source` (string), and optionally `group` (string). Example:

```json
{"event_id":4728,"source":"lab-dc-01","group":"Domain Admins"}
```

The `source` field represents the source host or identifier supplied by the exporter. Group membership alerts are high severity only for the explicitly named privileged groups; all other group changes are medium severity.

## Active Directory / Windows

See [docs/ACTIVE_DIRECTORY.md](docs/ACTIVE_DIRECTORY.md) for supported Windows event IDs and [scripts/Export-SecurityEvents.ps1](scripts/Export-SecurityEvents.ps1) for an **optional read-only local export**. The exporter must be run only on systems you administer and where access to security logs is authorized.

## Limitations and safety

- Detection is per input batch, **not** a rolling time window.
- No enrichment, user identity resolution, network scanning, machine learning or remote collection.
- False positives are possible. Validate alerts before responding.
- Avoid uploading real authentication logs, usernames, secrets or personal data to public repositories.
- No telemetry or external network calls in the analyzer.

## Development

```powershell
py -3.11 -m unittest discover -s tests -v
```

Contributions welcome; see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Apache License 2.0; see [LICENSE](LICENSE). Copyright 2026 DR Disso King.
