# KING SHIELD AI

Open-source defensive security event analyzer by **DR Disso King**.

## Quick start

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m kingshield sample-events.jsonl
```

Reads local JSONL events and emits explainable security alerts. No network connection, credentials, or elevated privileges required. This is a prototype, not a production SOC or trained AI model.

## Supported events

Failed logons (4625), privileged group changes (4728, 4732), and account creation (4720). The input is user-supplied JSONL, not direct Windows Event Log ingestion.

## Security

Use synthetic events for demonstrations. Do not commit personal data, secrets, or production logs. Report vulnerabilities privately through SECURITY.md.

## License

Apache-2.0. Copyright 2026 DR Disso King.
