# Architecture and threat model

KING SHIELD AI is a local defensive analyzer with three independent entry points:

- `python -m kingshield input.jsonl`: CLI rules and optional heuristic anomaly scoring.
- `python -m kingshield --collect-local`: opt-in, read-only export of selected Windows Security events from the **current** host, followed by analysis.
- `python -m kingshield.gui`: local Tkinter graphical interface for JSONL inspection.

## Trust boundaries

The analyzer treats input files as untrusted. JSONL input is capped at 10 MB and 100,000 events. No credentials, domain controller access, remote commands, or network calls are required. The optional collector reads the local Windows Security log and requires explicit operator action and existing Windows permissions.

## AI status

The optional anomaly module uses an explainable robust statistical heuristic (median/MAD) across event sources. It is **not** a trained AI model. The project name includes AI as a roadmap designation, not a claim of production machine learning.

## Future improvements

- Time-aware baselines with labeled evaluation data
- Streaming processing for larger files
- Signed releases, reproducible packaging, dependency review
- Permission-scoped remote collection through approved enterprise management tooling
- Integration testing against a dedicated Windows lab domain controller
