# Active Directory event coverage

KING SHIELD AI does not connect to Active Directory, use LDAP, or modify domain settings. It analyzes exported and normalized **Windows Security** events.

| Event ID | Interpretation | Rule |
| --- | --- | --- |
| 4625 | Failed logon | Alert after configured count per source in batch |
| 4720 | User account created | Medium |
| 4726 | User account deleted | Medium |
| 4724 | Password reset attempted | High |
| 4728 | Member added to global security group | High for named privileged groups |
| 4732 | Member added to local security group | High for named privileged groups |
| 4756 | Member added to universal security group | High for named privileged groups |
| 4719 | Audit policy changed | High |
| 1102 | Security log cleared | Critical |

Group names may be localized or renamed; adjust your upstream normalization. The exporter has limited group-name extraction and does not handle every localized format. Verify event fields in your environment.

## Authorized workflow

1. Export a small batch of Security events on an authorized Windows host.
2. Inspect the JSONL for sensitive information before sharing.
3. Run `python -m kingshield exported-events.jsonl --output report.json`.
4. Investigate alerts using approved administrative procedures.

## Roadmap

- Structured XML extraction and localization
- Time-window aggregation and deduplication
- Optional offline anomaly scoring with explainability
- Windows collection integration tests
