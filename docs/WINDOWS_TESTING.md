# Windows collection validation

The local collector reads Windows Security events with `Get-WinEvent`. It does not change Windows permissions, enable auditing, or connect to a domain controller.

## Preflight on a system you administer

Open an authorized PowerShell session and check:

```powershell
Get-WinEvent -ListLog Security | Select-Object LogName, RecordCount
```

If access is denied, use an appropriately authorized account through your organization's approved procedure. Do **not** grant broad access to security logs or disable Windows protections just to run this tool.

Then:

```powershell
py -3.11 -m kingshield --collect-local --max-events 25 --output report.json
```

If there are no matching event IDs, the exporter writes an empty file and the report should show zero events. If permission is denied, the tool exits with a readable error and does not attempt privilege escalation.

## Current validation status

- Unit tests: passing on Windows workstation EMPIRE.
- Local Security log read on EMPIRE: blocked by Windows access permissions.
- Domain controller integration: not tested; requires a dedicated authorized lab environment.
- GUI: Tkinter import and Python compilation checked; visual interaction not yet manually verified.
