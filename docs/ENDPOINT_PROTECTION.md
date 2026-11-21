# KING SHIELD AI Endpoint — defensive workstation audit

This module is a **read-only posture auditor**, not an antivirus engine, EDR agent, intrusion prevention system, or replacement for Microsoft Defender. It checks security controls and highlights possible gaps. It does not stop malware or unauthorized location tracking by itself.

## On each authorized Windows computer

```powershell
py -3.11 -m kingshield.endpoint --audit --output endpoint-report.json
```

The audit checks Microsoft Defender antivirus and real-time protection, signature age, Windows Firewall profiles, Remote Desktop, Remote Assistance, machine-level location consent, and time since last restart. Unknown results mean a control could not be evaluated; they are **not** proof that a device is secure.

For a fleet, collect each report by your organization's approved secure method, keep reports private, and aggregate offline:

```powershell
py -3.11 -m kingshield.endpoint --fleet pc1.json pc2.json --output fleet-summary.json
```

The aggregator deliberately assigns neutral identifiers `endpoint-1`, `endpoint-2` and does not transmit reports over a network.

## Protection guidance

1. Keep Microsoft Defender or another reputable endpoint antivirus enabled and up to date.
2. Keep Windows Firewall on for all profiles.
3. Install operating system and browser updates.
4. Use MFA, strong passwords and least-privilege user accounts.
5. Disable Remote Desktop and Remote Assistance if not needed.
6. Review Windows Settings > Privacy & security > Location and each application's permissions.
7. Keep encrypted, offline or otherwise protected backups.
8. Investigate unexpected remote-control tools and login alerts.

Disabling Windows location services does **not** prevent IP-based geolocation, Wi-Fi network inference, account tracking, or location disclosure by other devices and services. For multi-device centralized monitoring, a secure authenticated management server, enrollment, encrypted transport, signed updates and incident-response procedures would still be required. These are **not** included in this prototype.

Do not upload endpoint reports to the public GitHub repository.
