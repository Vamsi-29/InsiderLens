# InsiderLens Detection Catalog

InsiderLens uses endpoint and Windows security telemetry to produce investigation signals for a simulated insider-threat scenario.

> **Important:** The SPL queries are portfolio/reference detections. Field names and sourcetypes may need to be adapted to the actual Windows/Sysmon data model in a deployment. They should be validated against representative logs before production use.

| Detection | Primary telemetry | Technique focus | Purpose |
|---|---|---|---|
| `sensitive_file_access.spl` | Windows Event ID 4663 | Data from Local System | Identify access to resources named Finance, Customer Data, or HR |
| `archive_creation.spl` | Sysmon Event ID 1 / process creation | Archive Collected Data | Surface archive utilities and PowerShell `Compress-Archive` activity |
| `usb_device_activity.spl` | Windows Event ID 6416 | Exfiltration Over Physical Medium | Surface newly detected USB/removable-device activity |
| `powershell_exfiltration.spl` | PowerShell Script Block Logging Event ID 4104 | PowerShell / application-layer transfer | Surface PowerShell patterns associated with outbound transfer tooling |
| `log_clearing.spl` | Windows Event ID 1102 | Clear Windows Event Logs | Surface attempts to clear the Security event log |

## Investigation principle

These detections are **signals, not verdicts**. A SOC analyst should correlate the alert with the same user's activity, host, and time window before deciding whether the behavior is expected or suspicious.

A higher-confidence investigation can combine:

1. Sensitive-resource access
2. Archive creation
3. Removable-media activity
4. PowerShell transfer behavior
5. Evidence-removal activity

The exact correlation logic should be tuned to the organization's baseline and telemetry schema rather than treating every individual event as malicious.

## Validation checklist

Before considering a detection production-ready:

- Confirm the expected sourcetype and field names.
- Test against benign administrative activity.
- Test against representative suspicious activity.
- Measure false positives and tune filters.
- Add a documented severity/risk rationale.
- Record the telemetry prerequisites and known blind spots.
