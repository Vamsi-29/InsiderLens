# InsiderLens

**Splunk SIEM detection engineering for insider threats and data exfiltration.**

InsiderLens is a defensive security portfolio project that models a simulated insider-threat scenario and turns Windows/endpoint telemetry into investigation signals. The project focuses on detection engineering, analyst triage, telemetry assumptions, and practical investigation workflows.

## Scenario

The simulated scenario covers a user who:

1. Accesses sensitive information.
2. Creates an archive containing data.
3. Uses removable media.
4. Uses PowerShell-related transfer tooling.
5. Attempts to remove forensic evidence.

The repository does **not** treat any single event as proof of compromise. The intended workflow is to correlate multiple signals and validate activity against the user's expected role and baseline.

## Detection coverage

Current SPL detections are stored under [`detections/`](./detections):

| Detection | Telemetry | Focus |
|---|---|---|
| [`sensitive_file_access.spl`](./detections/sensitive_file_access.spl) | Windows Event ID 4663 | Sensitive resource access |
| [`archive_creation.spl`](./detections/archive_creation.spl) | Sysmon Event ID 1 | Archive creation |
| [`usb_device_activity.spl`](./detections/usb_device_activity.spl) | Windows Event ID 6416 | USB/removable-device activity |
| [`powershell_exfiltration.spl`](./detections/powershell_exfiltration.spl) | PowerShell Event ID 4104 | PowerShell transfer patterns |
| [`log_clearing.spl`](./detections/log_clearing.spl) | Windows Event ID 1102 | Security log clearing |

See [`docs/DETECTION_CATALOG.md`](./docs/DETECTION_CATALOG.md) for telemetry prerequisites, ATT&CK-oriented technique mapping, investigation guidance, and validation considerations.

## Example: sensitive file access

```spl
index=windows EventCode=4663
(Object_Name="*Finance*" OR Object_Name="*Customer_Data*" OR Object_Name="*HR*")
| stats count by user Object_Name
```

This is a starting signal for investigation. A high-quality detection workflow should correlate the user, host, resource, time window, and related endpoint events before escalation.

## Analyst triage workflow

1. Identify the affected `user`, `host`, and `Object_Name`.
2. Establish the relevant time window around the alert.
3. Review nearby endpoint events for archive creation, removable media, PowerShell activity, or log clearing.
4. Determine whether the activity is consistent with the user's role and normal behavior.
5. Correlate multiple signals when available instead of relying on one event.
6. Document the evidence, confidence, impact, and recommended response.

## Architecture

```text
Windows Security Logs / Sysmon / PowerShell
                    ↓
                 Splunk
                    ↓
             SPL detections
                    ↓
        Correlation + investigation
                    ↓
             SOC triage
```

## MITRE ATT&CK-oriented coverage

The current detection themes map broadly to techniques including:

- **T1005 — Data from Local System**
- **T1560 — Archive Collected Data**
- **T1052.001 — Exfiltration Over Physical Medium: Exfiltration over USB**
- **T1059.001 — Command and Scripting Interpreter: PowerShell**
- **T1070.001 — Indicator Removal: Clear Windows Event Logs**

These mappings describe the behavioral focus of the detections; they are not claims that every matching event represents malicious activity.

## Validation and limitations

The SPL queries are **portfolio/reference detections**, not production-ready content. Windows/Sysmon sourcetypes and field names vary between environments, so the searches should be validated against representative logs before deployment.

A mature detection lifecycle should include:

- Benign and suspicious test cases
- False-positive measurement and tuning
- Documented telemetry prerequisites
- Severity/risk rationale
- Known blind spots
- Periodic review as attacker behavior and logging change

## Project goals

InsiderLens demonstrates the workflow from **endpoint telemetry → detection logic → investigation → analyst decision-making**. The emphasis is on practical detection engineering rather than simply collecting SPL queries.

## Status

Active portfolio project. Future work can add controlled test data, detection validation, correlation logic, dashboards, and measurable tuning results.
