# InsiderLens

**Splunk SIEM detection engineering for insider threats and data exfiltration.**

InsiderLens simulates a realistic insider-threat scenario in which an employee accesses sensitive information, creates archives, transfers data through removable media, uploads data to cloud storage, and attempts to remove forensic evidence.

## What it demonstrates

- Windows Security Log and endpoint telemetry analysis
- Suspicious access to sensitive files
- Archive creation involving sensitive data
- USB/removable-media activity monitoring
- PowerShell-based data-exfiltration detection
- Log-clearing / anti-forensics detection
- Risk-based alerting and SOC triage
- MITRE ATT&CK-oriented detection thinking

## Detection engineering

The repository contains custom SPL detections under [`detections/`](./detections). The current detection set includes a sensitive-file-access rule based on Windows Event ID 4663 and patterns for Finance, Customer Data and HR resources.

Example:

```spl
index=windows EventCode=4663
(Object_Name="*Finance*" OR Object_Name="*Customer_Data*" OR Object_Name="*HR*")
| stats count by user Object_Name
```

### Analyst triage workflow

The sensitive-file-access detection is intended as a starting signal rather than a standalone verdict. A SOC analyst can investigate the alert by:

1. Identifying the `user` and accessed `Object_Name` returned by the search.
2. Reviewing the surrounding Windows events for the same user and time window.
3. Correlating the access with other endpoint activity such as archive creation, removable-media use, PowerShell execution, or log-clearing activity.
4. Checking whether the accessed resource and user activity are expected for the user's role.
5. Escalating the event when multiple suspicious behaviors form a consistent data-exfiltration sequence.

This keeps the detection focused on **behavioral correlation and analyst investigation**, rather than treating a single file-access event as proof of malicious activity.

## Architecture

```text
Windows / Sysmon telemetry
          ↓
       Splunk
          ↓
Correlation + SPL detections
          ↓
   Risk scoring / triage
          ↓
   SOC investigation
```

## Project goals

The goal is to demonstrate how endpoint telemetry can be converted into practical detections that help a SOC analyst identify suspicious insider activity before sensitive data leaves an organization.

## Status

Active portfolio project. Additional detections and investigation workflows can be added as the project evolves.
