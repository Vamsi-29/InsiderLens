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
