# InsiderLens
InsiderLens is a SOC-focused detection engineering project designed to identify malicious insider activity before sensitive data leaves an organization.

The platform simulates a real-world insider threat scenario where an employee attempts to access confidential data, compress files, transfer data through USB devices, upload archives to cloud storage, and erase forensic evidence.

Splunk is used to ingest endpoint telemetry, correlate suspicious behaviors, assign risk scores, and generate actionable alerts.

Objectives
Detect unauthorized access to sensitive data
Identify abnormal file access patterns
Detect archive creation of sensitive documents
Monitor USB device usage
Detect PowerShell-based data exfiltration
Identify log tampering attempts
Generate risk-based alerts
Reduce SOC analyst investigation time
