# InsiderLens Threat Model

## Purpose

InsiderLens models a simulated insider-threat scenario in which a user accesses sensitive data and performs a sequence of actions that may indicate data staging, transfer, and anti-forensic behavior.

This document defines the assumptions and investigation boundaries for the portfolio detections. It is a threat-modeling artifact, not a claim that the simulated behavior represents a production incident.

## Assets

| Asset | Security concern |
|---|---|
| Finance data | Confidential business information |
| Customer data | Sensitive organizational/customer information |
| HR data | Sensitive employee information |
| Windows endpoint | Source of security and Sysmon telemetry |
| Removable media | Potential physical data-transfer path |
| Splunk | Detection, correlation, and investigation platform |
| Security logs | Evidence required for investigation |

## Threat actor assumptions

The modeled actor is an authorized user whose activity may become malicious or policy-violating. The scenario assumes the user already has legitimate access to at least some endpoint resources.

The detections therefore focus on **behavioral anomalies and sequences**, rather than attempting to identify an attacker solely from authentication events.

## Attack sequence modeled

```text
Sensitive data access
        ↓
Data staging / archive creation
        ↓
Removable-media or PowerShell transfer activity
        ↓
Potential evidence removal
        ↓
SOC correlation and investigation
```

Individual events are treated as investigation signals. Confidence should increase when multiple signals occur for the same user/host within a relevant time window.

## Detection assumptions

The current project assumes availability of some combination of:

- Windows Security events
- Sysmon process telemetry
- PowerShell Script Block Logging
- Removable-device telemetry
- Splunk indexing and search capability

Exact field names, sourcetypes, logging configuration, and event availability vary by environment and must be validated before deployment.

## Out of scope

The current model does not claim to detect:

- All insider-threat behaviors
- Cloud-only exfiltration without endpoint evidence
- Data theft through encrypted or custom protocols without useful telemetry
- Compromised accounts whose activity is indistinguishable from the legitimate user's baseline
- Endpoint activity for which the required Windows/Sysmon telemetry is unavailable

## Investigation priorities

When multiple detections correlate, an analyst should prioritize:

1. Confirming the user, host, resource and time window.
2. Establishing whether the activity is authorized and expected.
3. Correlating process, file, removable-media and PowerShell evidence.
4. Preserving relevant evidence before destructive actions remove context.
5. Recording confidence, impact and supporting evidence before escalation.

## Validation requirement

Before treating these detections as operational controls, test them with both benign and suspicious scenarios. Measure false positives, confirm the required telemetry exists, tune environment-specific fields, and document known blind spots.
