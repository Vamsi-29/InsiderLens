# InsiderLens Correlation Model

InsiderLens is designed around a sequence of weak-to-strong investigation signals rather than treating one event as proof of malicious activity.

## Correlation sequence

```text
Sensitive resource access
        ↓
Archive creation
        ↓
USB/removable-media activity OR PowerShell transfer activity
        ↓
Security-log clearing
        ↓
Higher-confidence insider-threat investigation
```

## Signal model

| Signal | Example telemetry | Investigation meaning |
|---|---|---|
| Sensitive file access | Windows Event ID 4663 | A user accessed a resource considered sensitive |
| Archive creation | Sysmon Event ID 1 | Files may have been staged or compressed |
| USB activity | Windows Event ID 6416 | A removable device was detected |
| PowerShell activity | PowerShell Event ID 4104 | PowerShell executed transfer-related commands |
| Log clearing | Windows Event ID 1102 | Security event logs were cleared |

## Analyst correlation logic

A useful investigation should correlate signals by **user, host, and time window**. The sequence should be treated as contextual evidence, not an automatic malicious verdict.

A practical triage model is:

- **Low confidence:** one isolated signal with no supporting activity.
- **Medium confidence:** sensitive-resource access plus one related staging or transfer signal.
- **High confidence:** sensitive-resource access followed by staging/transfer activity and evidence-removal behavior within the same investigation window.

These labels are an investigation framework, not measured detection-performance results.

## Tuning considerations

Before using this model in a real environment, tune it for:

- Service accounts and backup processes
- Approved administrative activity
- Endpoint management software
- Known removable-media workflows
- Legitimate PowerShell automation
- Organizational definitions of sensitive resources
- Normal event volume and retention

The model should be validated against representative benign and suspicious telemetry before production deployment.
