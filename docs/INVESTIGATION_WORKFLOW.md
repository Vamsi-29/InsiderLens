# InsiderLens Investigation Workflow

InsiderLens is designed to support analyst investigation rather than automatically label a user as malicious. The current detection set covers sensitive-resource access, archive creation, removable-media activity, PowerShell transfer patterns, and Security event-log clearing.

## 1. Confirm the alert context

Record the minimum investigation context before correlating events:

- User
- Host
- Detection name
- Event time
- Relevant resource or process
- Source event / telemetry type

Do not infer intent from the detection alone.

## 2. Build the investigation window

Use the alert time as an anchor and review nearby activity for the same user and host. The repository's correlation model expects the analyst to look for a sequence rather than isolated events.

```text
Sensitive access
      ↓
Archive / staging activity
      ↓
USB or PowerShell transfer activity
      ↓
Security-log clearing
```

The exact time window should be adapted to the environment and event volume; this repository does not claim a universal threshold.

## 3. Correlate the available evidence

| Evidence | Question to answer |
|---|---|
| Event ID 4663 | Was a sensitive resource accessed, and by whom? |
| Sysmon process creation | Was an archive utility or related process launched? |
| Event ID 6416 | Was removable media detected around the activity? |
| PowerShell 4104 | Was PowerShell used for a relevant transfer pattern? |
| Event ID 1102 | Was the Security event log cleared, and when? |

A detection match is an investigation signal. Correlation should consider user, host, time, process context, resource, and expected business activity.

## 4. Check for legitimate explanations

Before escalation, compare the activity with the user's expected role and known operational workflows. Examples include:

- Approved access to Finance, Customer Data, or HR resources
- Backup or software-packaging jobs that create archives
- Authorized removable-media workflows
- Legitimate PowerShell administration
- Approved maintenance that clears security logs

Any allowlist or tuning decision should have a documented business justification rather than suppressing a broad event category.

## 5. Assess investigation confidence

Use the existing correlation model as a qualitative guide:

- **Low confidence:** one isolated signal with no supporting activity.
- **Medium confidence:** sensitive-resource access plus a related staging or transfer signal.
- **High confidence:** sensitive-resource access followed by staging/transfer activity and evidence-removal behavior within the same investigation window.

These are investigation labels, not measured detection-performance scores.

## 6. Document the evidence

A useful investigation record should capture:

```text
User:
Host:
Detection:
Time window:
Observed events:
Expected/authorized activity:
Correlated signals:
Confidence:
Potential impact:
Known telemetry gaps:
Recommended next action:
```

Keep observations separate from conclusions. If required telemetry is missing, record that limitation rather than filling the gap with an assumption.

## 7. Validate before operational use

The repository's validation plan requires testing against representative benign and suspicious data, confirming the Splunk field/sourcetype mapping, recording false positives, and documenting blind spots before treating the detections as production-ready.

## Scope

This workflow is a portfolio investigation framework for the simulated InsiderLens scenario. It does not claim measured SOC performance, production deployment, or coverage of all insider-threat behaviors.
