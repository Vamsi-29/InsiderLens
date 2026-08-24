# InsiderLens False-Positive Tuning Guide

InsiderLens treats detections as investigation signals rather than automatic proof of malicious activity. This guide defines how to tune the current detection set before operational use.

## Tuning workflow

1. Confirm the event fields and sourcetype match the target Splunk data model.
2. Collect representative benign activity from normal users and administrators.
3. Run each detection independently and record recurring benign patterns.
4. Identify stable context that distinguishes expected activity from suspicious activity, such as user role, host, process parent, resource path, or time window.
5. Add narrow filters or allowlists only when the business justification is documented.
6. Re-run the suspicious test cases after each tuning change to make sure useful signals are not removed.
7. Record the final tuning decision and known blind spots.

## Detection-specific considerations

### Sensitive file access

Potential benign activity includes approved Finance, Customer Data, or HR workflows. Tune using documented role or service-account context rather than suppressing all access to sensitive resources.

### Archive creation

Backup jobs, software packaging, and administrative workflows can create archives legitimately. Correlate archive creation with the initiating user, process, destination and nearby sensitive-file access before escalation.

### USB activity

Removable media can be authorized for IT or operational workflows. Consider approved device/user context and the timing of nearby sensitive-data access when prioritizing alerts.

### PowerShell transfer patterns

PowerShell is commonly used for legitimate administration. Avoid treating PowerShell execution alone as exfiltration. Require relevant transfer indicators and surrounding endpoint context where possible.

### Security log clearing

Authorized maintenance can produce log-clearing events. Investigate the initiating account, host, timing and preceding activity rather than assuming every Event ID 1102 event is malicious.

## Correlation principle

A useful tuning objective is to reduce noise without removing the behavioral sequence modeled by InsiderLens:

`Sensitive access → archive/transfer activity → removable media or PowerShell transfer → evidence removal`

A single weak signal should generally receive lower investigative priority than multiple related signals from the same user, host and time window.

## Evidence to record

For each tuning change, document:

- Detection name
- Original behavior
- Benign example observed
- Tuning condition
- Reason for the exception
- Expected security impact
- Remaining blind spot

## Status

This is a tuning methodology, not a claim of measured false-positive rates. Actual thresholds and allowlists must be derived from representative logs in the target environment.
