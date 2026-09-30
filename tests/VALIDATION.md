# Detection Validation Plan

This document defines a **synthetic test plan** for validating the InsiderLens detections. The cases below are test scenarios, not claims that the repository has been executed against these events.

## Test cases

| ID | Scenario | Expected signal |
|---|---|---|
| T01 | User accesses a Finance/HR/Customer_Data resource | `sensitive_file_access.spl` |
| T02 | User launches a supported archive utility or PowerShell `Compress-Archive` | `archive_creation.spl` |
| T03 | Windows reports a newly detected USB device | `usb_device_activity.spl` |
| T04 | PowerShell Script Block Logging contains an outbound-transfer pattern | `powershell_exfiltration.spl` |
| T05 | Windows Security audit log is cleared | `log_clearing.spl` |
| T06 | Multiple suspicious behaviors occur for the same user and host in a short investigation window | Analyst correlation / escalation workflow |

## Validation method

For each detection:

1. Confirm the required Windows/Sysmon event is present.
2. Confirm the Splunk sourcetype and field names match the environment.
3. Run the SPL against representative benign data.
4. Run it against controlled suspicious test data.
5. Record whether the expected signal appears.
6. Document false positives and tune the query.

## Evidence to record

For each validation run, record enough information for another analyst to reproduce and review the result:

| Field | What to record |
|---|---|
| Detection | SPL filename and version/commit tested |
| Dataset | Synthetic, benign, or controlled suspicious data |
| Telemetry | Event ID, sourcetype, and fields available |
| Expected | Behavior the detection should identify |
| Observed | Whether the expected signal appeared |
| False positives | Benign matches and their reason |
| Tuning | Query changes made, if any |
| Blind spots | Required telemetry or behaviors not covered |

Do not store real credentials, tokens, personal data, or sensitive production logs in this repository. Prefer synthetic or sanitized validation data.

## Success criteria

A detection should not be considered production-ready merely because the SPL returns results. Validation should demonstrate that it identifies the intended behavior while keeping false positives manageable and documenting the telemetry assumptions.
