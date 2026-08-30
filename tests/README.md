# Test & Validation Guide

InsiderLens currently uses a **synthetic validation plan** rather than claiming execution against a live Splunk environment.

## What is covered

The validation scenarios map directly to the repository's five SPL detections:

| Scenario | Detection | Expected investigation signal |
|---|---|---|
| Sensitive Finance/HR/Customer_Data access | `sensitive_file_access.spl` | Sensitive-resource access |
| Archive utility or `Compress-Archive` execution | `archive_creation.spl` | Data-staging/archive activity |
| Newly detected USB device | `usb_device_activity.spl` | Removable-media activity |
| PowerShell outbound-transfer pattern | `powershell_exfiltration.spl` | Transfer-related PowerShell activity |
| Windows Security log clearing | `log_clearing.spl` | Evidence-removal activity |

## Validation approach

For each scenario, verify the required Windows/Sysmon/PowerShell event is present, confirm the Splunk field names and sourcetype match the target environment, then test the SPL against both benign and controlled suspicious data.

Record:

- Whether the expected signal appeared
- Relevant event fields
- Benign activity that generated a match
- Tuning applied and its justification
- Remaining blind spots

The project should not be described as production-ready until these checks have been performed against representative telemetry.

## Related documentation

- [`../docs/DETECTION_CATALOG.md`](../docs/DETECTION_CATALOG.md) — detection coverage and telemetry assumptions
- [`../docs/CORRELATION_MODEL.md`](../docs/CORRELATION_MODEL.md) — user/host/time-window correlation
- [`../docs/FALSE_POSITIVE_TUNING.md`](../docs/FALSE_POSITIVE_TUNING.md) — noise reduction methodology
- [`VALIDATION.md`](./VALIDATION.md) — synthetic test cases and success criteria
