---
title: "Endpoint Telemetry in a Red Team Assessment"
date: 2026-09-25
weight: 4
type: docs
tags:
  - Endpoint Security
  - Telemetry
  - Detection Engineering
---

Endpoint security products observe activity through several layers. An assessment is more useful when it measures which behaviors are visible and how the response process handles them, rather than treating a single alert or a blocked file as the whole result.

## Think in layers

Depending on the platform and configuration, telemetry may describe process creation, command lines, module loads, memory behavior, authentication, network connections, registry changes, file writes, and kernel level events. Each source has blind spots and a different retention period. A missing alert does not prove that no event was recorded.

Before testing, agree which telemetry the client will provide, who can access it, and how quickly the red team will receive feedback. For a blind exercise, keep those details within the authorized control group. For a collaborative exercise, compare expected events with what the monitoring team actually observed.

## Establish a baseline before the test

Capture local sensor and event channel status first. The example below is a read only health snapshot. It does not change Defender configuration or clear event logs.

```powershell
Get-MpComputerStatus |
  Select-Object AMServiceEnabled, AntivirusEnabled,
    RealTimeProtectionEnabled, BehaviorMonitorEnabled,
    AntivirusSignatureLastUpdated

Get-WinEvent -ListLog '*Defender*' |
  Select-Object LogName, IsEnabled, RecordCount
```

Synthetic output:

```text
AMServiceEnabled              : True
AntivirusEnabled              : True
RealTimeProtectionEnabled     : True
BehaviorMonitorEnabled        : True
AntivirusSignatureLastUpdated : 9/25/2026 8:04:00 AM

LogName                                                   IsEnabled RecordCount
-------                                                   --------- -----------
Microsoft-Windows-Windows Defender/Operational                 True        4128
```

The collector’s local view is only one source. Confirm central ingestion, retention, and alert routing with the monitoring team. A healthy local service does not prove that events are reaching the security platform.

## Design a useful test

Select a small number of actions tied to the agreed objective. For each one, write down the expected process, identity, target, network path, and likely changes. Use a unique test marker where possible. Preserve timestamps and synchronize clocks so the endpoint, identity, network, and operator records can be compared.

Do not disable security agents, tamper with event collection, or modify kernel callbacks to manufacture a blind spot. If a test requires changing an endpoint control, treat it as a separate high impact scenario with written approval, a maintenance window, and a recovery plan.

## Interpret results carefully

An alert can be technically correct and still be operationally ineffective if it is not triaged. A lack of alert may reflect policy coverage, missing sensor data, a detection rule gap, or a collection delay. Review the event source, analytic, alert disposition, escalation path, and response time before drawing conclusions.

For each approved action, maintain a small event worksheet:

| Field | Example |
| --- | --- |
| Action ID | `TEST-014` |
| Timestamp | `2026-09-25 10:42:16 UTC` |
| Source identity | `NORTHWIND\analyst01` |
| Source and target | `WS-014` to `APP-SRV-02` |
| Expected telemetry | Process event, authentication event, network record |
| Defender observation | Event or alert identifier supplied by the client |
| Outcome | Detected, blocked, delayed, or not observed |

Use a harmless unique marker in approved test activity so analysts can locate the event without searching for sensitive content. Record both the red team activity log and the defender’s source event. If clocks differ, retain the original timestamps and document the offset rather than silently changing them.

## Improve coverage

Correlate process, identity, network, and directory events. Maintain a baseline for administrative tools and service behavior. Validate that high value hosts send telemetry to a monitored destination, and test that alerts reach an on call analyst. Include the exact data source and timestamp in the finding so a defender can reproduce the analysis.

## Further reading

- [Microsoft Learn: Advanced credential protection](https://learn.microsoft.com/en-us/windows/security/book/identity-protection-advanced-credential-protection)
- [Microsoft Learn: Audit Directory Service Access event 4662](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662)
