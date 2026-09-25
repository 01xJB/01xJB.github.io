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

## Build a host telemetry baseline

Before evaluating an alert or an approved simulation, establish what the endpoint is configured to record. The following inventory uses built-in Windows facilities and reads configuration only. Run it on the named representative endpoint; do not collect process memory, credential material, or unrelated user data.

### 1. Record endpoint identity and protection state

```powershell
$Computer = Get-CimInstance Win32_ComputerSystem
$OS = Get-CimInstance Win32_OperatingSystem
$Defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
$DeviceGuard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
  -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue

[pscustomobject]@{
  Hostname = $Computer.Name
  Domain = $Computer.Domain
  OperatingSystem = $OS.Caption
  Build = $OS.BuildNumber
  DefenderRealtime = $Defender.RealTimeProtectionEnabled
  VBSStatus = $DeviceGuard.VirtualizationBasedSecurityStatus
  SecurityServicesConfigured = ($DeviceGuard.SecurityServicesConfigured -join ',')
  SecurityServicesRunning = ($DeviceGuard.SecurityServicesRunning -join ',')
}
```

Illustrative result:

```text
Hostname                    : WS-014
Domain                      : northwind.example
OperatingSystem             : Microsoft Windows 11 Enterprise
Build                       : 26100
DefenderRealtime            : True
VBSStatus                   : 2
SecurityServicesConfigured  : 1,2
SecurityServicesRunning     : 1
```

These values are configuration evidence, not a verdict. Map numeric Device Guard values against Microsoft's current documentation and the endpoint's intended baseline. A capability can be configured but not running because of hardware, policy, or startup constraints.

### 2. Check event sources and retention

```powershell
$Patterns = @('*PowerShell*', '*AppLocker*', '*CodeIntegrity*', '*Windows Defender*')

foreach ($Pattern in $Patterns) {
  Get-WinEvent -ListLog $Pattern -ErrorAction SilentlyContinue |
    Select-Object LogName, IsEnabled, RecordCount, MaximumSizeInBytes,
      LastWriteTime
}
```

Do not assume that collection is enabled because a channel exists. Confirm audit policy, channel state, forwarding status, retention, and access controls with the logging team. Export only the agreed time range and channels.

### 3. Review a bounded time range

For a controlled validation window, filter on a small period and a known test endpoint. Security Event 4688 records process creation when the relevant audit subcategory is configured. PowerShell Operational Event 4104 can record script block content when the associated logging policy is enabled. Availability, detail, and retention depend on host policy.

```powershell
$Start = Get-Date '2026-09-25 13:00:00'
$End = Get-Date '2026-09-25 13:30:00'

Get-WinEvent -FilterHashtable @{
  LogName = 'Security'
  Id = 4688
  StartTime = $Start
  EndTime = $End
} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, MachineName, Message

Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-PowerShell/Operational'
  Id = 4104
  StartTime = $Start
  EndTime = $End
} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, MachineName, Message
```

Review event data under the client's handling policy. Command lines and script blocks can contain tokens, paths, or personal data. Redact sensitive values before attaching results to a report, and never publish raw event records from a client environment.

### 4. Compare expected and observed signals

For each approved benign simulation, record its time, endpoint, initiating test account, expected telemetry source, observed event identifiers, and forwarding delay. If an event is absent, check whether audit policy was active, the channel was enabled, the log rolled over, and the collector received it. Do not conclude that a control was bypassed from one missing event.

### 5. Map telemetry gaps to owners

Prioritize process creation, authentication, application control, endpoint protection, and identity changes according to the organization's threat model. Assign each missing signal to the team that owns its generation or forwarding. Validate tuning with an approved benign test before changing production audit policy.

For platform semantics, review Microsoft's [Windows audit policy guidance](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-policy-recommendations), [App Control event explanations](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations), and [Device Guard WMI class reference](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity).

## Map endpoint assessment topics to defensive evidence

Several techniques studied in adversary emulation are most usefully assessed by verifying whether the corresponding control and signal exist, whether they reach the monitoring team, and whether an approved benign test is recognized. This matrix describes review targets without providing code or instructions for bypassing those controls.

| Area | Evidence to review | Safe validation question |
| --- | --- | --- |
| Application or image load | App Control policy, signer and hash records, Code Integrity channel | Does the approved test binary produce the expected allow, audit, or block result? |
| Script execution | PowerShell Operational channel, script-block logging policy, endpoint alert records | Does the approved marker create the expected event and alert? |
| Runtime monitoring | EDR sensor health, alert pipeline status, documented policy mode | Does an owner-approved benign simulation appear in the endpoint and central console? |
| Service and task changes | System/service audit, Security log, scheduled task inventory | Are approved changes attributable to an identity and correlated to the change record? |
| User context | Security logon events, group membership, token privileges reported by the owner | Can the assessor distinguish the test identity from the service or administrator context? |
| Credential protections | Credential Guard/VBS configuration, LSA policy, Defender health | Are the documented protections running on the systems where privileged logons occur? |
| Network activity | Firewall, DNS, VPN, proxy, and endpoint network telemetry | Can the SOC identify the source, destination, protocol, time, and responsible test identity? |

If the control is present but its data source is missing centrally, record a visibility gap with the source owner and collector owner. If the benign action is blocked but no alert reaches an analyst, report prevention and response separately. Do not intentionally disable the sensor, alter kernel monitoring, or manipulate process memory to create a blind spot.
