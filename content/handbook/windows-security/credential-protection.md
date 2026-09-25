---
title: "Credential Protection and Windows Identity Boundaries"
date: 2026-09-25
weight: 2
type: docs
tags:
  - Windows
  - Credential Security
  - Identity
---

Credential exposure is rarely a single event. It is the result of identity design, endpoint configuration, interactive logons, service use, and access to sensitive operating system components. A red team assessment should identify where those controls fail without collecting more material than needed to prove the risk.

## Map credential handling

Identify privileged accounts, service identities, administrative workstations, remote administration paths, and systems that hold sensitive authentication material. Determine which protections are enabled, including Credential Guard where supported, and whether the organization has separated everyday user activity from privileged administration.

Review where credentials may be exposed through saved secrets, service configuration, scripts, browser profiles, logon sessions, or excessive local administrator access. Use approved configuration and access reviews first. A theoretical location is not evidence that a credential is present or usable.

## Keep validation proportionate

Credential dumping, ticket extraction, pass the hash, ticket reuse, and directory replication abuse are high impact actions. They can expose reusable secrets and affect accounts or domains outside the immediate test. Require explicit written authorization, a named test identity, controlled storage, a defined retention period, and a cleanup plan before attempting any of them.

In many engagements, a safer proof is available. Demonstrate that a test account can read an improperly protected configuration file, or show that an unintended principal has a sensitive replication right, without extracting password material. Stop when the agreed proof point is reached.

## Defensive review

Limit privileged logons to managed administrative workstations. Use unique local administrator credentials, managed service identities, and tiered administration. Restrict rights that allow directory replication to domain controllers and the small set of approved principals that require them. Review unusual access to credential stores and replication interfaces in context with source system and account behavior.

Credential Guard and similar protections reduce some forms of credential exposure, but they do not replace least privilege, endpoint monitoring, or careful control of privileged sessions. Record which control prevented or detected the test and where visibility was missing.

## Verify Credential Guard state

Use the documented Windows Device Guard provider to distinguish whether virtualization based security is configured from whether its services are running. Run this on one approved endpoint and record its operating system build because available properties vary by release.

```powershell
$DeviceGuard = Get-CimInstance `
  -ClassName Win32_DeviceGuard `
  -Namespace root\Microsoft\Windows\DeviceGuard

$DeviceGuard | Select-Object VirtualizationBasedSecurityStatus,
  SecurityServicesConfigured, SecurityServicesRunning
```

Example output:

```text
VirtualizationBasedSecurityStatus SecurityServicesConfigured SecurityServicesRunning
--------------------------------- -------------------------- -----------------------
2                                 {1, 2}                     {1, 2}
```

Interpret the documented numeric values for the Windows version in scope. A running service value is useful evidence, but it does not establish that every credential exposure path is protected. Correlate with the device’s policy, hardware prerequisites, privileged logon practices, and endpoint telemetry.

Capture the test identity and host context without collecting secrets:

```powershell
whoami
whoami /groups
Get-ComputerInfo | Select-Object CsName, WindowsProductName, WindowsVersion, OsBuildNumber
```

Do not run credential extraction commands as a validation shortcut. If a client requires an invasive test, define the identity, evidence limits, storage controls, recovery plan, and named approval separately before the engagement.

## Further reading

- [Microsoft Learn: Credential Guard overview](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [Microsoft Learn: How Credential Guard works and its protection limits](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/how-it-works)
