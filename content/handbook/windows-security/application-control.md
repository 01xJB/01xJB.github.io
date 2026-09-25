---
title: "Assessing Windows Application Control"
date: 2026-09-25
weight: 1
type: docs
tags:
  - Windows
  - App Control
  - Policy Assessment
---

Application control is meant to define which software may run and under what conditions. Windows environments may use App Control for Business, AppLocker, or a combination of controls. A useful assessment asks whether the intended policy is active, correctly scoped, and enforced on the systems that matter.

## Establish the effective policy

Collect the policy source, enforcement mode, signing rules, update history, and the systems to which the policy applies. Review Group Policy links, security filtering, and any WMI filters that affect scope. A policy that exists in a management console is not necessarily applied to every endpoint.

Compare the policy against the organization’s approved software inventory. Pay particular attention to broad path rules, writable locations, publisher rules, script handling, and exceptions for built in tools. These settings can create unintended execution paths when combined with weak file permissions or overly broad trust rules.

## Read the effective local policy

Start with a read only capture on one approved representative endpoint. AppLocker and App Control for Business are separate technologies, so identify which policy is in use before interpreting the result.

```powershell
$EvidencePath = 'C:\Assessment\Evidence'
New-Item -ItemType Directory -Path $EvidencePath -Force | Out-Null

$PolicyXml = Get-AppLockerPolicy -Effective -Xml
$PolicyXml | Out-File (Join-Path $EvidencePath 'effective-applocker.xml') -Encoding utf8
$Policy = Get-AppLockerPolicy -Effective

$Policy.RuleCollections |
  Select-Object RuleCollectionType, EnforcementMode,
    @{Name='RuleCount'; Expression={$_.Rules.Count}} |
  Format-Table -AutoSize
```

Example output:

```text
RuleCollectionType EnforcementMode RuleCount
------------------ --------------- ---------
Exe                Enabled                 18
WindowsInstaller   AuditOnly                7
Script             Enabled                 11
Dll                NotConfigured            0
```

These values are illustrative. Preserve the effective policy and compare it with the centrally managed policy. Local rules can affect behavior, and an effective policy may differ from the written baseline.

Check relevant event channels and the Application Identity service state without changing either:

```powershell
Get-Service AppIDSvc | Select-Object Name, Status, StartType
Get-WinEvent -ListLog '*AppLocker*' |
  Select-Object LogName, IsEnabled, RecordCount
```

## Test safely

Use a harmless, uniquely identifiable test program that the client has approved. Test both an allowed and a denied case on a representative endpoint. Capture the policy result and the associated event records, then remove the test artifact. Never introduce an unreviewed executable or use an evasion payload to validate a policy.

When a policy appears to permit a risky application, document the exact policy rule, the user context, the machine group, and the observed result. Do not infer that a bypass exists from a broad rule alone. Confirm that the file is writable by the relevant principal and that the rule applies to the target system.

If the client provides a harmless test file, evaluate the effective AppLocker policy against it before any launch test. This predicts how the policy evaluates the file; it is not a substitute for an approved live test or event review.

```powershell
$TestFile = 'C:\Assessment\Markers\approved-marker.exe'
Test-Path $TestFile
Test-AppLockerPolicy -XmlPolicy (Join-Path $EvidencePath 'effective-applocker.xml') `
  -Path $TestFile `
  -User 'NORTHWIND\analyst01'
```

Synthetic result:

```text
FilePath                                      PolicyDecision MatchingRule
--------                                      -------------- ------------
C:\Assessment\Markers\approved-marker.exe  Allowed        Publisher rule 4
```

Run an actual allowed and denied case only on the representative endpoint, with the system owner present or available and an agreed rollback plan. Capture the exact user context and event time. Never replace a file or use a payload designed to bypass the policy.

## Improve policy quality

Prefer narrowly defined signer and managed installer rules over broad writable path allowances. Separate audit and enforcement rollout, review exceptions on a schedule, and ensure policy changes receive approval. Keep a tested recovery procedure for policies that could prevent essential applications or system recovery tools from running.

## Further reading

- [Microsoft Learn: App Control for Business](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/)
- [Microsoft Learn: AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/)
- [Microsoft Learn: Test-AppLockerPolicy](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/test-an-applocker-policy-by-using-test-applockerpolicy)
