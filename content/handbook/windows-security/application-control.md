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

Example output:

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

## AppLocker audit from policy to event

Use this sequence on one approved endpoint first. AppLocker policy cmdlets report Group Policy policy; environments that deliver application control through another management channel require the corresponding management view as well. Record the host, user, policy collection, and collection enforcement mode before interpreting a test result.

### 1. Capture the effective policy

```powershell
$EvidencePath = 'C:\Assessment\Evidence'
$PolicyFile = Join-Path $EvidencePath 'effective-applocker.xml'
New-Item -Path $EvidencePath -ItemType Directory -Force | Out-Null

Get-AppLockerPolicy -Effective -Xml |
  Set-Content -LiteralPath $PolicyFile -Encoding utf8

[xml]$PolicyXml = Get-Content -LiteralPath $PolicyFile -Raw
$PolicyXml.AppLockerPolicy.RuleCollection |
  Select-Object Type, EnforcementMode,
    @{Name='Rules'; Expression={ @($_.FilePathRule + $_.FilePublisherRule + $_.FileHashRule).Count }}
```

Example output:

```text
Type       EnforcementMode Rules
----       --------------- -----
Exe        Enabled            18
Msi        AuditOnly            4
Script     Enabled             9
Dll        NotConfigured        0
```

Read the XML rules and their exceptions. For each broad path rule, confirm both the path ACL and which identities can write files there. A rule granting execution from a location does not establish exploitability unless the assessed principal can write a file that the policy will trust.

### 2. Evaluate approved files without launching them

Use a known benign vendor application and an explicitly approved test identity. `Test-AppLockerPolicy` predicts the policy decision for the supplied file; it does not execute it.

```powershell
$Candidates = Get-ChildItem 'C:\Program Files\Northwind Tools' -Filter '*.exe' -File -Recurse
$Candidates.FullName |
  Test-AppLockerPolicy -XmlPolicy $PolicyFile -User 'NORTHWIND\analyst01' |
  Select-Object FilePath, PolicyDecision, MatchingRule
```

Example output:

```text
FilePath                                             PolicyDecision MatchingRule
--------                                             -------------- ------------
C:\Program Files\Northwind Tools\viewer.exe        Allowed        Publisher rule 4
C:\Program Files\Northwind Tools\helper.exe        Denied         No matching allow rule
```

Record the AppLocker collection, matching rule, signer or hash, and user context. If the command returns no records, verify that the XML file contains rules, that the path exists, and that the selected policy is the policy applied to the endpoint.

### 3. Correlate policy decisions with Windows events

AppLocker events are stored in separate channels for executables and DLLs, scripts and Windows Installer, and packaged apps. Start with the first two channels and inspect the event message, not just its ID:

```powershell
$Since = (Get-Date).AddDays(-2)
$Channels = @(
  'Microsoft-Windows-AppLocker/EXE and DLL',
  'Microsoft-Windows-AppLocker/MSI and Script'
)

foreach ($Channel in $Channels) {
  Get-WinEvent -FilterHashtable @{
    LogName   = $Channel
    StartTime = $Since
    Id        = 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007
  } -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, MachineName, Message
}
```

Common event meanings include policy application failure (8000), successful application (8001), allowed execution (8002/8005), audit-only would-block (8003/8006), and enforced block (8004/8007). Confirm channel and message text because the event set varies by collection. An empty query can mean no matching activity, a disabled channel, a collection mismatch, or an expired log window.

### 4. Report the control outcome

For each test case, retain the exported policy hash, machine and user context, file signer and hash, `Test-AppLockerPolicy` result, and correlated event. A policy in `AuditOnly` mode records would-block events but does not enforce the block. Report that distinction plainly. Run any live allow/deny test only with an owner-approved benign file and rollback plan.

### 5. Correct the policy in a controlled change

Remove unused rules, narrow writeable path exceptions, and prefer publisher rules tied to trusted publishers and product metadata when that fits the application. Stage changes in audit mode, review would-block events with the application owner, then enforce through normal change control. Keep a recovery plan for essential administration tools and validate policy application on a representative endpoint after the change.

Microsoft's [AppLocker event reference](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker) describes channel-specific events and their meanings. Microsoft's [Test-AppLockerPolicy instructions](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/test-an-applocker-policy-by-using-test-applockerpolicy) cover offline policy evaluation.
