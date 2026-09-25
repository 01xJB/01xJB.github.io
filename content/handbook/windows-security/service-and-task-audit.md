---
title: "Auditing Windows Services, Scheduled Tasks, and Startup Entries"
date: 2026-09-25
weight: 6
type: docs
tags:
  - Windows
  - Persistence Review
  - Endpoint Security
---

Services, scheduled tasks, and startup entries are normal administration mechanisms. They are also important places to review when investigating unexpected execution or verifying endpoint hardening. This guide inventories metadata and ownership; it does not create or alter an autorun entry.

## 1. Establish the review context

Record the endpoint name, operating system, time window, and approved account. Capture command output to the evidence store with access controls. Review only the named endpoint or device group.

## 2. Inventory services with unusual execution paths

```powershell
Get-CimInstance Win32_Service |
  Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
  Sort-Object StartName, Name
```

Filter for services that run as highly privileged built-in identities, have an unexpected binary path, or lack a clear owner. Do not label a service malicious from its name or account alone. Verify file signature, file ACL, package owner, installation record, and expected start behavior.

```powershell
$Service = Get-CimInstance Win32_Service -Filter "Name='ExampleAgent'"
$Service | Select-Object Name, State, StartName, PathName

$BinaryPath = ($Service.PathName -replace '^"?([^\"]+\.exe).*$', '$1')
if (Test-Path -LiteralPath $BinaryPath) {
  Get-AuthenticodeSignature -FilePath $BinaryPath |
    Select-Object Status, StatusMessage, SignerCertificate
  Get-FileHash -LiteralPath $BinaryPath -Algorithm SHA256
}
```

The illustrative service name is a placeholder. Validate the parsed path when the command line contains arguments or an unquoted path with spaces; do not rely on a simplistic parse to make a security decision.

## 3. Inventory scheduled tasks

```powershell
Get-ScheduledTask |
  ForEach-Object {
    $Task = $_
    [pscustomobject]@{
      TaskPath = $Task.TaskPath
      TaskName = $Task.TaskName
      State = $Task.State
      Principal = $Task.Principal.UserId
      RunLevel = $Task.Principal.RunLevel
      Actions = ($Task.Actions | ForEach-Object {
        '{0} {1}' -f $_.Execute, $_.Arguments
      }) -join ' ; '
    }
  } |
  Sort-Object Principal, TaskPath, TaskName
```

Check whether the task is expected, who can change the task definition and its executable, whether its principal needs the reported run level, and whether the trigger is still required. Task names can be misleading; inspect the action, principal, trigger, and file permissions together.

## 4. Review common startup locations

Use a read-only registry query for the current machine and current user. Expand the review to managed profiles only when approved:

```powershell
$RunKeys = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
)

foreach ($Key in $RunKeys) {
  if (Test-Path $Key) {
    Get-ItemProperty -Path $Key |
      Select-Object PSPath, * -ExcludeProperty PS* 
  }
}
```

Treat values as potentially sensitive because command lines can contain paths or arguments. Redact secrets and user data before reporting. Compare entries with the endpoint build baseline and software inventory.

## 5. Validate and remediate with the owner

For a suspected unauthorized entry, preserve the original metadata, binary hash, signature result, ACL, owner, and relevant creation/change events. Have the endpoint owner classify it before removal. Disable or delete an entry only under incident-response or change-control authority, with a recovery plan and a way to validate business services afterward.

## Further reading

- [Microsoft Learn: Win32_Service class](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service)
- [Microsoft Learn: ScheduledTasks PowerShell module](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/)
- [MITRE ATT&CK: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)
