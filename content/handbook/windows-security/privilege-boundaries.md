---
title: "Windows Privilege Boundary Assessment"
date: 2026-09-25
weight: 3
type: docs
tags:
  - Windows
  - Privilege Escalation
  - Configuration Review
---

Local privilege findings often come from ordinary configuration mistakes rather than a software vulnerability. Weak service permissions, writable application directories, excessive user rights, and overbroad administrative groups can connect a standard account to a more privileged context.

## Work from the current identity

Record the user, group memberships, integrity level, host role, and approved test scope. Review services, scheduled tasks, installed software, local groups, and policy settings. For each candidate issue, identify the exact permission that allows the change and the account that can exercise it.

| Area | Evidence to collect |
| --- | --- |
| Service configuration | Service identity, executable path, configuration permissions, and restart behavior. |
| File system | Owner and access control entries on application and service directories. |
| Registry | Permissions on keys that control service or application execution. |
| User rights | Assigned privileges and the business reason for granting them. |
| Scheduled tasks | Principal, trigger, executable, and write access to referenced files. |
| Database services | Service account, linked system relationships, and effective database role. |

Begin with a host and identity baseline. These commands are local inventory and do not change permissions.

```powershell
whoami /all

Get-LocalGroupMember -Group 'Administrators' |
  Select-Object Name, ObjectClass, PrincipalSource

Get-CimInstance Win32_Service |
  Where-Object StartName -Match 'LocalSystem|LocalService|NetworkService' |
  Select-Object Name, StartName, State, StartMode, PathName |
  Sort-Object Name
```

Example output:

```text
Name                    ObjectClass PrincipalSource
----                    ----------- ---------------
NORTHWIND\IT Support   Group       ActiveDirectory
BUILTIN\Administrator User        Local

Name             StartName             State   StartMode PathName
----             ---------             -----   --------- --------
InventoryAgent   LocalSystem                Running Auto C:\Program Files\Northwind\agent.exe
Spooler          NT AUTHORITY\LocalService  Running Auto C:\Windows\System32\spoolsv.exe
```

Treat service names and paths as leads. To assess a specific path, inspect the file and directory access control lists and compare them with the identity that can modify them. Do not change the ACL or replace a service binary during a routine review.

```powershell
icacls 'C:\Program Files\Northwind\agent.exe'
icacls 'C:\Program Files\Northwind'
```

Example output:

```text
C:\Program Files\Northwind\agent.exe NORTHWIND\IT Support:(RX)
                                      BUILTIN\Administrators:(F)
                                      NT AUTHORITY\SYSTEM:(F)
Successfully processed 1 files; Failed processing 0 files
```

Save the output for the selected service and identify the exact principal and permission that matter. Broad recursive scans of a production disk are noisy and rarely necessary to validate one candidate.

## Prove impact without changing production

First validate the permissions and configuration offline or through read only inspection. If execution is necessary, use a client approved test binary with no destructive behavior on a designated test system. Do not replace a production service executable, create a privileged task, alter a registry autorun location, or change a database setting without explicit approval and a rollback plan.

For SQL Server, distinguish database permissions from operating system rights. A database role or linked server relationship does not by itself prove code execution on the host. Map the chain and stop at the approved proof point.

## Remediation

Give service identities only the rights they need. Protect service binaries and configuration from modification by ordinary users. Remove unnecessary local administrator memberships, review privileged user rights, and avoid shared credentials across hosts. For scheduled tasks and database services, document owners and periodically validate that the configured principal still matches the business requirement.

## Further reading

- [Microsoft Learn: Implementing least privilege administrative models](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models)
