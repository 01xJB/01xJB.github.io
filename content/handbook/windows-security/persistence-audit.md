---
title: "Auditing Windows Persistence Locations"
date: 2026-09-25
weight: 8
type: docs
tags:
  - Windows
  - Persistence Review
  - Incident Response
---

This runbook inventories common Windows autorun locations for a named endpoint. It covers services, scheduled tasks, Run keys, logon scripts, and WMI event subscriptions. The commands are read only; they do not install a service, task, subscription, profile change, or COM registration.

## 1. Set the endpoint and review window

Use endpoint management or an approved local session on the specific host. Record the account, machine, time, and source of the collection. Do not fan this query out to unrelated systems.

## 2. Check scheduled tasks

```cmd
schtasks.exe /query /fo CSV /v
```

Review the task path, author, principal, run level, trigger, action, and last result. Verify the executable signature and file ACL. A vendor-looking task name does not prove that the task is legitimate.

## 3. Check services and their binary paths

```cmd
sc.exe query state= all
sc.exe qc ExampleAgent
```

`sc query` inventories service state; `sc qc` shows the configured start type, service account, and binary path for one named service. Compare these values with the software inventory and change record. Verify whether the service account can modify the binary or its parent directory.

## 4. Check common Run keys and logon scripts

```cmd
reg.exe query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
reg.exe query "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
reg.exe query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

Check user and machine logon script assignments through the approved Group Policy or directory report. Compare the script path, signer, hash, owner, and write ACL with the organization's managed baseline. Do not execute a listed script during inventory.

## 5. Review WMI event subscriptions

WMI permanent event subscriptions are stored in `root\subscription`. Query each class narrowly and retain only metadata needed for the review:

```powershell
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
  Select-Object Name, EventNamespace, Query

Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer |
  Select-Object Name, ExecutablePath, CommandLineTemplate

Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
  Select-Object Filter, Consumer
```

Treat command lines and WMI query strings as sensitive evidence. Compare each filter and consumer with software ownership and approved management tooling. Do not delete a subscription until the system owner confirms its purpose and approves the change.

## 6. Correlate changes with audit events

If auditing is enabled, review the bounded Security log window for service installation and scheduled task creation events, then correlate actor, process, host, and change ticket. Event absence does not prove that no change occurred; check audit policy, log retention, and forwarding.

## 7. Handle a suspicious entry

Preserve the entry's raw configuration, owner, file hash, signature, ACL, and relevant event IDs. Notify the incident owner and follow the containment plan. Disable or remove entries only with incident-response authority or a documented change, and verify the system after the action.

## Further reading

- [Microsoft Learn: ScheduledTasks module](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/)
- [Microsoft Learn: Win32_Service class](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service)
- [MITRE ATT&CK: Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
