---
title: "Kerberos Tickets for Lateral Movement Services"
date: 2026-09-25
weight: 7
type: docs
tags:
  - Kerberos
  - Lateral Movement
  - Service Principal Names
---

Remote administration and application protocols use different service classes. This reference maps common Windows services to the SPN classes defenders and assessors are likely to encounter. An SPN identifies a service; it does not grant permission to use it.

| Service or protocol | Common SPN service class | What to verify |
| --- | --- | --- |
| SMB file service | `cifs` | Share and file ACLs; local and domain identity used by the server. |
| Remote Service Control Manager / PsExec-style tools | `cifs` plus service-control interfaces | Whether remote service control is enabled, who can create services, and whether service-install auditing is collected. |
| WinRM / PowerShell remoting | Often `HTTP` or `WSMAN` | Listener configuration, SPN registration, endpoint ACLs, and remoting policy. |
| WMI / DCOM | `HOST`, `RPCSS`, or `RestrictedKrbHost` depending on the path | DCOM and WMI namespace permissions, firewall policy, and process-creation auditing. |
| Remote Desktop | `TERMSRV` and related host SPNs | RDP policy, allowed-logon groups, NLA, and session logging. |
| Microsoft SQL Server | `MSSQLSvc` | Exact instance/port SPN, SQL login mapping, database roles, and linked-server configuration. |

## 1. Resolve one service name

Use the exact SPN from approved inventory and identify its owner:

```cmd
setspn.exe -Q MSSQLSvc/db-srv-04.northwind.example:1433
```

Example output:

```text
Checking domain DC=northwind,DC=example
CN=SQL Reporting,OU=Service Accounts,DC=northwind,DC=example
        MSSQLSvc/db-srv-04.northwind.example:1433
Existing SPN found!
```

Compare the SPN owner with the SQL service configuration and the application's owner. An SPN registered to the wrong account can cause authentication failures or security ambiguity.

## 2. Review access without remote execution

For one approved source identity and destination, separate reachability, authentication, and authorization. Use a named benign marker or owner-provided health check. Do not use a remote shell, service creation, scheduled task, WMI process launch, or administrative share as a generic proof step.

For SQL Server, inventory the SPN and server/database role assignments with the database owner. Validate using a designated test database and non-sensitive query. For SMB, verify only an owner-provided read-only marker. Record the source, identity, target, service, result, and corresponding audit event.

## 3. Give defenders a useful event trail

Correlate domain-controller Event 4769 with endpoint and service logs. For remote administration pathways, review the relevant WinRM, WMI, SMB, service-control, RDP, or SQL logs as well. Compare source host, user, requested SPN, target, and time against the approved test record.

## Further reading

- [Microsoft Learn: Kerberos authentication overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- [Microsoft Learn: setspn command reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/setspn)
- [Microsoft Learn: PowerShell remoting security](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ps-remoting-second-hop)
