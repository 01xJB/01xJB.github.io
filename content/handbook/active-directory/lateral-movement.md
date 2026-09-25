---
title: "Assessing Lateral Movement Paths"
date: 2026-09-25
weight: 5
type: docs
tags:
  - Active Directory
  - Lateral Movement
  - Network Segmentation
---

Lateral movement is the use of one system or identity to reach another system. In an Active Directory assessment, the important question is not how many hosts can be contacted. It is whether a user or service can move from an ordinary endpoint to a system that matters to the agreed objective.

## Map the path

For each proposed path, identify the current identity, the source host, the destination, the protocol, and the permission that allows access. Common administrative paths include remote management, file sharing, scheduled administration, Windows Management Instrumentation, and database services. Each path leaves a different combination of authentication, process, service, and network evidence.

Use directory data, endpoint configuration, firewall policy, and interviews with system owners to understand expected relationships. A network connection alone does not prove that the identity has administrative control. Confirm the actual authorization boundary on the destination.

## Include pivots in the scope

A pivot or proxy changes which system originates a connection and how the traffic is routed. Document the approved source, destination ranges, permitted protocols, and traffic limits before testing. Avoid broad port scans through an internal host. A narrow connection check against a named test system is easier to attribute and less likely to affect unrelated services.

## Validate without overreach

Use a test account and a benign action, such as reading a designated test share or querying a service banner that the client approved. Do not create remote services, tasks, accounts, or persistence to demonstrate a path unless that exact behavior is in scope. Stop when the objective has been proven.

Record the source address seen by the destination, the account used, the protocol, and the corresponding endpoint and network events. This helps defenders distinguish expected administration from unusual access and confirms whether segmentation controls behaved as intended.

## Reduce unnecessary reach

Use separate administrator accounts for separate tiers. Limit remote administration to managed jump hosts. Restrict workstation to server and server to domain controller pathways according to business need. Review local administrator membership and firewall rules together, since either one alone may give an incomplete picture of effective access.

## Work from a single named source and destination

Build a small matrix before testing. Record the source host, test identity, destination, expected protocol, business reason, approved time, and stop condition. Select one representative system rather than sweeping an entire subnet.

| Source | Destination | Port or service | Question |
| --- | --- | --- | --- |
| Managed test workstation | Approved application server | WinRM TCP 5985 or 5986 | Is the management service reachable from this network zone? |
| Managed test workstation | Approved file server | SMB TCP 445 | Is the approved test share reachable? |
| Managed test workstation | Approved database server | SQL TCP 1433 or documented port | Does the expected application route exist? |

Use a narrowly targeted connection check only when permitted. This does not authenticate an account or prove authorization to administer the destination.

```powershell
$Target = 'app-srv-02.northwind.example'
Test-NetConnection -ComputerName $Target -Port 5985 -InformationLevel Detailed
```

Example output:

```text
ComputerName     : app-srv-02.northwind.example
RemoteAddress    : 192.0.2.24
RemotePort       : 5985
InterfaceAlias   : Ethernet
SourceAddress    : 192.0.2.80
TcpTestSucceeded : True
```

The example address range is reserved for documentation. A successful TCP connection means only that a listener answered. It does not show that WinRM authentication succeeds or that the identity can run commands.

## Validate authorization without remote execution

Review the effective local group membership through approved inventory, Group Policy, or a client provided endpoint management report. If the engagement explicitly authorizes a live access check, use a designated test share or benign resource and stop after confirming the expected permission. Do not create a remote service, scheduled task, account, or process as a shortcut to prove control.

Capture both sides of the test where possible: the source identity and route, the destination log entry, the exact resource permission, and the time. Compare the observation with firewall policy and system owner expectations. This distinguishes reachability, authentication, and authorization, which are three separate questions.
