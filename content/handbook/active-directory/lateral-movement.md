---
title: "Assessing Lateral Movement Paths"
date: 2026-09-24
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
