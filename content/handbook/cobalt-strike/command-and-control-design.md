---
title: "Command and Control Design for Authorized Assessments"
date: 2026-09-25
weight: 2
type: docs
tags:
  - Cobalt Strike
  - Infrastructure
  - Network Security
---

Command and control infrastructure is part of the assessment surface. Its design affects availability, attribution, data protection, and the quality of the defensive exercise. A professional setup makes ownership clear to the red team and keeps the impact of a detection or infrastructure mistake bounded.

## Plan for failure and containment

Before deployment, document the approved domains, addresses, hosting providers, ports, protocols, redirectors, and expected traffic volume. Assign an owner to every component and establish a contact path for the client’s network team. Confirm how infrastructure will be disabled if it is detected, misconfigured, or reported by a third party.

Redirectors can separate an externally reachable endpoint from a team server. This is an architectural boundary, not a substitute for access control or monitoring. Document what they forward, where logs are stored, and how they are removed after the engagement.

## Protect the control plane

Restrict administrative access to the team server, use unique operator accounts, protect credentials, and keep management access separate from listener traffic. Encrypt administrative connections and client data in transit and at rest. Limit where collected files can be stored, and establish a retention period before collection begins.

## Coordinate with defenders

The right design depends on the exercise objective. A detection exercise may intentionally expose known indicators to measure alerting and response. A threat emulation may require a bounded set of observed behaviors. Agree on which defenders are informed, which indicators may be shared, how safety stops work, and whether infrastructure takedown is part of the scenario.

Avoid designing infrastructure around hiding from unrelated providers, bypassing client controls, or preserving access after the engagement. Resilience should protect the test from accidental single points of failure while preserving the client’s ability to stop the operation.

## Report the infrastructure

Include an inventory of domains, addresses, certificates, hosting services, and external dependencies. Record the dates of use, the client systems contacted, and the removal status for each resource. This gives the client a clear path to distinguish test infrastructure from legitimate services and to block or retire it after the assessment.

## Validate owned infrastructure before use

Perform simple DNS and transport checks from an approved administration host. These commands confirm resolution and reachability only. They do not validate a listener configuration or authorize traffic to third party systems.

```powershell
Resolve-DnsName 'c2-test.northwind.example' -Type A
Test-NetConnection -ComputerName 'c2-test.northwind.example' -Port 443
```

Illustrative output:

```text
Name                       Type TTL Section IPAddress
----                       ---- --- ------- ---------
c2-test.northwind.example  A    300 Answer  192.0.2.80

ComputerName     : c2-test.northwind.example
RemotePort       : 443
TcpTestSucceeded : True
```

The sample IP is reserved for documentation. Compare the result with the approved infrastructure register. A DNS answer or open port can be stale, misrouted, or owned by another party. If the result does not match the register, stop before sending assessment traffic.

## Maintain an infrastructure ledger

Use one row per resource. Keep provider account identifiers and renewal details in the team’s protected system rather than a public report.

| Resource | Owner | Approved purpose | First and last use | Evidence location | Retirement status |
| --- | --- | --- | --- | --- | --- |
| `c2-test.northwind.example` | Infrastructure lead | Authorized lab callback test | Recorded in operation log | Restricted evidence store | Pending client signoff |
| `192.0.2.80` | Infrastructure lead | Documentation example only | Not used | None | Not applicable |

Review the ledger at kickoff, after any infrastructure change, and during closeout. Record takedown confirmation and any remaining DNS or certificate dependencies.

## Further reading

- [Fortra: Listener management](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructue_listener_mgmnt.htm)
- [Fortra: HTTP and HTTPS Beacon listeners](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructue_beacon-http-https.htm)
