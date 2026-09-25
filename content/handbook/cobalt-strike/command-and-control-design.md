---
title: "Command and Control Design for Authorized Assessments"
date: 2026-09-24
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

## Further reading

- [Fortra: Listener management](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructue_listener_mgmnt.htm)
- [Fortra: HTTP and HTTPS Beacon listeners](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructue_beacon-http-https.htm)
