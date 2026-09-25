---
title: "Assessing Active Directory Trust Boundaries"
date: 2026-09-24
weight: 4
type: docs
tags:
  - Active Directory
  - Trusts
  - Identity Security
---

Domain and forest trusts connect separate identity namespaces. They allow users in one domain to access resources in another, subject to trust direction, transitivity, filtering, and resource permissions. A trust is not a blanket statement that every identity is trusted everywhere. It is a boundary whose actual effect depends on configuration and authorization at the destination.

## Build a trust map

For each trust, document the trusted and trusting domains, direction, transitivity, scope, and the business purpose. Record where the trust object is stored and which teams own each side. Validate that the observed configuration matches the intended architecture.

| Review area | Questions |
| --- | --- |
| Direction | Which domain accepts identities from the other domain? |
| Transitivity | Can the relationship extend beyond the two directly connected domains? |
| Filtering | Which claims or security identifiers are accepted across the boundary? |
| Selective authentication | Must access be granted on each destination computer? |
| Privileged groups | Are foreign principals or nested groups included in administrative roles? |
| Trust maintenance | Are ownership, monitoring, and credential rotation responsibilities clear? |

## Trace the path to a resource

An effective assessment follows the identity from its source domain to the target resource. Check group membership and nested groups on both sides, the resource’s access control list, and any delegated administration. Trust metadata can show that a path exists, but it cannot prove that a particular user is authorized to use a particular service.

Treat trust account secrets, inter realm keys, privileged tickets, and SID history as highly sensitive material. Their use can have broad consequences across domains. Do not extract or forge them as a routine validation step.

## Safe validation

Use a designated test account and a low impact resource to confirm expected cross domain access. Keep the proof to a benign access check, record the source and destination identities, and avoid changing trust configuration. If validating privilege escalation would require secret material or ticket forgery, report the path as a high impact configuration risk and obtain separate written authorization before further testing.

## Reduce trust exposure

Remove trusts that no longer serve a business need. Prefer the narrowest trust scope that supports the workflow, review foreign principals in privileged groups, and assign an owner on both sides. Monitor trust configuration changes and cross domain authentication from unexpected systems.

## Further reading

- [Microsoft Learn: Best practices for securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
- [Microsoft Learn: Service administrator scope of authority](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/service-administrator-scope-of-authority)
