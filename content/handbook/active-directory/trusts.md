---
title: "Assessing Active Directory Trust Boundaries"
date: 2026-09-25
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

## Enumerate trust metadata

Run a bounded query against the approved domain controller. Trust direction describes which side accepts authentication from the other; it does not grant access to a resource by itself.

```powershell
$Server = 'NW-AD-01.northwind.example'
$Base = 'DC=northwind,DC=example'

Get-ADTrust -Filter * -Server $Server |
  Select-Object Name, Source, Target, Direction, TrustType,
    TrustAttributes, SelectiveAuthentication, SIDFilteringForestAware,
    SIDFilteringQuarantined |
  Sort-Object Target
```

Synthetic output:

```text
Name                 Source              Target             Direction TrustType SelectiveAuthentication
----                 ------              ------             --------- --------- -----------------------
eu.northwind.example northwind.example   eu.northwind.example Bidirectional Uplevel False
partner.example      northwind.example   partner.example     Inbound    Uplevel  True
```

Property availability can vary with the trust type and Active Directory module version. Inspect the returned object with `Get-Member` if a field is absent. Do not convert a blank value into an assumption about trust behavior.

To identify foreign security principal objects, query their directory container and retain the SID for resolution by the domain owner:

```powershell
Get-ADObject -Server $Server -SearchBase $Base `
  -LDAPFilter '(objectClass=foreignSecurityPrincipal)' `
  -Properties objectSid |
  Select-Object Name, objectSid, DistinguishedName
```

Then inspect only groups relevant to the agreed objective. For example, recursively list the membership of one named administrative group and compare the results with the foreign SID objects. Do not attempt to authenticate to the other domain as part of inventory.

```powershell
Get-ADGroupMember -Server $Server -Identity 'Server Administration' -Recursive |
  Select-Object Name, SamAccountName, ObjectClass, SID |
  Sort-Object ObjectClass, SamAccountName
```

## Validate a cross domain route safely

Select a test identity and a benign resource whose owner has approved the test. First establish the identity and domain boundary, then perform only the agreed read check. A failed check may reflect selective authentication, resource permissions, DNS, or connectivity; it does not establish that the trust is broken.

```powershell
whoami /user
nltest /domain_trusts /all_trusts
```

The second command reports trust discovery from the current Windows context. It is a diagnostic view, not a complete security analysis. Reconcile it with the directory trust objects and the owner’s architecture documentation.

## Further reading

- [Microsoft Learn: Get-ADTrust](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adtrust)
- [Microsoft Learn: Best practices for securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
- [Microsoft Learn: Service administrator scope of authority](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/service-administrator-scope-of-authority)
