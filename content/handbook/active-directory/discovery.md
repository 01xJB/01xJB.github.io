---
title: "Active Directory Discovery and Enumeration"
date: 2026-09-24
weight: 1
type: docs
tags:
  - Active Directory
  - Enumeration
  - Identity Security
---

Active Directory discovery is the work of building a reliable picture of an identity environment before testing a specific security question. The strongest assessments collect only what they need, preserve the context behind each observation, and distinguish a theoretical path from one that is actually reachable.

> [!IMPORTANT]
> Perform discovery only in environments named in the signed authorization. Agree in advance on permitted accounts, domain controllers, query volume, collection methods, evidence handling, and stop conditions.

## Start with the engagement boundary

Record the approved domains, forests, address ranges, test accounts, and excluded systems. Identify the designated domain controllers and confirm how the client wants unexpected access, sensitive records, or production impact handled. If the identity boundary is unclear, pause and ask the engagement lead before querying another domain.

## Build a directory map

Start with the domain naming context and the objects that describe the environment:

| Object family | Questions to answer |
| --- | --- |
| Users and service accounts | Which accounts are enabled, privileged, stale, or configured for service use? |
| Groups | Which groups carry administrative rights, and where are nested memberships? |
| Computers | Which systems are domain joined, and which are high value? |
| Organizational units and policy objects | Which policies apply to which systems, and are filters or permissions narrowing their reach? |
| Trust objects | Which domains are connected, in what direction, and under what constraints? |
| Object permissions | Can an ordinary principal modify an account, group, policy, or computer relationship? |

LDAP filters let an operator request a narrowly defined set of objects. Start with a small query and a short attribute list. Expand collection only when the assessment question requires it. A query that returns every object and every attribute is harder to review, creates unnecessary load, and can obscure the important evidence.

For example, in an approved lab using the Active Directory PowerShell module, a scoped inventory can begin with enabled user accounts and their service principal names:

```powershell
Get-ADUser -Filter 'Enabled -eq $true' -Properties ServicePrincipalName,MemberOf |
  Select-Object SamAccountName,ServicePrincipalName,MemberOf
```

Treat this as an inventory, not proof of exploitability. Confirm which domain controller answered, which identity performed the query, and when the result was collected. Replace lab context with the customer approved collection method for each engagement.

## Follow relationships, not just object names

Group membership is often nested. Direct membership alone can miss effective privilege. Review the membership chain from ordinary users to sensitive groups, and record each relationship that creates the path. Directory data also does not tell the whole story. Group Policy can assign local rights, and policy scope can depend on links, security filtering, inheritance, or a WMI filter.

When an attack graph shows an unexplained edge or an unresolved security identifier, verify the underlying directory object and policy data. Do not treat a visualized path as conclusive until the permissions and policy scope have been checked against the source.

## Keep collection proportionate

Use indexed attributes where practical, request only the fields needed for the current question, and split large inventories into bounded queries. Keep collection separate from credential access. A discovery exercise rarely requires password material, private keys, ticket caches, or the contents of user files.

Record the query method, account context, target domain controller, time, result count, and any errors. This makes it possible to explain the assessment to the client and to distinguish expected test traffic from unrelated activity.

## Turn observations into defensible findings

For every suspected path, document:

1. The starting identity and the permission it holds.
2. The target object and the exact relationship that connects them.
3. The business system or role that could be affected.
4. The minimum safe validation that demonstrates impact.
5. The relevant logs and telemetry the defender could use to detect the activity.

Prefer a reversible proof that confirms access over collecting sensitive data or changing production permissions. If the authorized scope does not permit validation, report the path as an observed risk and describe what remains unproven.

## Defensive priorities

Review privileged group membership, delegation settings, service account ownership, stale objects, Group Policy permissions, and access control entries on sensitive directory objects. Remove unnecessary write rights, separate administrative roles, and monitor changes to high value identities and policies.

## Further reading

- [Microsoft Learn: Creating an Active Directory query filter](https://learn.microsoft.com/en-us/windows/win32/ad/creating-a-query-filter)
- [Microsoft Learn: Best practices for securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
