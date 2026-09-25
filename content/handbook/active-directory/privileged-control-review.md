---
title: "Reviewing Domain-Level Privileged Control Paths"
date: 2026-09-25
weight: 9
type: docs
tags:
  - Active Directory
  - Privileged Access
  - Domain Security
---

Domain-wide control can result from privileged group membership, directory replication rights, control of the domain controller tier, or access to domain recovery material. This runbook inventories those control points; it does not perform directory replication, export recovery secrets, or forge Kerberos tickets.

## 1. Review the highest-privilege groups

Run from an authorized domain-joined management host and preserve nested group membership for only the named groups:

```cmd
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net group "Schema Admins" /domain
```

Example output:

```text
Group name     Domain Admins
Members
-------------------------------------------------------------------------------
id.platform
svc_directory_backup
The command completed successfully.
```

Resolve nested groups and service identities with the directory team. Check each member's owner, purpose, authentication policy, and last review date. Do not assume that a group name proves its effective membership or use a privileged identity as a test account.

## 2. Inspect the domain root ACL for replication rights

`dsacls` reads the security descriptor for the supplied directory object. Filter output for the replication extended-right GUIDs and investigate each matching principal, including nested group membership and inheritance:

```cmd
dsacls "DC=northwind,DC=example" | findstr /i /c:"Replicating Directory Changes"
```

These GUIDs correspond to directory replication extended rights: `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`, `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`, and `89e95b76-444d-4c62-991a-0facbeda640c`. `dsacls` commonly renders the right by display name. A match requires review of trustee, ACE type, scope, and effective inherited rights. Preserve the complete ACL in the restricted evidence store; the filtered line alone may omit context.

## 3. Review changes and replication activity

Ask the directory team for Security Event 4662 records tied to replication rights and Event 5136 for changes to domain-root ACLs, with the required auditing and SACLs enabled. Correlate actor, source host, object DN, rights, and change ticket. Event IDs are useful only when policy, SACL coverage, retention, and forwarding are confirmed.

```cmd
repadmin.exe /showrepl NW-AD-01.northwind.example
```

Use this command to review replication health with the directory owner. It does not verify that sensitive replication rights are appropriately assigned; review the ACL and audit trail separately.

## 4. Handle ticket-forgery or recovery-key indicators as an incident

Kerberos ticket forgery depends on sensitive domain key material. Domain backup keys and CA signing keys also have broad recovery consequences. If those secrets may have been exposed, stop routine testing and notify the identity incident owner. They should determine the scope, rotate keys using the current Microsoft recovery procedure, assess replication and authentication impact, and review issued certificates or affected credentials. Do not export the secret as a proof-of-impact step.

## 5. Reduce domain-level control paths

Keep privileged memberships short and owner-approved, restrict write rights on the domain root and privileged groups, separate tier-zero administration, protect domain controllers, and monitor ACL and membership changes. After remediation, rerun the group and ACL inventory and confirm that required directory operations still work.

## Further reading

- [Microsoft Learn: Active Directory security best practices](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models)
- [Microsoft Learn: Audit Directory Service Access event 4662](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662)
- [Microsoft Learn: Event 5136 directory service changes](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136)
