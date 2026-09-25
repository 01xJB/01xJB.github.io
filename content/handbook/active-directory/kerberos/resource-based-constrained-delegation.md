---
title: "Exploiting Resource-Based Constrained Delegation: ACL Review"
date: 2026-09-25
weight: 4
type: docs
tags:
  - Kerberos
  - RBCD
  - Active Directory
---

Resource-based constrained delegation (RBCD) stores the permitted front-end principals on the resource account. The backing attribute is `msDS-AllowedToActOnBehalfOfOtherIdentity`; the AD PowerShell module exposes it through `PrincipalsAllowedToDelegateToAccount`. The key review question is who can change the resource's delegation descriptor.

## 1. Inventory configured resource relationships

Use a scoped, read-only query and retain the resource object distinguished name:

```powershell
$Server = 'NW-AD-01.northwind.example'
$Base = 'DC=northwind,DC=example'

Get-ADComputer -Server $Server -SearchBase $Base -Filter * `
  -Properties PrincipalsAllowedToDelegateToAccount, Enabled, ManagedBy |
  Where-Object { $_.PrincipalsAllowedToDelegateToAccount } |
  Select-Object Name, DistinguishedName, Enabled, ManagedBy,
    PrincipalsAllowedToDelegateToAccount
```

Example output:

```text
Name       Enabled ManagedBy                              PrincipalsAllowedToDelegateToAccount
----       ------- --------                              -------------------------------------
FILE-SRV-03 True   CN=File Services Owners,OU=Groups,... {CN=APP-SRV-02,OU=Servers,...}
```

Resolve each principal, its SPNs, owner, and nested group memberships. A listed relationship says which accounts the resource trusts; it does not prove that the principal is controlled or that a user is authorized at the service.

## 2. Review who can modify the resource

Inspect the target object's effective ACL, including inherited entries, nested groups, deny ACEs, ownership, `WriteProperty`, and rights to modify the security descriptor. The schema GUID for `msDS-AllowedToActOnBehalfOfOtherIdentity` is `3f78c3e5-f79a-46bd-a0b8-9d18116ddc79`.

For a single object, an approved PowerView copy can filter its ACL to that attribute:

```powershell
Get-DomainObjectAcl -Identity 'CN=FILE-SRV-03,OU=Servers,DC=northwind,DC=example' `
  -ResolveGUIDs |
  Where-Object { $_.ObjectAceType -match 'AllowedToActOnBehalfOfOtherIdentity' } |
  Select-Object IdentityReference, ActiveDirectoryRights, AceType, IsInherited
```

Example output:

```text
IdentityReference              ActiveDirectoryRights AceType IsInherited
-----------------              --------------------- ------- -----------
NORTHWIND\Server Operations    WriteProperty         Access        False
```

Resolve the trustee's group path and verify the effective right with the directory owner. A raw ACE is evidence to investigate, not proof that a particular user can exercise it.

## 3. Explain the exposure

### Exploiting resource-based constrained delegation

An abuse path requires control of a principal the resource accepts, a service identity with the necessary Kerberos properties, a permitted target service, and backend authorization. A write right on the resource descriptor can create or alter a delegation relationship. Do not modify `msDS-AllowedToActOnBehalfOfOtherIdentity` or request an impersonated user's ticket to demonstrate that configuration risk.

Report which access-control entry creates the exposure, who receives the right through nesting or inheritance, the affected resource, and the resource owner's expected configuration.

## 4. Monitor changes and remediate

With Directory Service Changes auditing and an applicable SACL, review Security Event 5136 for modifications to the resource object and the delegation attribute. Correlate the actor, source, object DN, timestamp, approved change, and SIEM forwarding.

The resource owner should remove stale principals through change control, then rerun the inventory and test the legitimate application flow. Preserve before-and-after object state.

## Further reading

- [Microsoft Learn: PowerShell remoting second hop and RBCD](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ps-remoting-second-hop)
- [Microsoft Open Specifications: S4U overview](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/36d103d2-61a6-42d5-a725-74de3205cdaf)
- [Microsoft Learn: Event 5136 directory service changes](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136)
