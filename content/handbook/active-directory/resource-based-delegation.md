---
title: "Assessing Resource Based Constrained Delegation"
date: 2026-09-25
weight: 8
type: docs
tags:
  - Kerberos
  - RBCD
  - Active Directory
---

Resource based constrained delegation (RBCD) is configured on the resource account. The resource owner selects which front-end accounts may request delegated access to it. This reverses the administrative direction of traditional KCD, but it does not remove the need to control who can change the resource account's delegation descriptor.

## 1. Find configured resource relationships

Query computers and service users in the agreed domain. The Active Directory module's `PrincipalsAllowedToDelegateToAccount` property represents the principals allowed by the resource object's delegation descriptor.

```powershell
$Server = 'NW-AD-01.northwind.example'
$Base = 'DC=northwind,DC=example'

Get-ADComputer -Server $Server -SearchBase $Base -Filter * `
  -Properties PrincipalsAllowedToDelegateToAccount, Enabled, ManagedBy |
  Where-Object { $_.PrincipalsAllowedToDelegateToAccount } |
  Select-Object Name, Enabled, ManagedBy,
    @{Name='AllowedFrontEnds'; Expression={
      @($_.PrincipalsAllowedToDelegateToAccount | ForEach-Object DistinguishedName) -join '; '
    }}

Get-ADUser -Server $Server -SearchBase $Base -Filter * `
  -Properties PrincipalsAllowedToDelegateToAccount, Enabled, ManagedBy |
  Where-Object { $_.PrincipalsAllowedToDelegateToAccount } |
  Select-Object SamAccountName, Enabled, ManagedBy,
    @{Name='AllowedFrontEnds'; Expression={
      @($_.PrincipalsAllowedToDelegateToAccount | ForEach-Object DistinguishedName) -join '; '
    }}
```

Illustrative output:

```text
Name       Enabled ManagedBy                          AllowedFrontEnds
----       ------- ---------                          -----------------
DB-SRV-04  True    CN=Database Owners,OU=Groups,...  CN=APP-SRV-02,OU=Servers,...
```

## 2. Validate ownership and write access

For each target, identify the resource owner and the listed front-end owner. Review who can write the RBCD attribute or change the resource object's security descriptor. Resolve nested groups, inherited ACEs, deny entries, and object ownership before assigning risk. Use a directory ACL analyzer on the single candidate object, then preserve only the relevant ACEs and group path in the evidence record.

Ask whether the application still needs the relationship and whether the listed front end is the correct service identity. Validate ordinary user access to a low-impact application path without impersonating a privileged user. Configuration, control of a front-end account, and permission at the target are separate links in an access path.

## 3. Monitor changes

Review directory service change auditing for modifications to the target computer or user object, particularly changes to the `msDS-AllowedToActOnBehalfOfOtherIdentity` security descriptor. Correlate the actor, source host, change time, ticket, and service owner. Event visibility depends on directory auditing and central collection configuration; agree on required SACLs and retention with the directory team.

## 4. Remove stale principals through change control

If the relationship is no longer needed, the resource owner can preview clearing it through the AD module. This removes the resource's allowed front-end list, so confirm the business impact and obtain approval first:

```powershell
Set-ADComputer -Server $Server -Identity 'DB-SRV-04' `
  -PrincipalsAllowedToDelegateToAccount $null -WhatIf
```

For a user-based resource, use the corresponding `Set-ADUser` cmdlet. After an approved change, rerun the inventory and test the legitimate application workflow with its owner. Preserve the approved change record and compare the before/after object state.

## Further reading

- [Microsoft Learn: Resource based constrained delegation overview](https://learn.microsoft.com/en-us/entra/identity/domain-services/deploy-kcd)
- [Microsoft Learn: PowerShell remoting second hop and RBCD configuration](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ps-remoting-second-hop)
- [Microsoft Learn: Least privilege administrative models](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models)
