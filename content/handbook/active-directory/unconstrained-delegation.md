---
title: "Assessing Unconstrained Kerberos Delegation"
date: 2026-09-25
weight: 6
type: docs
tags:
  - Kerberos
  - Delegation
  - Active Directory
---

Unconstrained delegation allows a service to request services on behalf of an authenticated user without an explicit list of destination SPNs. That behavior can be required by legacy applications, but it broadens where delegated authentication may be used. Treat each configured account as a high-sensitivity identity and verify the business need with its owner.

## 1. Scope the review

Record the approved domain, domain controller, search base, allowed query window, and directory account used. Start with directory metadata only. Do not collect tickets, credentials, or memory from delegated systems.

```powershell
$Server = 'NW-AD-01.northwind.example'
$Base = 'DC=northwind,DC=example'

$ComputerDelegation = Get-ADComputer -Server $Server -SearchBase $Base -Filter * `
  -Properties TrustedForDelegation, Enabled, OperatingSystem, ManagedBy

$ComputerDelegation |
  Where-Object TrustedForDelegation |
  Select-Object Name, Enabled, OperatingSystem, ManagedBy, DistinguishedName |
  Sort-Object Name

$UserDelegation = Get-ADUser -Server $Server -SearchBase $Base -Filter * `
  -Properties TrustedForDelegation, Enabled, ServicePrincipalName, ManagedBy

$UserDelegation |
  Where-Object TrustedForDelegation |
  Select-Object SamAccountName, Enabled, ManagedBy, ServicePrincipalName,
    DistinguishedName |
  Sort-Object SamAccountName
```

Example output:

```text
Name         Enabled OperatingSystem              ManagedBy
----         ------- ---------------              ---------
FILE-SRV-03  True    Windows Server 2022 Standard CN=Infrastructure Owners,...

SamAccountName Enabled ManagedBy
-------------- ------- ---------
svc_legacy    True    CN=Application Operations,...
```

The list is a starting point. A domain controller can have delegation-related settings for legitimate reasons, and service accounts may not have a `ManagedBy` value. Confirm the server role, service identity, owner, and user populations that can authenticate to the service.

## 2. Determine whether the configuration is still needed

For each object, ask the service owner to identify the exact application flow and dependent users. Check whether the service can move to resource-based or constrained delegation. Review whether sensitive accounts are marked as non-delegable and whether administrative logons are prohibited on the affected host.

Use the machine-readable properties as evidence, not as a proof of a user-to-administrator path. Validate the destination authorization separately through ACL review and a low-impact access check with a designated test identity. Do not use a privileged account as an impersonation test identity.

## 3. Review exposure and monitoring

Prioritize servers where privileged users may log on, systems that process inbound authentication from broad populations, and service identities with excessive administrative rights. Correlate approved assessment windows with domain controller Security Event 4769 and endpoint logon records. Event meaning depends on audit configuration and normal workload, so compare service, client, source host, encryption type, and timing with an owner-provided baseline.

## 4. Remediate with a change owner

If the application no longer requires unconstrained delegation, the directory owner can preview clearing the setting with `-WhatIf`:

```powershell
Set-ADAccountControl -Server $Server -Identity 'FILE-SRV-03$' `
  -TrustedForDelegation $false -WhatIf
```

Do not run the change until the service owner confirms the dependency, the change is approved, and rollback is documented. Test the application after an approved change. For sensitive user accounts, the owner can separately review the non-delegable flag:

```powershell
Set-ADAccountControl -Server $Server -Identity 'admin.ops01' `
  -AccountNotDelegated $true -WhatIf
```

Non-delegability can affect application workflows. Apply it to designated sensitive accounts through identity policy and validate legitimate access afterward.

## Further reading

- [Microsoft Learn: Least privilege administrative models](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models)
- [Microsoft Learn: Set-ADAccountControl](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountcontrol)
- [Microsoft Learn: UserAccountControl flags](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
