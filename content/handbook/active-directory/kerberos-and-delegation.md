---
title: "Kerberos and Delegation Risk Assessment"
date: 2026-09-25
weight: 2
type: docs
tags:
  - Kerberos
  - Delegation
  - Active Directory
---

Kerberos gives domain users single sign on through tickets issued by a trusted Key Distribution Center. Delegation lets a service act on behalf of a user when it needs to reach another service. These features support ordinary business workflows, but a broad or poorly understood configuration can turn a low privilege foothold into access to a more sensitive system.

## Understand the ticket path

A user first obtains a ticket granting ticket from a domain controller. The user then requests a service ticket for a particular service principal name. The destination service validates the ticket and makes its own authorization decision. A valid ticket does not automatically grant access to every resource on the server.

For assessment work, keep three questions separate:

1. Which identity controls the account or service principal name?
2. Which systems and services may that identity reach?
3. What authorization does the destination service actually grant?

## Review service accounts

An account with a service principal name deserves review because its credentials protect a service identity. Check whether the account is still required, who can administer it, whether it uses a managed service account, and whether its password lifecycle is appropriate. Avoid collecting or cracking password material unless the rules of engagement explicitly permit it and the client has approved a safe handling plan.

## Review delegation settings

Delegation should be evaluated as a relationship between a service identity, an impersonated user, and a destination service. Inventory the configured delegation targets and identify whether the setting is broader than the application requires.

| Configuration | Assessment question |
| --- | --- |
| Unconstrained delegation | Is a system trusted to delegate user credentials without a narrow service boundary? |
| Constrained delegation | Are the allowed service principal names limited to the application’s actual dependencies? |
| Resource based constrained delegation | Who can modify the target computer’s allowed delegation principals? |
| Protocol transition | Does the application need to accept one authentication method and request a Kerberos service ticket on the user’s behalf? |

Do not infer risk from a flag alone. Confirm the account type, the destination service, the object permissions, the authentication flow, and the operational purpose with the system owner.

## Validate with a narrow proof

In a lab or explicitly approved production assessment, verify the configuration through directory inventory first. If a proof of impact is required, use a designated test identity and a non sensitive service. Confirm the expected access, capture the minimum evidence, and stop before reading protected files or modifying the destination.

Ticket manipulation, impersonation of privileged users, or use of production service credentials can create material impact. These actions need explicit authorization and a documented rollback plan. When those conditions are absent, use the configuration and access control evidence to support a risk finding without attempting escalation.

## Detection and remediation

Correlate Kerberos service ticket requests with the requesting identity, source host, destination service, and normal application behavior. Review unusual request volume and requests that do not fit the expected service relationship. Detection should account for legitimate batch jobs and application patterns rather than treating every ticket request as malicious.

Use managed service accounts where supported, remove unused service principal names, restrict delegation to required services, and limit who can change delegation attributes. Treat domain controllers, certificate authorities, and identity administration hosts as privileged systems with separate administrative paths.

## Step by step directory review

Use a designated domain controller and a read only account. The following commands inventory account metadata only. They do not request service tickets or attempt to authenticate as another identity.

```powershell
$Server = 'NW-AD-01.northwind.example'
$Base = 'DC=northwind,DC=example'

Get-ADUser -Server $Server -SearchBase $Base `
  -LDAPFilter '(servicePrincipalName=*)' `
  -Properties ServicePrincipalName, PasswordLastSet, ManagedBy, Enabled |
  Select-Object SamAccountName, Enabled, ManagedBy, PasswordLastSet,
    @{Name='SPNCount'; Expression={ @($_.ServicePrincipalName).Count }} |
  Sort-Object SamAccountName
```

Example output:

```text
SamAccountName Enabled ManagedBy                         PasswordLastSet       SPNCount
-------------- ------- ---------                         ---------------       --------
svc_app01  True    CN=Platform Owners,OU=Groups,...  8/14/2026 9:20:00 AM         2
svc_reporting  True    CN=Finance Systems,OU=Groups,...  7/02/2026 1:05:00 PM         1
```

Review delegation separately on computer and user objects. An empty list may mean no configured value, an unreadable attribute, a wrong search base, or a mismatch between the attribute and object type. Preserve the distinction in your notes.

```powershell
Get-ADComputer -Server $Server -SearchBase $Base -Filter * `
  -Properties TrustedForDelegation, TrustedToAuthForDelegation,
    'msDS-AllowedToDelegateTo', PrincipalsAllowedToDelegateToAccount |
  Where-Object {
    $_.TrustedForDelegation -or $_.TrustedToAuthForDelegation -or
    $_.'msDS-AllowedToDelegateTo' -or $_.PrincipalsAllowedToDelegateToAccount
  } |
  Select-Object Name, TrustedForDelegation, TrustedToAuthForDelegation,
    @{Name='AllowedServices'; Expression={$_.'msDS-AllowedToDelegateTo'}},
    PrincipalsAllowedToDelegateToAccount
```

Use PowerView only if the engagement requires it and the tool copy has been reviewed. For a read only comparison with the native module, query the same object and attributes rather than running broad user or host hunting functions:

```powershell
Get-DomainComputer -Domain 'northwind.example' `
  -Properties samaccountname, dnshostname, useraccountcontrol,
    msds-allowedtodelegateto |
  Select-Object SamAccountName, DNSHostName, useraccountcontrol,
    msds-allowedtodelegateto
```

The exact object property names depend on the version of PowerView. Confirm them with `Get-Help Get-DomainComputer -Full` and a single in scope object before saving results. Do not use the enumeration to request tickets, inject tickets, impersonate users, or change delegation.

## Interpret the result with logs

For each candidate, document the account, service principal name, delegation mode, listed target services, object owner, and groups that can modify the configuration. Ask the service owner whether the relationship is required. A flag by itself is not proof of a usable access path.

Ask defenders to correlate the query and any separately approved access check with domain controller Kerberos service ticket events, including Event ID 4769 where auditing is enabled. Compare the service, client address, account, and time with application baselines. Avoid treating a single event as malicious without understanding routine service behavior.

## Further reading

- [Microsoft Learn: Kerberos authentication overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- [Microsoft Learn: Kerberos authentication troubleshooting and delegation guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/kerberos-authentication-troubleshooting-guidance)
- [MITRE ATT&CK: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [MITRE ATT&CK: DCSync](https://attack.mitre.org/techniques/T1003/006/)

## Inventory all three delegation models

Use the same search base and domain controller throughout collection. Save raw object distinguished names so the application owner can confirm which service actually runs under each identity. These queries read directory attributes only. They do not ask a KDC for a ticket on behalf of another user.

```powershell
$Server = 'NW-AD-01.northwind.example'
$Base = 'DC=northwind,DC=example'

$Computers = Get-ADComputer -Server $Server -SearchBase $Base -Filter * `
  -Properties TrustedForDelegation, TrustedToAuthForDelegation,
    'msDS-AllowedToDelegateTo', PrincipalsAllowedToDelegateToAccount

$Computers |
  Where-Object {
    $_.TrustedForDelegation -or $_.TrustedToAuthForDelegation -or
    $_.'msDS-AllowedToDelegateTo' -or $_.PrincipalsAllowedToDelegateToAccount
  } |
  Select-Object Name, DistinguishedName, TrustedForDelegation,
    TrustedToAuthForDelegation,
    @{Name='KcdTargets'; Expression={ @($_.'msDS-AllowedToDelegateTo') -join '; ' }},
    @{Name='RbcdPrincipals'; Expression={ @($_.PrincipalsAllowedToDelegateToAccount) -join '; ' }} |
  Sort-Object Name

Get-ADUser -Server $Server -SearchBase $Base -Filter * `
  -Properties TrustedForDelegation, TrustedToAuthForDelegation,
    'msDS-AllowedToDelegateTo' |
  Where-Object {
    $_.TrustedForDelegation -or $_.TrustedToAuthForDelegation -or
    $_.'msDS-AllowedToDelegateTo'
  } |
  Select-Object SamAccountName, DistinguishedName, TrustedForDelegation,
    TrustedToAuthForDelegation,
    @{Name='KcdTargets'; Expression={ @($_.'msDS-AllowedToDelegateTo') -join '; ' }} |
  Sort-Object SamAccountName
```

Example output, with shortened DNs:

```text
Name         TrustedForDelegation TrustedToAuthForDelegation KcdTargets                 RbcdPrincipals
----         -------------------- -------------------------- ----------                 -------------
APP-SRV-02   False                False                      {HTTP/api.northwind.example} {}
FILE-SRV-03  True                 False                      {}                         {}
DB-SRV-04    False                False                      {}                         {CN=APP-SRV-02,...}

SamAccountName  TrustedForDelegation TrustedToAuthForDelegation KcdTargets
--------------  -------------------- -------------------------- ----------
svc_app01       False                True                       {HTTP/api.northwind.example}
```

Interpret each model separately:

| Model | Directory evidence | Assessment questions |
| --- | --- | --- |
| Unconstrained delegation | `TrustedForDelegation` | Is the service still required to delegate broadly? Is the computer tier appropriate? Are privileged identities protected from delegation? |
| Constrained delegation | `msDS-AllowedToDelegateTo`, sometimes with `TrustedToAuthForDelegation` | Does every SPN belong to an active application dependency? Is protocol transition required? Who can change the service account? |
| Resource based constrained delegation | `PrincipalsAllowedToDelegateToAccount` on the resource object, backed by `msDS-AllowedToActOnBehalfOfOtherIdentity` | Which front-end principals are trusted by the resource? Who can change the resource object's security descriptor? |

An entry is not proof that a user can become an administrator. Build the authorization path on paper: identify the principal that can act, the destination service, the users that may be delegated, and the destination's actual ACL. If the only proof would require a privileged impersonation or a ticket usable on a sensitive service, stop at the configuration evidence unless a separate written authorization defines a disposable lab target and exact permitted action.

## Review who can change the settings

For each candidate object, record the owner and inspect its effective ACL in a directory-aware ACL tool. Include inherited entries, nested groups, deny entries, and rights to write the delegation attributes or modify the object security descriptor. Keep the output to the candidate object rather than collecting every ACL in the domain. The built-in AD module can show the object's owner and raw security descriptor for subsequent review:

```powershell
$Target = Get-ADComputer -Server $Server -Identity 'DB-SRV-04' -Properties nTSecurityDescriptor
$Target.nTSecurityDescriptor.Owner
$Target.nTSecurityDescriptor.Access |
  Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType,
    ObjectType, IsInherited
```

Resolve group membership before attributing a right to an individual. A raw ACL row is evidence to investigate; it is not, by itself, proof that the principal can successfully change a protected attribute.

## Rubeus for ticket-cache visibility

Rubeus supports both legitimate ticket inspection and operations that request, extract, or alter tickets. For a low-impact assessment, use only a non-elevated, current-logon-session inventory. Never run a ticket-dump or harvesting action to answer an inventory question. Avoid running under SYSTEM or as an administrator, because some ticket views may expose other logon sessions.

Start with the Windows ticket viewer:

```powershell
klist
klist sessions
```

If Rubeus is specifically approved and present on the assessment workstation, its `triage` command can summarize tickets visible to the current context. Use the reviewed binary from the engagement tool store and save its SHA-256 with the evidence:

```powershell
Get-FileHash 'C:\Assessment\Tools\Rubeus.exe' -Algorithm SHA256
& 'C:\Assessment\Tools\Rubeus.exe' triage
```

Example output:

```text
LUID             UserName             ServiceName                         EndTime
----             --------             -----------                         -------
0x00000000002f5a21 NORTHWIND\analyst01 krbtgt/NORTHWIND.EXAMPLE            9/25/2026 6:45:00 PM
0x00000000002f5a21 NORTHWIND\analyst01 cifs/FILE-SRV-03.northwind.example  9/25/2026 6:45:00 PM
```

Use the result only to establish which tickets are present in the assessment user's own session. Do not export, inject, renew, request, crack, or impersonate with ticket material. Record the logon context, timestamp, tool hash, and the minimum metadata needed to explain the finding. If Rubeus is not explicitly approved, rely on `klist` and DC event records instead.

## Remediate with the identity owner

Remove delegation that the application no longer needs. Where broad delegation remains necessary, document the service owner, data sensitivity, and account-protection controls. Mark privileged user accounts as non-delegable when operationally appropriate, and use the narrowest supported constrained-delegation design for application flows.

Changes should be made by the directory owner through the normal change process. For example, the owner can review non-delegability on a sensitive user account with `Set-ADAccountControl -AccountNotDelegated $true`; do not apply it blindly to service accounts or systems without testing application behavior. The same cmdlet exposes `-TrustedForDelegation` and `-TrustedToAuthForDelegation`, but clearing a flag can interrupt a dependent service. For resource-based delegation, the resource owner should review and remove unneeded allowed principals using the AD module's supported account-management interface and validate the resulting attribute after change.

After an approved change, rerun the same bounded inventory and compare before/after results. Check Kerberos service-ticket activity on domain controllers, including Security Event 4769 where the required auditing is enabled. Baseline the source host, client, service name, encryption type, and request pattern before classifying an event as unusual.

For protocol details, see Microsoft's [Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview), [delegation security guidance](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models), and the [Rubeus project documentation](https://github.com/GhostPack/Rubeus/blob/master/README.md).
