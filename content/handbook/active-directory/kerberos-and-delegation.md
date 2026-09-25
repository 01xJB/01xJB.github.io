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

Synthetic output:

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
