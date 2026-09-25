---
title: "Assessing Kerberos Constrained Delegation"
date: 2026-09-25
weight: 7
type: docs
tags:
  - Kerberos
  - Constrained Delegation
  - Active Directory
---

Kerberos constrained delegation (KCD) limits a front-end service to a configured set of back-end service principal names. Some configurations also enable protocol transition, allowing a service to request Kerberos service access after authenticating a user through another mechanism. The security question is whether the principal, impersonation behavior, and target service list still match the application's design.

## 1. Inventory user and computer service accounts

Use read-only Active Directory queries and retain the exact SPN values. Search users and computers because either object type may run a service.

```powershell
$Server = 'NW-AD-01.northwind.example'
$Base = 'DC=northwind,DC=example'

Get-ADUser -Server $Server -SearchBase $Base -Filter * `
  -Properties 'msDS-AllowedToDelegateTo', TrustedToAuthForDelegation,
    ServicePrincipalName, Enabled, ManagedBy |
  Where-Object { $_.'msDS-AllowedToDelegateTo' } |
  Select-Object SamAccountName, Enabled, TrustedToAuthForDelegation,
    ManagedBy, ServicePrincipalName,
    @{Name='DelegationTargets'; Expression={ $_.'msDS-AllowedToDelegateTo' -join '; ' }}

Get-ADComputer -Server $Server -SearchBase $Base -Filter * `
  -Properties 'msDS-AllowedToDelegateTo', TrustedToAuthForDelegation,
    ServicePrincipalName, Enabled, OperatingSystem |
  Where-Object { $_.'msDS-AllowedToDelegateTo' } |
  Select-Object Name, Enabled, OperatingSystem, TrustedToAuthForDelegation,
    ServicePrincipalName,
    @{Name='DelegationTargets'; Expression={ $_.'msDS-AllowedToDelegateTo' -join '; ' }}
```

Example output:

```text
SamAccountName Enabled TrustedToAuthForDelegation DelegationTargets
-------------- ------- -------------------------- -----------------
svc_app01      True    True                       HTTP/api.northwind.example

Name       Enabled TrustedToAuthForDelegation DelegationTargets
----       ------- -------------------------- -----------------
APP-SRV-02 True    False                      cifs/FILE-SRV-03.northwind.example
```

From an authorized Beacon, a reviewed TrustedSec `ldapsearch` BOF can perform the same narrow read without switching to PowerShell. This is read-only directory enumeration; check BOF provenance and output limits first:

```text
beacon> ldapsearch "(&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*))" --attributes sAMAccountName,msDS-AllowedToDelegateTo --count 20 --hostname NW-AD-01.northwind.example --dn DC=northwind,DC=example
```

Example output:

```text
sAMAccountName: APP-SRV-02$
msDS-AllowedToDelegateTo: cifs/FILE-SRV-03.northwind.example
```

The sample filter selects computer accounts that have a constrained-delegation target. Run a separate bounded query for user service accounts; do not assume a computer-only result is complete.

## 2. Verify each allowed service principal name

For every target, resolve the SPN to the owning directory object and confirm that the service is active and required. An SPN may include an alias, alternate port, or service class; do not infer the host from a substring alone.

```powershell
$TargetSpn = 'HTTP/api.northwind.example'
setspn.exe -Q $TargetSpn
```

Example output:

```text
Checking domain DC=northwind,DC=example
CN=api-service,OU=Service Accounts,DC=northwind,DC=example
        HTTP/api.northwind.example
Existing SPN found!
```

Document the delegation account, exact SPN, SPN owner, application owner, transition flag, and business purpose. Check nested group paths and the account's object permissions. Confirm the back-end resource's ACL using a test identity specifically approved for that service.

## 3. Understand what a configuration finding proves

KCD configuration can define an impersonation-capable service relationship. It does not prove that a particular identity can reach an administrative service or that the destination grants administrative access. Avoid demonstrating a finding by requesting a service ticket as a privileged user. If a high-impact proof is required, obtain separate written authorization for an isolated lab account and a non-sensitive service; do not reuse the lab procedure on production identities.

Rubeus and Impacket implement Kerberos ticket operations, including S4U-related functions. Those operations can impersonate identities and access target services. This public guide limits tool use to inventory and ticket-cache visibility; it does not provide ticket-request, ticket-injection, or impersonation steps. For local cache review, see [Kerberos and Delegation Risk Assessment](../kerberos-and-delegation/).

### Exploiting constrained delegation: S4U2Self and S4U2Proxy

Use this sequence to understand the risk and the evidence an assessor should seek. It describes the protocol flow without providing commands that mint or apply an impersonated ticket:

1. A front-end service authenticates a user. With Kerberos-only delegation, the service has a user service ticket it may present as evidence to the KDC.
2. With protocol transition, S4U2Self allows the service to request a service ticket to itself for a user authenticated by another mechanism. The relevant account configuration and KDC behavior affect whether this ticket is forwardable.
3. S4U2Proxy asks the KDC for a ticket to a back-end SPN using the evidence ticket. The KDC checks that the target SPN is allowed for the delegating account and applies other delegation restrictions.
4. The back-end service then makes its own authorization decision. A ticket to a service does not by itself grant local administrator or domain administrator rights.

For an assessment, verify the delegating identity, `msDS-AllowedToDelegateTo` SPN, protocol-transition flag, ticket/user protections, back-end ACL, and service owner. If a proof would require impersonating a privileged identity or touching a sensitive service, document the configuration chain and stop unless a separately approved disposable lab target is defined.

To check the protocol-transition flag from a read-only LDAP result, request only the one account's UAC value:

```text
beacon> ldapsearch "(sAMAccountName=svc_app01)" --attributes sAMAccountName,userAccountControl --count 1 --hostname NW-AD-01.northwind.example --dn DC=northwind,DC=example
```

Example result and bit check:

```text
sAMAccountName: svc_app01
userAccountControl: 16777728

$ python3 -c 'print(bool(16777728 & 16777216))'
True
```

`16777216` is `TRUSTED_TO_AUTH_FOR_DELEGATION`. The result confirms a configuration bit only. It does not establish that S4U succeeds, that a service ticket is forwardable, or that the target service grants access.

## 4. Reduce the delegation surface

Have the application owner remove SPNs the service no longer uses and disable protocol transition if the authentication architecture does not require it. Where change is approved, preview clearing a user's delegation-target list:

```powershell
Set-ADUser -Server $Server -Identity 'svc_app01' `
  -Clear 'msDS-AllowedToDelegateTo' -WhatIf
```

Treat this as a change-plan example. Do not apply it without confirming application dependencies, directory ownership, approval, and rollback. Repeat the original inventory after change, then have the service owner validate the supported user workflow.

## Further reading

- [Microsoft Learn: Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft Learn: msDS-AllowedToDelegateTo schema](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtodelegateto)
- [GhostPack Rubeus documentation](https://github.com/GhostPack/Rubeus/blob/master/README.md)
- [Fortra Impacket getST source and usage comments](https://github.com/fortra/impacket/blob/master/examples/getST.py)
