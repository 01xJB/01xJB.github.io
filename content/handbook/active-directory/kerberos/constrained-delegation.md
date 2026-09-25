---
title: "Exploiting Constrained Delegation: S4U2Self and S4U2Proxy"
date: 2026-09-25
weight: 3
type: docs
tags:
  - Kerberos
  - Constrained Delegation
  - Active Directory
---

Constrained delegation limits a service account to configured backend SPNs in `msDS-AllowedToDelegateTo`. The S4U extensions let a service request a ticket on behalf of a user. S4U2Self obtains a ticket to the service itself; S4U2Proxy uses qualifying evidence to request a ticket to an allowed backend. Protocol transition is associated with the `TRUSTED_TO_AUTH_FOR_DELEGATION` flag.

## 1. Enumerate configured delegation targets

Query user and computer service accounts separately. This reviewed Beacon LDAP search is read-only and capped at 50 results:

```text
beacon> ldapsearch "(&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*))" --attributes sAMAccountName,msDS-AllowedToDelegateTo --count 50 --hostname NW-AD-01.northwind.example --dn DC=northwind,DC=example
```

Example output:

```text
sAMAccountName: APP-SRV-02$
msDS-AllowedToDelegateTo: HTTP/api-srv-02.northwind.example
msDS-AllowedToDelegateTo: MSSQLSvc/db-srv-04.northwind.example:1433
```

For a user service account, repeat with the user-object filter from the approved LDAP client's help. Preserve the raw SPNs and resolve each one to its actual directory owner with `setspn.exe -Q <SPN>`.

## 2. Check protocol-transition configuration

Read `userAccountControl` for the single candidate. The protocol-transition bit is `16777216` (`0x01000000`). Use a bitwise check; do not infer the flag from the full decimal value because other account flags may also be set.

```text
beacon> ldapsearch "(sAMAccountName=APP-SRV-02$)" --attributes sAMAccountName,userAccountControl --count 1 --hostname NW-AD-01.northwind.example --dn DC=northwind,DC=example
```

Example output:

```text
sAMAccountName: APP-SRV-02$
userAccountControl: 16781312
```

For the sample value, `16781312 & 16777216` is non-zero, so the bit is set. This confirms a directory setting only; it does not establish that a ticket exchange will succeed or that the backend grants access.

```bash
python3 -c 'print(bool(16781312 & 16777216))'
```

Example output:

```text
True
```

## 3. Understand the abuse conditions

### Exploiting constrained delegation

An exposure review follows the chain: a delegating account is controlled; its delegation policy permits a target SPN; the KDC accepts the S4U request under the applicable ticket and account restrictions; and the backend authorizes the requested operation. Each link is distinct. A service ticket is not administrator access by itself.

Use the configuration evidence, account ACLs, SPN ownership, authentication policy, and backend authorization model to explain impact. Do not use Rubeus or another client to request a ticket for an impersonated privileged user on a production service. If a lab owner requires a functional test, define a disposable identity and non-sensitive backend in separate written scope.

## 4. Record and remediate

For each finding, record the delegating principal, exact allowed SPNs, protocol-transition state, service owner, identities allowed to modify the object, and backend permissions. Remove stale SPNs or disable protocol transition through the directory change process, then repeat the inventory and test the supported application path.

## Further reading

- [Microsoft Open Specifications: S4U overview](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/36d103d2-61a6-42d5-a725-74de3205cdaf)
- [Microsoft Open Specifications: S4U2proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9f44-e1453be7af5a)
- [Microsoft Learn: UserAccountControl flags](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
- [GhostPack Rubeus documentation](https://github.com/GhostPack/Rubeus)
