---
title: "Exploiting Kerberos Service Name Substitution: SPN Ownership Review"
date: 2026-09-25
weight: 6
type: docs
tags:
  - Kerberos
  - SPN
  - Active Directory
---

A Kerberos ticket carries a service name as well as encrypted ticket data. A service-name substitution issue can arise when two service names resolve to services running under the same account key. The target service may then be able to decrypt ticket data even though the KDC issued the ticket for a different service name. This is conditional on key ownership and service behavior; it is not a general way to change a ticket into access to any host.

## 1. Identify the allowed and adjacent SPNs

Start with the exact SPN recorded in a constrained-delegation review. Query both the configured SPN and any proposed alias so the directory owner can compare their account owners:

```cmd
setspn.exe -Q HTTP/api-srv-02.northwind.example
setspn.exe -Q cifs/api-srv-02.northwind.example
```

Example output:

```text
Checking domain DC=northwind,DC=example
CN=API Service,OU=Service Accounts,DC=northwind,DC=example
        HTTP/api-srv-02.northwind.example
Existing SPN found!

Checking domain DC=northwind,DC=example
CN=API Service,OU=Service Accounts,DC=northwind,DC=example
        cifs/api-srv-02.northwind.example
Existing SPN found!
```

If both names resolve to the same principal, record that as a potential service-boundary concern and confirm which services actually run under the account. Different owners, duplicate SPNs, aliases, and port-qualified SPNs change the analysis.

## 2. Explain the delegation risk

### Exploiting service-name substitution

When a configured delegation target is a low-utility service, an attacker may look for another service name protected by the same account key. That could widen the impact of an otherwise narrow delegation entry. The condition is account-key equivalence, not merely that two SPNs share a hostname.

Do not request an impersonated-user ticket or alter a ticket's service name to demonstrate the issue. Use SPN ownership, service configuration, delegation attributes, and the backend ACL to show the possible boundary crossing. Treat this as a configuration risk until a separately authorized disposable lab verifies behavior.

## 3. Correct the service boundary

Assign services to appropriately separated accounts where practical. Remove stale or duplicate SPNs through the directory change process, review delegation targets, and verify the application after change. Monitor unexpected SPN registration and changes to service account ownership.

## Further reading

- [Microsoft Open Specifications: S4U overview](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/36d103d2-61a6-42d5-a725-74de3205cdaf)
- [Microsoft Learn: setspn command reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/setspn)
- [Microsoft Learn: Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
