---
title: "Exploiting Unconstrained Delegation: Exposure Review"
date: 2026-09-25
weight: 2
type: docs
tags:
  - Kerberos
  - Unconstrained Delegation
  - Active Directory
---

Unconstrained delegation permits a trusted service to act on behalf of users beyond a fixed list of backend SPNs. When a client receives a service ticket marked for delegation, its authentication context may make the user's TGT available to the service host. Exposure is therefore driven by which identities authenticate to that host and who can control it.

## 1. Find computer accounts with the delegation flag

Use a bounded LDAP query against an approved domain controller. The LDAP matching rule checks the `TRUSTED_FOR_DELEGATION` bit (`524288`) in `userAccountControl`.

```text
beacon> ldapsearch "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes sAMAccountName,dNSHostName,operatingSystem --count 50 --hostname NW-AD-01.northwind.example --dn DC=northwind,DC=example
```

Example output:

```text
sAMAccountName: APP-SRV-02$
dNSHostName: app-srv-02.northwind.example
operatingSystem: Windows Server 2022
```

The result establishes configuration only. Confirm the service role, account owner, privileged-user exposure, and whether the setting remains necessary. Treat domain controllers separately because they have their own delegation requirements and tier-zero protection needs.

## 2. Explain the exposure path

### Exploiting unconstrained delegation

The risk sequence is: a user authenticates to a broadly trusted service; the service host receives delegated authentication material; control of that host can expose the material; and the user's rights may then be usable against other services. The KDC flag alone does not prove that a privileged user has authenticated to the host or that any destination will grant access.

For a public assessment record, establish the configuration, affected service, expected user population, relevant host protections, and owner-confirmed business purpose. Do not harvest or replay tickets as a proof step.

## 3. Review authentication and host evidence

Ask the identity and endpoint teams for a bounded time range around approved testing. Correlate the service host, user identity, source endpoint, and domain-controller service-ticket activity (Security Event 4769 when auditing is enabled). Confirm that required log sources, SACLs where applicable, retention, and forwarding were active before interpreting missing events.

## 4. Reduce exposure

Have the directory and application owners remove unconstrained delegation when the workflow no longer needs it. Where delegation is required, migrate to the narrowest supported constrained model, protect service hosts as privileged systems, and prevent sensitive users from signing in to delegation hosts where operationally appropriate.

After an approved directory change, rerun the same LDAP query and validate the application's ordinary workflow with its owner.

## Further reading

- [Microsoft Learn: UserAccountControl flags](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
- [Microsoft Learn: Least-privilege administrative models](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models)
- [Microsoft Open Specifications: S4U overview](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/36d103d2-61a6-42d5-a725-74de3205cdaf)
