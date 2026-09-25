---
title: "Exploiting S4U2Self: Computer Account Exposure"
date: 2026-09-25
weight: 5
type: docs
tags:
  - Kerberos
  - S4U2Self
  - Active Directory
---

S4U2Self lets a service request a service ticket to itself on behalf of a named user. The extension supports application authorization when the user authenticated through a method other than Kerberos. In some Windows configurations, a service ticket associated with a computer account can become part of a larger impersonation risk when combined with service-name substitution and control of the account. The user name in a ticket does not establish that the ticket can be used against an unrelated service.

## 1. Check the account and SPN context

Start with directory facts for one in-scope computer account. Confirm the object owner, enabled state, SPNs, delegation flags, and any resource-side RBCD entry.

```text
beacon> ldapsearch "(sAMAccountName=APP-SRV-02$)" --attributes sAMAccountName,dNSHostName,userAccountControl,servicePrincipalName --count 1 --hostname NW-AD-01.northwind.example --dn DC=northwind,DC=example
```

Example output:

```text
sAMAccountName: APP-SRV-02$
dNSHostName: app-srv-02.northwind.example
userAccountControl: 4096
servicePrincipalName: HOST/APP-SRV-02
servicePrincipalName: RestrictedKrbHost/APP-SRV-02
```

This output is an account inventory, not evidence that the account's TGT is exposed or that any service will authorize a request.

## 2. Understand the risk chain

### Exploiting S4U2Self against a computer account

The assessment concern arises when an operator can control a computer service identity and use protocol behavior to seek a ticket representing another identity, then attempt to use it at a service that accepts the same account key. Impact still depends on KDC policy, ticket properties, service key ownership, and the target's authorization checks.

The chain crosses identity impersonation and privileged service access. For a public walkthrough, establish the relevant account configuration, service ownership, delegation restrictions, and audit evidence. Do not trigger inbound authentication, collect a machine TGT, issue an impersonated-user S4U request, inject a ticket, or access an administrative share.

## 3. Validate detection coverage

Have the identity team correlate approved test-window Kerberos service-ticket requests (Security Event 4769 when enabled) with the account, source host, target service, and expected application flow. On the endpoint, confirm the applicable Kerberos and logon auditing, process telemetry, time synchronization, retention, and forwarding. Record missing telemetry as a limitation, not as proof that the technique occurred.

## 4. Reduce the exposure

Limit control over computer and service accounts, review who may change SPNs and delegation descriptors, protect tier-zero systems from ordinary logons, and monitor unusual service-ticket patterns. A designated lab owner can authorize a separate isolated demonstration with disposable identities and non-sensitive services.

## Further reading

- [Microsoft Open Specifications: S4U overview](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/36d103d2-61a6-42d5-a725-74de3205cdaf)
- [Microsoft Open Specifications: S4U2proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9f44-e1453be7af5a)
- [Microsoft Learn: Kerberos authentication overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
