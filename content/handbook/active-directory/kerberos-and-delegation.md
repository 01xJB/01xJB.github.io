---
title: "Kerberos and Delegation Risk Assessment"
date: 2026-09-24
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

## Further reading

- [Microsoft Learn: Kerberos authentication overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- [Microsoft Learn: Kerberos authentication troubleshooting and delegation guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/kerberos-authentication-troubleshooting-guidance)
- [MITRE ATT&CK: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [MITRE ATT&CK: DCSync](https://attack.mitre.org/techniques/T1003/006/)
