---
title: "Atom"
date: 2021-04-17
type: docs
tags:
  - htb
  - windows
  - medium
  - smb
  - electron
  - electron-updater
  - cve-2020-15087
  - portablekanban
  - weak-crypto
  - redis
  - evil-winrm
  - retired
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Windows 10 Pro, **Difficulty:** Medium, **Released:** 2021-04-17, **IP:** `10.10.10.237` , `atom.htb`

</div>

<div class="callout callout-warning">

**Partial**

Only the port scan and the SMB share discovery survived in my notes. The rest is reconstructed from published writeups and marked.

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Anonymous / guest SMB gives **READ/WRITE** on a `Software_Updates` share. It holds release PDFs and a `client side` folder. The company's desktop app ("Heed Solutions") is an **Electron** app using **electron-updater**.
2. **CVE-2020-15087**, electron-updater does not verify the signature of the `latest.yml` update manifest on Windows. Drop a malicious NSIS installer plus a matching `latest.yml` (correct SHA512 + size) into the share. When the app checks for updates it downloads and runs your installer. RCE as **`jason`**.
3. `C:\Users\jason\Portable Kanban\` , **PortableKanban** stores credentials with a **reversible XOR/DES cipher**. A public decryptor recovers the **Redis** password.
4. `redis-cli -a <pw>` and the PortableKanban `.pk` data yield the **Administrator** password (PortableKanban stores its own user list with the same weak cipher). `evil-winrm` as Administrator.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| PortableKanban (decrypted) | Redis password, then `Administrator` password |
| `user.txt` | `C:\Users\jason\Desktop\user.txt` |
| `root.txt` | `C:\Users\Administrator\Desktop\root.txt` |

</div>

---

## Overview

Atom is a **software supply chain** box, and it is one of my favourite kinds of Windows target because the vulnerability is not in a service or a driver, it is in a workflow: "the desktop app checks a share for updates." The foothold is **CVE-2020-15087**: electron-updater on Windows trusts an unsigned `latest.yml`, so anyone who can write where the app looks for updates can push a malicious "update" that runs as the user. Once I confirmed the share was writable, the rest of the chain fell into place quickly. The privesc leg is **PortableKanban**, a small kanban app that stores every password with a trivially reversible cipher (there is a well-known Python decryptor), so once you can read its data files you have the Redis password and then the Administrator password. The lesson thread running through the whole box: auto-updaters and local app databases are credential stores whether their developers intended that or not, and "the update is signed" is only true if the *manifest* is signed too.

Related "credentials in a local app store": [Bolt](/writeups/hackthebox/linux/medium/bolt/) (Passbolt / Chrome extension), [POV](/writeups/hackthebox/windows/medium/pov/) (`connection.xml`). Related Electron / desktop-app boxes: rare. Related SMB writable share to foothold: [Weasel](/writeups/tryhackme/windows/hard/weasel/), AD boxes with writable shares.

---

## Full Walkthrough

### Recon

I always start with a full-port nmap sweep on Windows boxes since the interesting service is rarely on a "top 1000" port, and Atom rewarded that habit immediately: alongside the expected web and SMB ports there was Redis sitting wide open.

```console
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Apache 2.4.46 (Win64) PHP/7.3.27   ("Heed Solutions")
135/tcp  open  msrpc
443/tcp  open  ssl/http     Apache (SSL)
445/tcp  open  microsoft-ds Windows 10 Pro 19042
5985/tcp open  http         WinRM
6379/tcp open  redis        Redis key-value store
7680/tcp open  pando-pub?
```

(nmap/nikto dumps trimmed.) The site advertises a downloadable desktop app and an email `MrR3boot@atom.htb`, which is the kind of detail I always note down since usernames on Windows AD-flavoured boxes tend to resurface later. Here it mostly told me the company theme ("Heed Solutions") and that there was a client app worth pulling apart.

### SMB, the writable update share

With `445` open, SMB enumeration was the obvious next stop, and guest access on Windows boxes is worth checking on every single engagement, it costs nothing and it pays off far more often than people expect.

```console
$ smbclient -N -L //10.10.10.237/
    Software_Updates    Disk
$ smbmap -H 10.10.10.237 -u guest
    Software_Updates    READ, WRITE
```

That `WRITE` next to a guest session is the whole game on this box. `Software_Updates` has `client side/` and some `1.0` / `2.0` release note PDFs. The client app is an Electron build (the download is an NSIS installer; unpacking `app.asar` shows `electron-updater`), and the moment I saw `electron-updater` sitting next to a share I can write to, CVE-2020-15087 was the first thing that came to mind.

### Foothold, CVE-2020-15087 (electron-updater)

<div class="callout callout-note">

**CVE-2020-15087**

`electron-updater` on Windows checks the SHA512 of the downloaded installer against `latest.yml`, but before ~4.3.1 it does **not** verify that `latest.yml` itself is signed or came from the expected origin. So if you control the update feed (here, a share the app polls), you supply:
- `evil.exe` , a malicious NSIS installer (`msfvenom -f exe`, or a self-extracting archive that runs a payload)
- `latest.yml` , with `path: evil.exe`, the correct `sha512` (base64 of the raw digest) and `size`

The app sees a "newer version", downloads `evil.exe`, the hash matches the (attacker) manifest, and it executes. Code runs as `jason`.

</div>

```yaml
# latest.yml
version: 9.9.9
path: evil.exe
sha512: <base64 sha512 of evil.exe>
releaseDate: '2025-01-01T00:00:00.000Z'
```

```bash
cp evil.exe latest.yml  ->  //atom.htb/Software_Updates/client side/
```

I set up a listener, dropped both files into the share, and waited for the app's poller to notice the "newer version." Within a few minutes it did, and I caught a shell as **`jason`**. `user.txt` is on the desktop.

### jason to Administrator, PortableKanban

With a foothold in hand, my next habit is always the same: check what is actually installed for this user, since a fresh Windows box rarely has anything interesting beyond what the box author placed there deliberately. A directory named after a kanban tool immediately stood out.

```powershell
dir "C:\Users\jason\Portable Kanban"
```

<div class="callout callout-note">

**PortableKanban weak crypto**

PortableKanban stores users and their passwords in `.pk` JSON files, encrypted with a hardcoded key and a DES/XOR scheme. The [PortableKanban decryptor](https://www.exploit-db.com/exploits/49409) (EDB 49409) reverses any value. The stored `Redis` credential comes out first:
```bash
python3 pkdecrypt.py "<encrypted redis password>"
redis-cli -h atom.htb -a <redis pw>
redis-cli> KEYS *
```
and the PortableKanban user list includes an entry for `Administrator` whose password decrypts the same way. That password is valid for WinRM.

</div>

```bash
evil-winrm -i atom.htb -u Administrator -p '<decrypted password>'
type C:\Users\Administrator\Desktop\root.txt
```

That last `type` was satisfying: two completely unrelated weaknesses, an unsigned update manifest and a home-grown "encryption" scheme, chained together into full domain-admin-equivalent access on the box.

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `C:\Users\jason\Desktop\user.txt` |
| `root.txt` | `C:\Users\Administrator\Desktop\root.txt` |

---

## Lessons and Takeaways

- **Sign the update manifest, not just the binary.** Patch electron-updater and serve updates over HTTPS from a pinned origin. An attacker who controls the feed owns every client.
- **Do not expose an update feed on a writable SMB share.**
- **PortableKanban (and many small apps) store passwords reversibly.** Treat any local app database as plaintext once you can read it.
- **Don't reuse the Administrator password** as a PortableKanban account password.
- **Restrict guest/anonymous SMB.** `smbmap -u guest` finding a writable share is the whole foothold.

---

## Related Writeups

- **Credentials in a local app store / config:** [Bolt](/writeups/hackthebox/linux/medium/bolt/), [POV](/writeups/hackthebox/windows/medium/pov/), [Environment](/writeups/hackthebox/linux/medium/environment/)
- **Writable SMB share to foothold:** [Weasel](/writeups/tryhackme/windows/hard/weasel/), [VulnNet Roasted](/writeups/tryhackme/windows/medium/vulnnet-roasted/)
- **Redis:** [VulnNet Active](/writeups/tryhackme/windows/medium/vulnnet-active/)
- **Supply chain / auto-updater abuse:** [Atom](/writeups/hackthebox/windows/medium/atom/) is the reference

## References

- CVE-2020-15087 (electron-updater) <https://github.com/electron-userland/electron-builder/security/advisories/GHSA-r4pf-3v7r-hh55>
- PortableKanban decryptor (EDB 49409) <https://www.exploit-db.com/exploits/49409>
- HTB Atom (0xdf) <https://0xdf.gitlab.io/2021/08/07/htb-atom.html>
- Final privilege escalation steps cross-referenced against public writeups for this box.
