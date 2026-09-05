---
title: "Ollie"
type: docs
tags:
  - thm
  - linux
  - easy
  - phpipam
  - credential-leak
  - capabilities
---

<div class="callout callout-warning">

**🚧 Work in Progress**: This writeup is marked **partial** in my notes: the attack chain below may stop short of a full root/completion.

</div>

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Linux, **Difficulty:** Easy

</div>

<div class="callout callout-warning">

**Partial**

My notes cover recon and the credential grab from the port-1337 service. The SSH foothold and the root step are only sketched from memory, treat the italicised parts below as the known public path, not something reproduced command-by-command here.

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Ports 22 (SSH), 80 (Apache, **phpIPAM**), 1337 (a custom "Ollie" chat service).
2. Talk to the port-1337 service with `nc`. Answering its prompts (name, then what you're here for) makes the bot **leak a credential pair** → `admin : OllieUnixMontgomery!`.
3. *Those creds log into phpIPAM at `/`. phpIPAM ≤ 1.4.4 is vulnerable to authenticated SQLi (CVE-2021-46426) and post-auth RCE, used to land a shell as `www-data`.*
4. *Reuse / pivot to the `ollie` user (same password), grab `user.txt`.*
5. *`ollie` is in the `adm` group and there is a binary with the `cap_setuid` capability set (`feroxbuster`) → GTFOBins `cap_setuid` one-liner → root.*

</div>

<div class="callout callout-key">

**Credentials**

- `admin` : `OllieUnixMontgomery!`  (phpIPAM admin; also works for the `ollie` system user)

</div>

![Ollie_01](Ollie_01.png)

## Reconnaissance

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

`http-enum` on port 80, the layout is a **phpIPAM** install:

```console
/robots.txt   Robots file
/db/          BlogWorx Database
/app/  /css/  /functions/  /js/  /misc/   directory listings
/install/     phpIPAM installer left in place
```

![Ollie_02](Ollie_02.png)

![Ollie_03](Ollie_03.png)

A full-port scan turns up a custom service on **1337** that greets every connection:

```console
PORT     STATE SERVICE
1337/tcp open  unknown

Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.

What is your name?  ...  It's been a while. What are you here for?
```

## Foothold, leak creds from the port-1337 service

Connect with netcat and work through the bot's questions. Playing along with the prompts (give a name, then say you're here for the panel / credentials) gets it to hand over a login:

```bash
nc 10.10.x.x 1337
# What is your name?  -> <anything>
# What are you here for? -> the panel creds
# => admin / OllieUnixMontgomery!
```

Those credentials log into the **phpIPAM** panel on port 80.

## Privilege Escalation *(sketch)*

<div class="callout callout-note">

**Public path**

phpIPAM 1.4.x is vulnerable to authenticated SQL injection (**CVE-2021-46426**) and has a post-auth code-exec path; the common route is to get a `www-data` shell, then `su ollie` with the same password for `user.txt`.
For root: check `getcap -r / 2>/dev/null`, a binary carries `cap_setuid+ep`, so its GTFOBins `cap_setuid` invocation drops a `uid=0` shell.

</div>

```bash
getcap -r / 2>/dev/null
# .../feroxbuster = cap_setuid+ep
./feroxbuster ...     # GTFOBins cap_setuid payload -> root
```
