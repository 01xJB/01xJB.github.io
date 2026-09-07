---
title: "Dog"
date: 2025-03-08
type: docs
tags:
  - htb
  - linux
  - easy
  - git-disclosure
  - backdrop-cms
  - cve-2022-45903
  - user-enumeration
  - password-reuse
  - sudo
  - bee
  - gtfobins
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 20.04), **Difficulty:** Easy, **Released:** 2025-03-08, **IP:** `10.10.11.58` → `dog.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Exposed **`.git/`** on the web root → dump → `settings.php` leaks the Backdrop DB password `BackDropJ2024DS2024`; commit metadata and config leak `tiffany@dog.htb`, `dog@dog.htb`.
2. The login form is a **username oracle** (`Sorry, no account with that email address found.` vs `Cannot send email`). Hydra finds a valid user **`john`**; `john` + the DB password logs into **Backdrop CMS** admin.
3. As admin, install a malicious module (`shell.tar`). **CVE-2022-45903** authenticated RCE. Webshell at `/modules/shell/shell.php` → shell as `www-data`.
4. **Password reuse**. The Backdrop DB password is also the local user **`johncusack`**'s password.
5. `johncusack` may `sudo /usr/local/bin/bee` (the Backdrop CLI). `bee eval` runs arbitrary PHP as root → SUID bash → root.

</div>

<div class="callout callout-key">

**Credentials & Flags**


| Where | Value |
| --- | --- |
| `.git` → `settings.php` (Backdrop DB) | `root : BackDropJ2024DS2024` |
| Backdrop admin | `john : BackDropJ2024DS2024` |
| `johncusack` (password reuse) | `BackDropJ2024DS2024` |
| `user.txt` | `/home/johncusack/user.txt` |
| `root.txt` | `/root/root.txt`. `1d2f8404f9d69d259d2666a6c741b759` |

</div>

---

## Overview

Dog turned out to be a great reminder that you don't need a single flashy zero-day to fully compromise a box, you just need to be relentless about connecting the small pieces of information you find along the way. Looking back at the full chain, it's really four well-worn primitives stacked on top of each other: a `.git` disclosure that leaked a database password, an error-message username oracle that told me exactly which account that password belonged to, an authenticated CMS RCE that got me a shell as `www-data`, and finally password reuse combined with a GTFOBins-style `sudo` binary (`bee eval`) that got me to root. None of these individually required writing new exploit code or chaining anything exotic. What actually mattered was discipline: dumping the git repository thoroughly, reading every file it gave me instead of skimming for the first credential I saw, and then, critically, trying that one recovered password against every account I could identify rather than assuming it only applied to the CMS.

I've run into variations on nearly every piece of this chain elsewhere. The `.git` disclosure pattern shows up again on [Cat](/writeups/hackthebox/linux/medium/cat/) and [Pilgrimage](/writeups/hackthebox/linux/easy/pilgrimage/). Username oracles in login forms are exactly what tripped up the target on [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/) and [Previse](/writeups/hackthebox/linux/easy/previse/). The `sudo <interpreter>` escalation pattern, where a management CLI or scripting language runtime is left runnable as root, is the same idea behind [Bizness](/writeups/hackthebox/linux/easy/bizness/), and GTFOBins-flavored escalations turn up repeatedly across [Lookup](/writeups/tryhackme/linux/easy/lookup/) and [BackFire](/writeups/hackthebox/linux/medium/backfire/). And the password-reuse-to-root pattern here mirrors what worked on [Blocky](/writeups/hackthebox/linux/easy/blocky/), [Cat](/writeups/hackthebox/linux/medium/cat/), and [Smol](/writeups/tryhackme/linux/medium/smol/).

---

## Full Walkthrough

### Nmap scan

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-git:
|   10.10.11.58:80/.git/
|_    Git repository found!
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
```

A standard nmap service scan against the host did most of the initial recon work for me here. Its scripts flagged an exposed `/.git/` directory on the web root and fingerprinted the application running on top of it as Backdrop CMS, both details that immediately told me where to focus first.

### Dump `.git`

An exposed `.git` directory on a live web server is effectively a source code and history leak, so my first move was to pull the entire object store down locally rather than try to browse it over HTTP:

```console
$ ./gitdumper.sh http://dog.htb/.git/ dest-dir
[+] Downloaded: HEAD
[+] Downloaded: refs/heads/master
[+] Downloaded: logs/HEAD
...
$ ./extractor.sh ../Dumper/dest-dir/ Dog
```

<div class="callout callout-note">

**`.git` disclosure (see [Cat](/writeups/hackthebox/linux/medium/cat/) for the full explanation)**

For anyone who wants the deeper mechanics of why this works, I cover it in more detail in my Cat writeup, but the short version is that `gitdumper` walks the exposed `.git` directory and pulls down the raw object store file by file, and `extractor` then replays every commit in that history into its own folder on disk. On Dog, that gave me two separate wins at once: `settings.php`, which held Backdrop's live database configuration, and a handful of configuration JSON files and commit author metadata that seeded a working list of usernames to test.

</div>

Reading through what the extractor pulled out, the database configuration inside `settings.php` was sitting in plaintext:

```php
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
```

While I had the full repository history on disk, it made sense to grep across everything for the box's domain rather than only check the obvious files, since commit metadata often leaks emails and usernames that don't appear anywhere in the current codebase:

```console
$ grep -iR 'dog.htb' Dog/
.../active/update.settings.json:  "tiffany@dog.htb"
.../commit-meta.txt: author root <dog@dog.htb> 1738963331 +0000
```

### Enumerating users

With a candidate password in hand and a couple of email addresses pulled from the commit history, my next question was which account, if any, that password actually belonged to. Poking at the login form manually, I noticed something useful: submitting an email that doesn't exist in the system returns "Sorry, no account with that email address found," while submitting one that does exist, just with a password Backdrop can't use to log in, returns a completely different message, **"Cannot send email."** That discrepancy is a textbook username oracle, so I automated the check with hydra against a large username list, using the recovered database password as the fixed password and watching for which attempts didn't return the "no account" failure string:

```bash
hydra -L /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  -p 'BackDropJ2024DS2024' -f dog.htb http-post-form \
  "/?q=user/login:name=^USER^%40dog.htb&pass=^PASS^&form_build_id=form-...&form_id=user_login&op=Log+in:Sorry, no account with that email address found."
```

```console
[80][http-post-form] host: dog.htb   login: john   password: BackDropJ2024DS2024
```

<div class="callout callout-note">

**Login forms as username oracles**

The reason this kind of oracle is so reliable is that developers rarely think about the information leaked by their error branches, they're focused on giving the user a helpful message, not on what that message confirms to an attacker. Backdrop returning a distinctly different string for "no such account" versus "account exists but can't log in this way" gave hydra exactly the differential it needed: pointing it at the failure string lets it flag any response that doesn't match as a hit. Once I knew `john` was a real account, trying the database password against it was an obvious next step, and it worked immediately, which says a lot about how often the same credential gets reused between a database connection string and a human-facing account. The fix on the defensive side is straightforward: return an identical, generic response regardless of whether the account exists ("if that account exists, we've sent a reset email"), and handle both branches in constant time so a timing side channel doesn't reopen the same oracle.

</div>

### Backdrop admin → CVE-2022-45903 → www-data

With valid admin credentials confirmed, logging into the Backdrop administration panel at `/?q=admin` as `john : BackDropJ2024DS2024` was straightforward.

<div class="callout callout-note">

**CVE-2022-45903, Backdrop CMS authenticated RCE**

Once I had admin access, I already knew where this was likely headed, since Backdrop CMS has a well-documented authenticated RCE tracked as CVE-2022-45903, and I wanted to understand exactly why it works before just running an exploit blindly. The module installer lets an administrator upload an archive and have Backdrop extract and register it as a new module, but the application never actually validates what's inside that archive. That means a module directory containing nothing more than a `.php` webshell and a minimal `.info` metadata file installs cleanly and becomes reachable directly under `/modules/<name>/` once the install finishes. In other words, any account with admin access is one archive upload away from arbitrary code execution, a serious design flaw for a feature most admins would assume is at least loosely sandboxed. Backdrop's "manual installation" URL-based install flow offers the same path in, for what it's worth.

</div>

I built a minimal module archive containing a PHP webshell alongside the required `.info` file, uploaded it as `shell.tar` through the module installer, and once Backdrop finished registering it, browsing to `http://dog.htb/modules/shell/shell.php` gave me code execution as `www-data`.

### User. Password reuse

Checking `/home` from my new shell showed a single local account, `johncusack`, and given how far a bit of password reuse had already gotten me on this box, testing the same Backdrop database password against it was the obvious next move, and it worked:

```bash
su johncusack        # BackDropJ2024DS2024   (SSH also works)
cat user.txt
```

### Privilege Escalation. `sudo bee eval`

Checking `sudo -l` as `johncusack` showed I could run `/usr/local/bin/bee`, Backdrop's command-line management tool, as root without a password. `bee` ships an `eval`/`ev` subcommand specifically for running arbitrary PHP inside the site's bootstrapped context, which meant I effectively had a root-level PHP interpreter available to me. Rather than do anything fancy in PHP, I used it to drop a SUID copy of bash, the simplest and most reliable way to convert arbitrary code execution as root into a stable root shell:

```console
(remote) johncusack@dog:/var/www/html$ sudo /usr/local/bin/bee ev "system('cp /bin/bash /tmp/bash && chmod u+s /tmp/bash')"
(remote) johncusack@dog:/tmp$ ./bash -p
(remote) root@dog:/root# cat root.txt
1d2f8404f9d69d259d2666a6c741b759
```

<div class="callout callout-note">

**`bee` = Backdrop's Drush**

If you haven't run into `bee` before, think of it as Backdrop's equivalent of Drupal's `drush`: a management CLI that bootstraps the full CMS environment so administrators can run maintenance tasks, clear caches, or evaluate PHP snippets directly against the site. That last capability is the problem. Handed a `sudo` entry, `bee eval` is functionally identical to `sudo php -r`, which GTFOBins has documented for years as an instant path to root, the CLI just happens to be a Backdrop-specific wrapper instead of the raw interpreter. One quirk worth noting for anyone reproducing this: `bee` needs to be invoked from the Backdrop site root to correctly bootstrap the application, so `cd /var/www/html` first or the `eval` call fails to find the site context it needs.

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/johncusack/user.txt` |
| `root.txt` | `/root/root.txt`. `1d2f8404f9d69d259d2666a6c741b759` |

---

## Lessons & Takeaways

- **Never let `.git/` be reachable over HTTP.** This single misconfiguration is what unraveled the entire box for me, a database password, several usernames, and enough context to understand the application's structure, all from files that were never meant to leave the deployment pipeline. Block dotfiles at the web server level (`location ~ /\.git { deny all; }` in nginx, or the Apache equivalent) and, better yet, deploy from built artifacts rather than `git pull`-ing a working copy straight onto a production web root.
- **Real credentials should never enter version control, full stop.** `settings.php` with a live, working database password baked in is the kind of thing that feels harmless in a private repo and becomes catastrophic the moment that repo (or just its `.git` metadata) is exposed. Secrets belong in environment variables or a secrets manager, injected at deploy time, never committed.
- **User-enumeration oracles in login and password-reset flows are worth taking seriously, even though they feel minor on their own.** By themselves they don't grant access, but paired with a leaked credential from anywhere else, which is exactly what happened here, they tell an attacker precisely which account to point that credential at. Return identical, generic responses regardless of whether the account exists, and make sure both code paths take the same amount of time.
- **Treat "install from an uploaded archive" as remote code execution, because functionally it is.** CVE-2022-45903 exists because Backdrop trusted the contents of an admin-uploaded archive without validating what was inside it. Any feature that lets a privileged user push arbitrary files onto the server needs to either restrict file types explicitly or run in a properly sandboxed, non-web-reachable location. Keeping the CMS patched matters here too, this vulnerability has a public advisory and exploit code.
- **Unique, non-reused passwords would have stopped this chain cold at multiple points.** The same database password unlocked the CMS admin account and then the underlying Linux user account. One password compromise turned into a full account takeover and a root path, purely because it was reused across trust boundaries that should never have shared a secret.
- **Any `sudo` rule granting access to an interpreter or a management CLI is functionally a root shell.** `bee eval`, like `drush`, `wp eval`, `artisan tinker`, `rails runner`, `node -e`, or plain `sudo php`, all hand you a code execution primitive at the elevated privilege level. When auditing `sudo -l` output, I treat any of these as an immediate root path rather than something to investigate further, and as a defender, I'd never grant `sudo` access to a CLI capable of evaluating arbitrary code in its own runtime.

---

## Related Writeups

- **`.git` disclosure:** [Cat](/writeups/hackthebox/linux/medium/cat/), [Pilgrimage](/writeups/hackthebox/linux/easy/pilgrimage/)
- **Username / login oracles:** [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), [Previse](/writeups/hackthebox/linux/easy/previse/)
- **Authenticated CMS RCE:** [Blocky](/writeups/hackthebox/linux/easy/blocky/), [Smol](/writeups/tryhackme/linux/medium/smol/), [Avenger](/writeups/tryhackme/windows/medium/avenger/)
- **`sudo <interpreter>` → root:** [Bizness](/writeups/hackthebox/linux/easy/bizness/), [Lookup](/writeups/tryhackme/linux/easy/lookup/)
- **Password reuse to `root`:** [Blocky](/writeups/hackthebox/linux/easy/blocky/), [Cat](/writeups/hackthebox/linux/medium/cat/), [Smol](/writeups/tryhackme/linux/medium/smol/)

## References

- CVE-2022-45903 (Backdrop CMS) <https://www.exploit-db.com/exploits/52021>
- GitTools <https://github.com/internetwache/GitTools>
- GTFOBins <https://gtfobins.github.io/>
