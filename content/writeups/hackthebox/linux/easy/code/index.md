---
title: "Code"
date: 2025-07-05
type: docs
tags:
  - htb
  - linux
  - easy
  - python
  - sandbox-escape
  - flask
  - sqlalchemy
  - hashcat
  - sudo
  - path-traversal
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 20.04), **Difficulty:** Easy, **Released:** 2025-07-05, **IP:** `10.10.11.62` → `code.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Gunicorn app on `:5000`. An online **Python code editor** with a keyword blacklist sandbox.
2. Bypass the blacklist to reach the app's own **SQLAlchemy** models and dump the `users` table → MD5 hashes for `development` and `martin`.
3. Crack `martin` → `nafeelswordsmaster` → SSH.
4. `martin` may `sudo /usr/bin/backy.sh`, which archives paths from an attacker-supplied JSON. Its `../` sanitiser is bypassable → archive `/root` → read root's files (and `root.txt` / an SSH key).

</div>

<div class="callout callout-key">

**Credentials & Flags**


| Where | Value |
| --- | --- |
| `development` (cracked MD5) | `development` |
| `martin` (cracked MD5) | `nafeelswordsmaster` |
| `user.txt` | `/home/martin/user.txt` |
| `root.txt` | recovered from the `/root` archive |

</div>

---

## Overview

Code is, at its heart, a Python sandbox-escape box, and almost all of the interesting work happens right at the foothold. The target exposes an "online code editor" that lets you submit Python for execution, and the developers tried to make that safe the way most people instinctively do: with a blacklist of dangerous substrings like `import`, `os`, `subprocess`, `eval`, `open`, and `__`. The moment I saw that approach I had a pretty good idea where this box was going, because blacklisting substrings in a Turing-complete language is a losing game from the start. You don't actually need to write `import os` when the Flask application hosting your sandbox has already done all the importing for you and left its `db` session object and `User` model class sitting in the global namespace, fully reachable from inside the "sandboxed" code. Once I confirmed that, the rest of the foothold was standard ORM abuse to pull credentials straight out of the database. Privilege escalation turned out to be a different flavor of the same underlying lesson: a `sudo` script that trusted a path field inside an attacker-supplied JSON file, defeated by a path-traversal sanitiser that only stripped `../` once instead of looping until the string stopped changing.

I've run into this "blacklist versus Turing-complete language" pattern often enough that I keep a mental catalog of related boxes. The eval/sandbox-escape family includes [Headless](/writeups/hackthebox/linux/medium/headless/), [TwoMillion](/writeups/hackthebox/linux/easy/twomillion/), and [Athena](/writeups/tryhackme/linux/easy/athena/), while the "attacker-controlled config feeding a `sudo` script" pattern shows up again on [Bizness](/writeups/hackthebox/linux/easy/bizness/) (through `gradlew`), and across the cluster of [Stocker](/writeups/hackthebox/linux/easy/stocker/), [Bagel](/writeups/hackthebox/linux/medium/bagel/), and [Forge](/writeups/hackthebox/linux/medium/forge/).

---

## Reconnaissance

I started, as I do on every box, with a full port scan to get a baseline picture of what `code.htb` was exposing before I touched anything else:

```console
Nmap scan report for code.htb (10.10.11.62)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12
5000/tcp open  http    Gunicorn 20.0.4
|_http-title: Python Code Editor
```

## Foothold. Sandbox escape → DB dump

Since the editor was clearly built on Flask, my working assumption was that a SQLAlchemy `User` model was already imported somewhere in the application and therefore reachable from the sandbox's global scope. The runtime itself was locked down hard behind a keyword blacklist, but blacklists filter source text, not the object graph that's already sitting in memory, so direct attribute and object access was still fair game. I tested that theory by walking the ORM directly from inside the editor:

<div class="callout callout-note">

**Why the blacklist fails**

The sandbox rejects any source string containing patterns like `import`, `os`, `open`, `eval`, `exec`, `__`, or `subprocess`, but it never touches objects that are already sitting in scope by the time my code runs. A Flask application's module globals almost always include the `app` instance, the `db` SQLAlchemy session, and every model class it defines, and none of those names trip the filter because I'm not importing anything, I'm only referencing what's already there. From that starting point, `db.session` and `Model.query` hand me full ORM read and write access without a single forbidden keyword ever appearing in my payload. Even against an app that doesn't leave anything quite that convenient lying around, I can usually still walk `().__class__.__mro__[1].__subclasses__()` to enumerate every loaded class until I find something like `subprocess.Popen`. That's exactly why blacklisting `__` is such a common instinct, and also why it's such a commonly broken one: it catches a lot of naive exploitation attempts, but it also breaks legitimate introspection, and a determined attacker routes around it regardless. In my experience the only mitigation that actually holds up is a real, OS-level sandbox: a separate process, `seccomp` filtering, `nsjail`, or something like RestrictedPython built around an allowlist rather than a blacklist.

</div>

```python
for i in User.query.all():
    print(i.__dict__)
```

![Pasted image 20250508184130](Pasted-image-20250508184130.png)

<div class="callout callout-key">

**Credentials (`hash:username` → cracked password)**

- `759b74ce43947f5f4c91aeddc3e5bad3 : development` → `development`
- `3de6f30c4a09c27fc71932bfc68474be : martin` → `nafeelswordsmaster`

</div>

With both hashes pulled out of the `users` table, I threw them at hashcat against `rockyou.txt` rather than trying to guess anything manually, and `martin`'s hash cracked almost immediately:

```bash
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
ssh martin@code.htb          # nafeelswordsmaster
```

## Privilege Escalation. `sudo backy.sh` path traversal

```console
martin@code:~$ sudo -l
User martin may run the following commands on code:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
```

With a shell as martin, checking `sudo -l` was the obvious next move, and it paid off immediately: martin could run `/usr/bin/backy.sh` as root with no password. Digging into what that script actually does, I found it wraps `/usr/bin/backy`, a small backup utility that reads a JSON task file describing which directories to archive and then shells out to `tar` on martin's behalf.

<div class="callout callout-note">

**The traversal bypass**

Reading through `backy`, I found it restricts `directories_to_archive` to paths starting with `/home/` or `/var/`, then makes exactly one non-recursive pass to strip the literal substring `../` out of whatever path I give it. That single pass is the entire flaw, and it's a satisfying one to spot: if I double up the dots into `....//`, stripping the first `../` the sanitiser finds out of the middle of that string still leaves `../` behind. Stack two of those groups in front of `root/` and the one-shot strip collapses `/var/....//....//root/` down to `/var/../../root/`, which resolves straight past `/var` and lands in `/root` the moment `tar` actually walks it, well after the sanitiser already finished its job. The leading `/var/` is all it takes to satisfy the whitelist check before any of that collapsing happens, so the crafted path sails through untouched.

</div>

```json
{
  "destination": "/home/martin/backups/",
  "multiprocessing": true,
  "verbose_log": false,
  "directories_to_archive": [
    "/var/....//....//root/"
  ],
  "exclude": [".*"]
}
```

```bash
sudo /usr/bin/backy.sh task.json
# then extract the resulting archive from /home/martin/backups/
tar xf /home/martin/backups/code_home_martin_*.tar.bz2
cat root/root.txt        # and root/.ssh/id_rsa -> ssh root@code.htb
```

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/martin/user.txt` |
| `root.txt` | `/root/root.txt` (via the archive) |

---

## Lessons & Takeaways

- **Blacklists aren't sandboxes.** If you must run untrusted code, isolate it at the OS level (`nsjail`, gVisor, a throwaway container). Never with string filters.
- **Don't leave live ORM handles in module globals** of a service that evals user input.
- **Unsalted MD5** for password storage is indefensible; use `argon2`/`bcrypt`.
- **Path sanitisers must loop until stable** and canonicalise with `realpath()` before the prefix check, not after a single `str.replace`.
- Scope `sudo` scripts and validate their entire input, not just a prefix.

---

## Related Writeups

- **Python / eval sandbox escape:** [Headless](/writeups/hackthebox/linux/medium/headless/), [TwoMillion](/writeups/hackthebox/linux/easy/twomillion/), [Athena](/writeups/tryhackme/linux/easy/athena/)
- **Attacker-controlled config → `sudo` script:** [Bizness](/writeups/hackthebox/linux/easy/bizness/), [Stocker](/writeups/hackthebox/linux/easy/stocker/), [Bagel](/writeups/hackthebox/linux/medium/bagel/)
- **Dump an app's own user table → crack:** [Cat](/writeups/hackthebox/linux/medium/cat/), [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/), [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/)
- **`sudo` misconfig privesc:** [Forge](/writeups/hackthebox/linux/medium/forge/), [Headless](/writeups/hackthebox/linux/medium/headless/), [Lookup](/writeups/tryhackme/linux/easy/lookup/)

## References

- Escaping Python sandboxes <https://hacktricks.boitatech.com.br/misc/basic-python/bypass-python-sandboxes>
- RestrictedPython <https://github.com/zopefoundation/RestrictedPython>
- nsjail <https://github.com/google/nsjail>
- The `backy.sh` path-traversal privesc was cross-referenced against public writeups for this box.
