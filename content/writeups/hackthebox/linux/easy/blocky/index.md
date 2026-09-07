---
title: "Blocky"
date: 2017-07-21
type: docs
tags:
  - htb
  - linux
  - easy
  - wordpress
  - directory-listing
  - jar-decompile
  - hardcoded-credentials
  - password-reuse
  - sudo
  - retired
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 16.04), **Difficulty:** Easy, **Released:** 2017-07-21, **IP:** `10.10.10.37` → `blocky.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. WordPress + phpMyAdmin + a Minecraft server on `25565`. `/wp-content/uploads/` (really `/plugins/`) has **directory listing on** and hosts a custom plugin jar, `BlockyCore.jar`.
2. Decompile the jar with **jd-gui** → hard-coded MySQL root password `8YsqfCTnvxAUeduzjNSXe22`.
3. Log into phpMyAdmin as `root`, read `wp_users`. Confirms the user **`notch`** (the Minecraft creator, a theme joke).
4. **Password reuse**. The SQL password is also `notch`'s system password → SSH.
5. `notch` has unrestricted `sudo` (`(ALL : ALL) ALL`) → `sudo su` → root.

</div>

<div class="callout callout-key">

**Credentials & Flags**


| Where | Value |
| --- | --- |
| `BlockyCore.jar` (decompiled) | `root : 8YsqfCTnvxAUeduzjNSXe22` (MySQL) |
| `notch` (password reuse) | `8YsqfCTnvxAUeduzjNSXe22` |
| `user.txt` | `/home/notch/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Blocky is one of the oldest boxes on HackTheBox, and it's still the canonical teaching example for a vulnerability class I run into constantly on real assessments: credentials baked directly into a compiled artifact. My reasoning going in, once I spotted an exposed plugins directory, was straightforward: a Java `.jar` file is nothing more than a zip archive of `.class` bytecode, and that bytecode retains enough structure (field names, method signatures, string constants) that a decompiler reconstructs something extremely close to the original source. Any secret a developer hard-codes into a plugin, an agent, or a desktop app is trivially recoverable the moment you can pull the file down. Everything past that point on this box comes down to two classic mistakes stacked on top of each other: the same MySQL password reused as a Linux login password, and the resulting shell landing on a throwaway unrestricted-sudo rule. The full chain, in the order I actually worked it: find the exposed jar, decompile it, reuse the recovered credential across two different services, then `sudo su` straight to root.

I've run into this exact "secrets in a downloadable file" pattern on a handful of other boxes worth cross-referencing: [Backdoor](/writeups/hackthebox/linux/easy/backdoor/) exposes `wp-config.php` through a directory traversal bug, and [Cat](/writeups/hackthebox/linux/medium/cat/) leaks source through an exposed `.git` directory. The password-reuse-to-root pattern shows up again on [Dog](/writeups/hackthebox/linux/easy/dog/), [Cat](/writeups/hackthebox/linux/medium/cat/), and [Smol](/writeups/tryhackme/linux/medium/smol/). And for an unrestricted-`sudo` finish, [Blocky](/writeups/hackthebox/linux/easy/blocky/) itself is about as textbook a case as they come.

---

## Full Walkthrough

### Recon

```console
PORT      STATE  SERVICE   VERSION
21/tcp    open   ftp       ProFTPD 1.3.5a
22/tcp    open   ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.2
80/tcp    open   http      Apache httpd 2.4.18 ((Ubuntu))
25565/tcp open   minecraft Minecraft 1.11.2 (Message: A Minecraft Server, Users: 0/20)
```

I also ran `nmap --script vulners` against the host, which threw back roughly two hundred lines of CVE references tied to the aging SSH and Apache builds. None of them turned out to be the actual way in, so I've trimmed that output here and gone straight to what mattered.

The `http-enum` and nikto scans against port 80 turned up the findings that actually drove the rest of the assessment:

```console
/phpmyadmin/: phpMyAdmin
/: WordPress version 4.8
/wp-content/uploads/: Directory indexing found  <-- browsable
Username found: notch
```

Browsing to `http://blocky.htb/phpmyadmin/` confirmed a live phpMyAdmin instance sitting alongside the WordPress install, which meant credentials for one service could plausibly unlock the other further down the line. I ran WPScan's `http-wordpress-users` enumeration against the WordPress side next, and it identified a single author account: **`notch`**.

```console
[+] notch
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

With the username in hand, I went looking for anywhere I could pull down more than just a name. Navigating to `http://blocky.htb/plugins/` turned up an open directory listing exposing two Minecraft server plugin jars sitting in the clear: `BlockyCore.jar` and `griefprevention-..jar`. The first one immediately stood out to me. It's a custom, project-specific name rather than a well-known public plugin, which usually means it was written in-house and is far more likely to contain something the developer never meant to publish.

<div class="callout callout-note">

**Directory listing is an information-disclosure vuln**

This is `Options +Indexes` at work, whether explicitly set or left over from a default Apache vhost, and it turns any directory lacking an index file into a browsable file listing. On a WordPress install I always check the same handful of spots for this: `/wp-content/uploads/`, `/wp-content/plugins/`, and `/wp-content/backups/`, since that's where developers tend to drop things temporarily and forget about them. Here it exposed a custom, purpose-built plugin that was never meant to be publicly downloadable. I ran into the exact same primitive on [Backdoor](/writeups/hackthebox/linux/easy/backdoor/), where a different misconfiguration exposed `wp-config.php` instead.

</div>

### Decompile the jar

Since I hadn't decompiled a Java plugin before, I spent a few minutes reading up on the tooling before diving in. Once I had a feel for it, I pulled `BlockyCore.jar` down from the plugins directory and opened it in **jd-gui**, a graphical Java decompiler, to see exactly what the developer had shipped inside it.

```bash
jd-gui BlockyCore.jar
```

```java
package com.myfirstplugin;

public class BlockyCore {
  public String sqlHost = "localhost";
  public String sqlUser = "root";
  public String sqlPass = "8YsqfCTnvxAUeduzjNSXe22";

  public void onServerStart() {}
  public void onServerStop() {}
  public void onPlayerJoin() {
    sendMessage("TODO get username", "Welcome to the BlockyCraft!!!!!!!");
  }
  public void sendMessage(String username, String message) {}
}
```

<div class="callout callout-note">

**Why `.jar` secrets always come back**

The reason this works so reliably is structural, not incidental. A `.jar` file is just a zip archive of `.class` files, and Java bytecode preserves field names, method signatures, string constants, and usually even local-variable tables. That's more than enough for decompilers like **jd-gui**, **CFR**, **procyon**, or **Fernflower** to reconstruct source that reads almost exactly like what the developer originally typed. If I'd wanted to skip the GUI entirely, `unzip -o BlockyCore.jar && strings **/*.class | grep -i pass` would have surfaced the same password just as fast. The same weakness carries over to .NET assemblies (crackable with dnSpy or ILSpy), Android APKs (jadx), and Electron desktop apps (`asar extract`). The takeaway I keep coming back to on every engagement: never ship a credential inside client-distributable code, full stop.

</div>

### phpMyAdmin → confirm `notch`

With a MySQL root password in hand, logging into the phpMyAdmin panel I'd spotted earlier was the obvious next move.

```
http://blocky.htb/phpmyadmin/sql.php?db=wordpress&table=wp_users
```

Querying the `wp_users` table this way surfaced the account `notch` along with its password hash. Cracking that WordPress hash was one option, but I already had a faster route available: try the recovered SQL password as this same user's system password.

### Password reuse → SSH → user

```console
❯ ssh notch@blocky.htb
notch@blocky.htb's password:
Welcome to Ubuntu 16.04.2 LTS
notch@Blocky:~$
```

we are also able to ssh into `notch` with the same password ;3. Wqe are already user.

<div class="callout callout-note">

**Credential reuse**

The MySQL `root` password was reused as `notch`'s **Linux** password. This is the single highest-yield assumption in a lab: any secret you recover, try it as an SSH/`su` password for every username you know. Real engagements are the same: one leaked service password unlocks a domain account remarkably often.

</div>

### Privilege Escalation. Unrestricted sudo

```console
notch@Blocky:~$ sudo -l
User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
notch@Blocky:~$ sudo su
root@Blocky:/home/notch#
```

bruh... `sudo su` and you're root.

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/notch/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons & Takeaways

- **Compiled ≠ secret.** Jars, DLLs, APKs, Electron bundles all decompile. Keep credentials server-side and inject them at runtime from a vault.
- **Disable directory indexing** globally (`Options -Indexes`) and drop an `index.html` in every asset dir.
- **Unique passwords per service and per account.** A DB password should never be a login password.
- **`sudo` should be scoped.** `(ALL) ALL` on a user account defeats the point of not logging in as root.
- Old but exposed: ProFTPD 1.3.5a here is vulnerable to `mod_copy` (CVE-2015-3306). An alternative foothold if the jar route were closed.

---

## Related Writeups

- **Secrets in a downloadable artifact:** [Backdoor](/writeups/hackthebox/linux/easy/backdoor/), [Cat](/writeups/hackthebox/linux/medium/cat/)
- **Password reuse to `root`:** [Dog](/writeups/hackthebox/linux/easy/dog/), [Cat](/writeups/hackthebox/linux/medium/cat/), [Smol](/writeups/tryhackme/linux/medium/smol/), [Bizness](/writeups/hackthebox/linux/easy/bizness/)
- **WordPress footholds:** [Backdoor](/writeups/hackthebox/linux/easy/backdoor/), [Smol](/writeups/tryhackme/linux/medium/smol/), [Avenger](/writeups/tryhackme/windows/medium/avenger/)
- **Directory listing disclosure:** [Backdoor](/writeups/hackthebox/linux/easy/backdoor/)

## References

- jd-gui <https://github.com/java-decompiler/jd-gui>
- CFR decompiler <https://www.benf.org/other/cfr/>
- ProFTPD mod_copy CVE-2015-3306 <https://nvd.nist.gov/vuln/detail/CVE-2015-3306>
