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

Blocky is one of the original HTB boxes and still the canonical example of **"credentials in a compiled artifact"**. A Java `.jar` is just a zip of `.class` bytecode; bytecode decompiles cleanly back to near-original source, so any secret a developer hard-codes in a plugin/agent/app is trivially recoverable once you can download the file. The rest is **password reuse** (dev used the same string for MySQL and their Linux account) and a throwaway `sudo ALL` misconfiguration. Total path: download → decompile → reuse → `sudo su`.

Related "secrets in a downloadable file" boxes: [Backdoor](/writeups/hackthebox/linux/easy/backdoor/) (`wp-config.php` via traversal), [Cat](/writeups/hackthebox/linux/medium/cat/) (`.git` source). Related password-reuse-to-root: [Dog](/writeups/hackthebox/linux/easy/dog/), [Cat](/writeups/hackthebox/linux/medium/cat/), [Smol](/writeups/tryhackme/linux/medium/smol/). Related unrestricted-`sudo` finish: [Blocky](/writeups/hackthebox/linux/easy/blocky/) itself is the textbook case.

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

(`nmap --script vulners` dumped ~200 lines of CVE references for the old SSH/Apache builds. None are the path; trimmed.)

`http-enum` / nikto findings that matter:

```console
/phpmyadmin/: phpMyAdmin
/: WordPress version 4.8
/wp-content/uploads/: Directory indexing found  <-- browsable
Username found: notch
```

`http://blocky.htb/phpmyadmin/`. Seems to be running phpMyAdmin. WPScan / `http-wordpress-users` identifies one author: **`notch`**.

```console
[+] notch
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

`http://blocky.htb/plugins/`. There seems to be plugins here (directory listing), containing `BlockyCore.jar` and `griefprevention-..jar`.

<div class="callout callout-note">

**Directory listing is an information-disclosure vuln**

`Options +Indexes` (or the default on a fresh Apache vhost) makes any directory without an index file render as a file browser. On a WordPress box the interesting spots are `/wp-content/uploads/`, `/wp-content/plugins/`, `/wp-content/backups/`. Here it exposes a *custom* plugin nobody was meant to download. Same primitive on [Backdoor](/writeups/hackthebox/linux/easy/backdoor/).

</div>

### Decompile the jar

so we did some research about decompiling java files. we went to the plugins page on the website, downloaded the `BlockyCore.jar`, and used **jd-gui** to see what's in it ;3

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

A `.jar` is a zip archive of `.class` files. Java bytecode keeps field names, method signatures, string constants and (usually) local-variable tables, so decompilers like **jd-gui**, **CFR**, **procyon** or **Fernflower** reproduce readable source. `unzip -o BlockyCore.jar && strings **/*.class | grep -i pass` finds it even faster. The same is true of.NET assemblies (dnSpy/ILSpy), Android APKs (jadx), and Electron apps (`asar extract`). **Never ship a credential in client-distributable code.**

</div>

### phpMyAdmin → confirm `notch`

we are able to log into the phpMyAdmin page using the creds above.

```
http://blocky.htb/phpmyadmin/sql.php?db=wordpress&table=wp_users
```

here we can see the user `notch` and his password hash. (You could crack the WP hash, but there's a shorter path.)

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
