---
title: "Wifinetic"
date: 2023-09-30
type: docs
tags:
  - htb
  - linux
  - easy
  - anonymous-ftp
  - openwrt
  - config-secrets
  - password-reuse
  - wifi
  - wps
  - reaver
  - capabilities
  - mac80211-hwsim
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 20.04), **Difficulty:** Easy, **Released:** 2023-09-30, **IP:** `10.10.11.247`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. **Anonymous FTP** exposes an OpenWrt backup tarball.
2. `backup-OpenWrt-*.tar` contains `etc/config/wireless` with the WPA key `VeRyUniUqWiFIPasswrd1!`, and `etc/passwd` lists user **`netadmin`**. Password reuse gets SSH as `netadmin`.
3. `netadmin` can run **`reaver`** (it carries `cap_net_raw`) against the box's own simulated access point (`mac80211_hwsim`). A **WPS PIN attack** recovers the real WPA PSK, `WhatIsRealAnDWhAtIsNot51121!`, which is also **root**'s password.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| OpenWrt `wireless` config | `VeRyUniUqWiFIPasswrd1!` (reused for `netadmin`) |
| WPS/WPA PSK from reaver | `WhatIsRealAnDWhAtIsNot51121!` (reused for `root`) |
| `user.txt` | `/home/netadmin/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Wifinetic stood out to me as one of those boxes that teaches something genuinely niche: real Wi-Fi attack tradecraft against a fully simulated radio. I hadn't touched `reaver` in a while going into this one, and I was curious whether the techniques would even translate cleanly to a virtual environment, so this ended up being as much a refresher on WPS internals as it was a normal box. The Linux kernel's `mac80211_hwsim` module creates virtual wireless interfaces that behave exactly like real hardware, right down to producing a genuine WPS handshake, which meant I could run `reaver` (and, in principle, `wifite`) against it exactly as I would with a physical adapter and a live access point in front of me. Everything leading up to that point was really about config file hygiene: OpenWrt, like most consumer router firmware, keeps WPA PSKs, admin password hashes, and other secrets sitting in plaintext UCI config files, so the moment I had a backup tarball in hand, the box had effectively handed me a foothold already. The thread running through the whole chain, and honestly through a lot of real Wi-Fi security assessments I've worked, is that people reuse the Wi-Fi password everywhere: for admin logins, for other services, and here, all the way up to root.

Related config-secret boxes: [Blocky](/writeups/hackthebox/linux/easy/blocky/), [Backdoor](/writeups/hackthebox/linux/easy/backdoor/). Related capability abuse: [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/) (capsh). Related password reuse to root: [Blocky](/writeups/hackthebox/linux/easy/blocky/), [Cat](/writeups/hackthebox/linux/medium/cat/).

---

## Full Walkthrough

### Nmap scan

```console
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r-- 1 ftp ftp    40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
| -rw-r--r-- 1 ftp ftp     4434 Jul 31  2023 MigrateOpenWrt.txt
| ... several PDFs
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9
53/tcp open  domain
```

### Anonymous FTP, OpenWrt backup

Anonymous FTP jumped out at me right away in the scan results, since `ftp-anon` succeeding almost never happens on a properly hardened box, and the file listing had exactly the kind of thing I was hoping for: a backup tarball. I grabbed the whole directory rather than cherry-picking files, since with OpenWrt backups I've learned you often don't know which config file has the interesting detail until everything is extracted:

```bash
tar xf backup-OpenWrt-2023-07-26.tar
```

Working through the extracted files, I checked `etc/config/rpcd` first, since that's normally where OpenWrt stores the RPC daemon's authentication setup, but the password field there turned out to be just a placeholder token, `$p$root`, which simply means "the hash currently set for the `root` account" rather than an actual credential I could use. The real prize was sitting in `etc/config/wireless`:

```
config wifi-iface 'wifinet0'
	option mode 'ap'
	option ssid 'OpenWrt'
	option encryption 'psk'
	option key 'VeRyUniUqWiFIPasswrd1!'
	option wps_pushbutton '1'
```

A quick check of `etc/passwd` from the same backup showed a non-default account, `netadmin`, and given how often a Wi-Fi password ends up reused as a login credential, that was the very first thing I tried:

```bash
ssh netadmin@10.10.11.247        # VeRyUniUqWiFIPasswrd1!
```

<div class="callout callout-note">

**Why OpenWrt configs are gold**

This is a pattern I actively look for whenever a target is running OpenWrt or similar consumer router firmware: WPA PSKs, the admin password hash, VPN keys, and port-forward rules all live as plaintext UCI configuration under `/etc/config/`, with nothing encrypting them at rest. It doesn't matter how I end up reading that directory, whether it's a backup tarball sitting on an anonymous FTP share like this one, a leaked `.git` folder from a firmware build, or a local file inclusion that reads `/etc/config/wireless` directly. The result is the same either way: full visibility into every credential the router holds. And in my experience, the Wi-Fi password is almost always reused somewhere else on the network, which is exactly what turned this into a working foothold.

</div>

### Privilege Escalation, WPS PIN attack

Once I had a shell as `netadmin`, my usual next move on any Linux box is checking for interesting file capabilities before I even look at SUID binaries, since capabilities get audited far less often and tend to hide in plain sight:

```console
netadmin@wifinetic:~$ getcap -r / 2>/dev/null
/usr/bin/reaver = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
...
```

`reaver` carrying `cap_net_raw` told me immediately that this box wanted me to attack Wi-Fi directly from inside it, so I ran `iw dev` to see what wireless interfaces were actually on offer, and found several `mac80211_hwsim` virtual interfaces already configured: `wlan0` running as the access point advertising the `OpenWrt` SSID, plus `wlan1` and a monitor-mode interface, `mon0`, sitting ready to use.

<div class="callout callout-note">

**WPS and why the PIN falls in seconds**

This is where knowing the protocol internals pays off instead of just pointing a tool at a target and hoping. WPS (Wi-Fi Protected Setup) is supposed to let a client join a network by entering an 8-digit PIN instead of the full passphrase, but the implementation has carried a design flaw publicly known since 2011: the access point validates that PIN in two separate halves, the first four digits and then the last three (the eighth digit is just a checksum), rather than validating all eight digits as one unit. That mistake collapses a search space of 10^8 possible PINs into two much smaller searches of 10^4 and 10^3, adding up to only 11,000 guesses total. With `wps_pushbutton` enabled and no lockout policy to slow down repeated failures, `reaver` chews through that in seconds, and the payoff is bigger than simply authenticating: once WPS succeeds, the access point hands back the **actual WPA PSK** inside the M7 message of the exchange, so I get the real Wi-Fi password rather than just a session. The only thing standing between `netadmin` and this attack is `cap_net_raw`, which grants monitor mode and raw frame injection without needing full root, and the box had already handed that capability to `reaver` for me.

</div>

```bash
reaver -i mon0 -b 02:00:00:00:00:00 -vv -c 36
```

```console
[+] Pin cracked in 2 seconds
[+] WPS PIN: '12345670'
[+] WPA PSK: 'WhatIsRealAnDWhAtIsNot51121!'
[+] AP SSID: 'OpenWrt'
```

Sure enough, the recovered PSK turned out to double as `root`'s login password, the exact same reuse pattern that got me onto the box in the first place, just one privilege level higher:

```bash
su root        # WhatIsRealAnDWhAtIsNot51121!
cat /root/root.txt
```

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/netadmin/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **Anonymous FTP is almost never intentional, and it's one of the first things I check for on any scan.** Disable it outright unless there's a specific, documented business reason, and even then, never let it serve anything beyond public, non-sensitive files. Here it handed me a full firmware backup with zero authentication required.
- **Router and IoT device configs are plaintext secret stores.** Treat a firmware backup, whether pulled from FTP, a `.git` directory, or an LFI, exactly like you'd treat a password vault, because functionally that's what it is. If a backup has to leave the device at all, encrypt it and strip credentials first.
- **Disable WPS entirely rather than trying to configure it safely.** The PIN method is broken by design because of that split verification, and Pixie Dust attacks make many access points fall almost instantly regardless of push-button versus PIN mode. There's no hardened configuration of WPS, only a slower path to the same outcome.
- **A file capability is not "sudo-lite," it's a scoped grant of real power.** `cap_net_raw` on `reaver` alone was enough to put an interface into monitor mode and inject raw frames without any other privilege. I run `getcap -r /` on every Linux box now for exactly this reason, right alongside the usual SUID hunt.
- **Never reuse a Wi-Fi passphrase for a login account, and never reuse it for root above all else.** This box chained two instances of the exact same mistake to go from anonymous FTP straight to root, and neither step required anything more advanced than pattern recognition.

---

## Related Writeups

- **Config file / backup secrets:** [Blocky](/writeups/hackthebox/linux/easy/blocky/), [Backdoor](/writeups/hackthebox/linux/easy/backdoor/)
- **Linux capabilities abuse:** [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/), [Antique](/writeups/hackthebox/linux/easy/antique/)
- **Password reuse to root:** [Blocky](/writeups/hackthebox/linux/easy/blocky/), [Cat](/writeups/hackthebox/linux/medium/cat/), [Dog](/writeups/hackthebox/linux/easy/dog/)

## References

- reaver-wps-fork-t6x <https://github.com/t6x/reaver-wps-fork-t6x>
- mac80211_hwsim <https://www.kernel.org/doc/html/latest/networking/mac80211_hwsim/mac80211_hwsim.html>
- WPS PIN brute force (Viehbock, 2011) <https://sviehb.files.wordpress.com/2011/12/viehboeck_wps.pdf>
