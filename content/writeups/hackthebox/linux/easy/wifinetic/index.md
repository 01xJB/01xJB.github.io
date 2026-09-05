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

Wifinetic is a themed box that actually teaches something niche and useful: **Wi-Fi attacks against a simulated radio**. The Linux kernel's `mac80211_hwsim` module creates virtual wireless interfaces that behave like real hardware, including a real WPS handshake, so you can practise `reaver` and `wifite` without a card. The path is otherwise about **config file secrets** (OpenWrt keeps plaintext PSKs and the rpcd password on disk) and **capability abuse** (`reaver` with `cap_net_raw` lets an unprivileged user put an interface into monitor mode and inject frames). The recurring lesson is that everyone reuses the Wi-Fi password.

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

Download everything. The tar is a config backup:

```bash
tar xf backup-OpenWrt-2023-07-26.tar
```

`etc/config/rpcd` holds a placeholder password (`$p$root`, which just means "hash of the `root` account", not a literal), but `etc/config/wireless` is the prize:

```
config wifi-iface 'wifinet0'
	option mode 'ap'
	option ssid 'OpenWrt'
	option encryption 'psk'
	option key 'VeRyUniUqWiFIPasswrd1!'
	option wps_pushbutton '1'
```

`etc/passwd` lists `netadmin`. Password reuse:

```bash
ssh netadmin@10.10.11.247        # VeRyUniUqWiFIPasswrd1!
```

<div class="callout callout-note">

**Why OpenWrt configs are gold**

OpenWrt (and most consumer router firmware) stores WPA PSKs, the admin password hash, VPN keys, and port-forward rules as plaintext UCI config under `/etc/config/`. A backup tarball from FTP, a `.git` of the firmware, or an LFI to `/etc/config/wireless` all give the same thing. And the Wi-Fi password is almost always reused for at least one account.

</div>

### Privilege Escalation, WPS PIN attack

```console
netadmin@wifinetic:~$ getcap -r / 2>/dev/null
/usr/bin/reaver = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
...
```

`iw dev` shows several `mac80211_hwsim` interfaces: `wlan0` (AP `OpenWrt`), `wlan1`, `mon0`.

<div class="callout callout-note">

**WPS and why the PIN falls in seconds**

WPS (Wi-Fi Protected Setup) lets a client join by entering an 8-digit PIN instead of the passphrase. The protocol checks the PIN in two halves (first 4 digits, then 3, with the 8th a checksum), so the brute force space is only 10^4 + 10^3 = 11000, not 10^8. On a box with `wps_pushbutton` enabled and no lockout, `reaver` walks it in seconds, and once WPS authenticates it hands back the **actual WPA PSK** in the M7 message. `reaver` needs `cap_net_raw` (monitor mode + frame injection), which the box has kindly granted to `netadmin`.

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

That PSK is `root`'s password:

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

- **Anonymous FTP is almost never intentional.** Disable it, and never expose config backups over it.
- **Router configs are plaintext secret stores.** Treat a firmware backup like a password vault.
- **Disable WPS.** The PIN method is broken by design (split verification) and Pixie Dust makes many APs instant. Push-button is only marginally better.
- **`cap_net_raw` on a tool like `reaver` is a privilege.** Capabilities are not "sudo-lite"; audit `getcap -r /` on every box.
- **Never reuse the Wi-Fi passphrase for a login account**, especially not for root.

---

## Related Writeups

- **Config file / backup secrets:** [Blocky](/writeups/hackthebox/linux/easy/blocky/), [Backdoor](/writeups/hackthebox/linux/easy/backdoor/)
- **Linux capabilities abuse:** [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/), [Antique](/writeups/hackthebox/linux/easy/antique/)
- **Password reuse to root:** [Blocky](/writeups/hackthebox/linux/easy/blocky/), [Cat](/writeups/hackthebox/linux/medium/cat/), [Dog](/writeups/hackthebox/linux/easy/dog/)

## References

- reaver-wps-fork-t6x <https://github.com/t6x/reaver-wps-fork-t6x>
- mac80211_hwsim <https://www.kernel.org/doc/html/latest/networking/mac80211_hwsim/mac80211_hwsim.html>
- WPS PIN brute force (Viehbock, 2011) <https://sviehb.files.wordpress.com/2011/12/viehboeck_wps.pdf>
