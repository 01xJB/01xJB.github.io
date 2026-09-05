---
title: "Armageddon"
type: docs
tags:
  - thm
  - linux
  - insane
---

<div class="callout callout-warning">

**🚧 Work in Progress**: This writeup is marked **partial** in my notes: the attack chain below may stop short of a full root/completion.

</div>

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Linux, **Difficulty:** Insane

</div>

<div class="callout callout-warning">

**Partial**

Recon only, directory enumeration was in progress when these notes stop.

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
