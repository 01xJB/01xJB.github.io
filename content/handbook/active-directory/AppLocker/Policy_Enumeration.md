---
title: "AppLocker Policy Enumeration"
date: 2026-09-25
weight: 3
type: docs
tags:
  - AppLocker
  - Application Control
  - Bypass
  - Active Directory
  - Applocker Enumeration
---

AppLocker configuration can be reviewed from the endpoint registry or from the Group Policy Object (GPO) that deploys it. Endpoint inspection shows the policy data available on that computer; GPO inspection helps identify the centrally managed settings and their scope. Compare both views when assessing enforcement, because local state and domain policy can differ.

Policy enumeration is a necessary first step when evaluating whether application control is configured as intended and identifying rule gaps that require further review. Use read-only collection on approved endpoints and policy locations.

## Inspect the endpoint registry

Use this approach when you have authorized local access to an endpoint protected by AppLocker. Policy data is stored beneath `HKLM\Software\Policies\Microsoft\Windows\SrpV2`, with a subkey for each rule collection. Rule values are stored as XML strings, which can be read directly from the registry.

List the configured collections:

```powershell
PS C:\Users\review.user> Get-ChildItem 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2'

    Hive: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2

Name                           Property
----                           --------
Appx                           EnforcementMode : 1
                               AllowWindows    : 0
Dll                            AllowWindows : 0
Exe                            EnforcementMode : 1
                               AllowWindows    : 0
Msi                            EnforcementMode : 1
                               AllowWindows    : 0
Script                         EnforcementMode : 1
                               AllowWindows    : 0
```

The collection names identify packaged apps (`Appx`), DLLs, executables (`Exe`), Windows Installer files (`Msi`), and scripts. Review the collection's enforcement mode along with its rules; a rule's presence alone does not tell you whether the collection is enforcing or auditing policy.

Inspect the executable rules:

```powershell
PS C:\Users\review.user> Get-ChildItem 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe'

    Hive: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2\Exe

Name                           Property
----                           --------
921cc481-6e17-4653-8f75-050b80 Value : <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="(Default Rule)
acca20                         All files located in the Program
                                       Files folder" Description="Allows members of the Everyone group to run
                               applications that are located in the
                                       Program Files folder." UserOrGroupSid="S-1-1-0"
                               Action="Allow"><Conditions><FilePathCondition
                                       Path="%PROGRAMFILES%\*"/></Conditions></FilePathRule>
a61c8b2c-a319-4cd0-9690-d2177c Value : <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="(Default Rule)
ad7b51                         All files located in the Windows
                                       folder" Description="Allows members of the Everyone group to run applications
                               that are located in the Windows
                                       folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition
                                       Path="%WINDIR%\*"/></Conditions></FilePathRule>
```

The `Value` field contains the rule as XML. In this example, the built-in path rules allow Everyone to run files from the Program Files and Windows directories. Continue by reviewing every rule in each relevant collection, including its action, target SID, condition, and exceptions.

### Read the effective policy with the AppLocker cmdlet

The native `Get-AppLockerPolicy` cmdlet parses policy rules into objects that are easier to inspect than raw XML. The `-Effective` option retrieves the effective Group Policy-deployed policy on the current computer:

```powershell
PS C:\Users\review.user> $policy = Get-AppLockerPolicy -Effective
PS C:\Users\review.user> $policy.RuleCollections

PathConditions      : {%PROGRAMFILES%\*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 921cc481-6e17-4653-8f75-050b80acca20
Name                : (Default Rule) All files located in the Program Files folder
Description         : Allows members of the Everyone group to run applications that are located in the Program Files
                      folder.
UserOrGroupSid      : S-1-1-0
Action              : Allow
```

Review the condition, exceptions, principal, and action together. For example, an `Allow` rule scoped to a broad group has a different effect from a publisher rule scoped to a smaller group. `Get-AppLockerPolicy` reports policies deployed through Group Policy; if the environment deploys application control through the AppLocker CSP, use the corresponding management view as well. See Microsoft's [Get-AppLockerPolicy reference](https://learn.microsoft.com/en-us/powershell/module/applocker/get-applockerpolicy?view=windowsserver2025-ps) for supported options and behavior.

## Inspect the GPO and its policy file

GPO review is useful when assessing which centrally managed AppLocker policy applies to a target endpoint. From an authorized directory session, enumerate Group Policy container objects and use their display names and file paths to identify candidate policies. Then confirm the target computer's OU, inheritance, link state, and filtering before attributing a GPO to that endpoint.

When you have an approved Beacon on an in-scope system, a bounded LDAP query can locate the directory-side GPO objects:

```text
beacon> ldapsearch "(objectClass=groupPolicyContainer)" --attributes displayName,gPCFileSysPath --count 50 --hostname NW-AD-01.northwind.example --dn DC=northwind,DC=example

--------------------
displayName: Endpoint Application Control
gPCFileSysPath: \\LAB.EXAMPLE\SysVol\LAB.EXAMPLE\Policies\{6F3A8C21-29BE-4D40-BA16-67C1C79F51D2}
--------------------
```

The LDAP result identifies the GPO name and its SYSVOL location. Alternatively, review policy directories under the domain's SYSVOL share and look for `Registry.pol` in the `Machine` directory:

```text
beacon> ls \\LAB.EXAMPLE\SysVol\LAB.EXAMPLE\Policies\{6F3A8C21-29BE-4D40-BA16-67C1C79F51D2}\Machine

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     03/29/2025 10:47:29   Microsoft
          dir     03/29/2025 10:47:27   Scripts
 8kb      fil     03/29/2025 10:48:02   Registry.pol
```

Copy the policy file to the approved analysis workstation for offline inspection:

```text
beacon> download \\LAB.EXAMPLE\SysVol\LAB.EXAMPLE\Policies\{6F3A8C21-29BE-4D40-BA16-67C1C79F51D2}\Machine\Registry.pol
[*] started download of \\LAB.EXAMPLE\SysVol\LAB.EXAMPLE\Policies\{6F3A8C21-29BE-4D40-BA16-67C1C79F51D2}\Machine\Registry.pol (8216 bytes)
[*] download of Registry.pol is complete
```

Treat SYSVOL policy data as configuration evidence. Preserve the GPO name, GUID, source path, collection time, and file hash with the assessment record. Avoid changing the policy file during analysis.

### Parse `Registry.pol` offline

The `Parse-PolFile` cmdlet from the [GpRegistryPolicy module](https://www.powershellgallery.com/packages/GPRegistryPolicy/0.3) can decode a local policy file into its registry key, value name, type, and data. Use a reviewed copy of the module on the analysis workstation:

```powershell
PS C:\Users\review.user> Parse-PolFile -Path .\Desktop\Registry.pol

KeyName     : Software\Policies\Microsoft\Windows\SrpV2\Exe\921cc481-6e17-4653-8f75-050b80acca20
ValueName   : Value
ValueType   : REG_SZ
ValueLength : 736
ValueData   : <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="(Default Rule) All files located in the
              Program Files folder" Description="Allows members of the Everyone group to run applications that are
              located in the Program Files folder." UserOrGroupSid="S-1-1-0"
              Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*"/></Conditions></FilePathRule>
```

The parsed entry corresponds to an executable-collection path rule. Compare it with the endpoint's effective policy and the GPO scope to identify differences between centrally configured and locally applied settings.
