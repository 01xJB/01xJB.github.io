---
title: "Active Directory Discovery and Enumeration"
date: 2026-09-25
weight: 1
type: docs
tags:
  - Active Directory
  - Enumeration
  - Identity Security
---

Active Directory enumeration turns directory data into a scoped map of identities, systems, policy, and relationships. A good assessment does not begin by collecting every object. It begins with a question, gathers the minimum evidence needed to answer it, and verifies each important relationship against the directory or the system that enforces it.

This walkthrough uses the sample domain `northwind.example`. The commands are read only directory queries intended for an authorized lab or engagement. Replace the domain controller, search base, and output path with values approved for the environment.

> [!IMPORTANT]
> Confirm the authorized domain, account, collection methods, rate limits, evidence location, and stop conditions before running queries. Directory reads can still generate security telemetry and expose sensitive organizational relationships.

## 1. Define the collection boundary

Write down the domain and the exact systems in scope. Identify a designated domain controller so that repeated queries use a consistent source. Confirm whether the client permits endpoint group membership collection, session collection, certificate services data, or only LDAP reads. Those methods have different network reach and sensitivity.

Use variables to make the boundary visible in the commands. The sample values below are placeholders, not real infrastructure.

```powershell
$Domain = 'northwind.example'
$Server = 'NW-AD-01.northwind.example'
$SearchBase = 'DC=northwind,DC=example'
$EvidencePath = 'C:\Assessment\Evidence\AD-Discovery'

New-Item -ItemType Directory -Path $EvidencePath -Force | Out-Null
Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'
whoami
```

Example output:

```text
2026-09-25 10:14:22 -04:00
northwind\analyst01
```

Record the operator identity, collection host, domain controller, start time, and approval reference in the activity log. Do not put passwords, ticket material, private keys, or client data in that log.

## 2. Confirm the PowerShell tools and directory context

The Microsoft Active Directory module is available through RSAT on supported Windows systems. Check that it is installed before attempting queries. The domain account used for collection should have only the access approved for the engagement.

```powershell
Get-Module -ListAvailable ActiveDirectory |
  Select-Object Name, Version, Path

Import-Module ActiveDirectory

Get-ADRootDSE -Server $Server |
  Select-Object defaultNamingContext, configurationNamingContext, dnsHostName
```

Example output:

```text
Name            Version Path
----            ------- ----
ActiveDirectory 1.0.1.0 C:\Windows\System32\WindowsPowerShell\v1.0\Modules\ActiveDirectory

defaultNamingContext     : DC=northwind,DC=example
configurationNamingContext : CN=Configuration,DC=northwind,DC=example
dnsHostName              : NW-AD-01.northwind.example
```

The root DSE confirms which naming contexts and server answered. If the domain controller is not the approved one, stop and correct the target before collecting more data. Do not work around access failures by switching to another domain, account, or protocol without approval.

## 3. Capture the domain and forest baseline

Record the domain mode, forest relationships, and available domain controllers. These facts help explain later findings and make the collection reproducible.

```powershell
Get-ADDomain -Server $Server |
  Select-Object DNSRoot, NetBIOSName, DomainMode, PDCEmulator

Get-ADForest -Server $Server |
  Select-Object Name, ForestMode, RootDomain, Domains, GlobalCatalogs

Get-ADDomainController -Filter * -Server $Server |
  Select-Object HostName, Site, IsGlobalCatalog, OperatingSystem
```

Example output:

```text
DNSRoot     : northwind.example
NetBIOSName : NORTHWIND
DomainMode  : Windows2016Domain
PDCEmulator : NW-AD-01.northwind.example

Name       : northwind.example
ForestMode : Windows2016Forest
RootDomain : northwind.example
Domains    : {northwind.example, eu.northwind.example}
```

Do not assume every listed forest domain is in scope. A forest relationship is useful context, not authorization to query or test every connected domain.

## 4. Inventory users with a bounded attribute set

Start with account identifiers, enabled state, organizational context, and group membership. Avoid `-Properties *` in a broad query. It returns far more information than most discovery questions require and makes review, evidence handling, and troubleshooting harder.

```powershell
Get-ADUser -Server $Server `
  -SearchBase $SearchBase `
  -Filter 'Enabled -eq $true' `
  -Properties Department, Title, MemberOf, ServicePrincipalName, LastLogonDate |
  Select-Object SamAccountName, Department, Title, LastLogonDate,
    @{Name='SPNCount'; Expression={ @($_.ServicePrincipalName).Count }} |
  Sort-Object Department, SamAccountName |
  Tee-Object -Variable UserInventory |
  Format-Table -AutoSize

"Enabled user records returned: $($UserInventory.Count)"
```

Example output:

```text
SamAccountName Department     Title                 LastLogonDate        SPNCount
-------------- ----------     -----                 -------------        --------
analyst01      IT Operations  Systems Analyst       9/24/2026 4:18:03 PM         0
svc_app01      Infrastructure Application Service   9/25/2026 8:02:11 AM         2
svc_batch01    Finance        Batch Service         9/24/2026 7:43:55 PM         1
Enabled user records returned: 3
```

The sample is intentionally small. In a real directory, apply an approved OU search base, filter, or paging strategy where appropriate. Treat SPNs as configuration data. Their presence alone does not establish a vulnerability, and this inventory does not request or expose password material.

For one account, query only the properties needed to validate a specific observation:

```powershell
Get-ADUser -Identity 'svc_app01' -Server $Server `
  -Properties Department, Description, ServicePrincipalName, MemberOf |
  Select-Object SamAccountName, Enabled, Department, Description,
    ServicePrincipalName, MemberOf
```

Descriptions and group names can contain sensitive business details. Keep output in the approved evidence store and redact unnecessary fields before sharing.

### OpenLDAP client alternative

From a Linux assessment host, the OpenLDAP `ldapsearch` client uses different syntax from the `ldapsearch` Beacon Object File described later. Use LDAPS with certificate validation and prompt for the password rather than placing it in shell history or process arguments.

```bash
ldapsearch -LLL -x \
  -H 'ldaps://NW-AD-01.northwind.example:636' \
  -D 'analyst01@northwind.example' -W \
  -b 'DC=northwind,DC=example' -z 10 \
  '(&(objectCategory=person)(objectClass=user))' \
  sAMAccountName department
```

Example output:

```text
dn: CN=Analyst 01,OU=Users,DC=northwind,DC=example
sAMAccountName: analyst01
department: IT Operations

dn: CN=Service App 01,OU=Service Accounts,DC=northwind,DC=example
sAMAccountName: svc_app01
department: Infrastructure
```

If the client requires Kerberos or SASL authentication, use its approved bind method. Do not downgrade transport security or disable certificate checking to make a query succeed. The `-z 10` limit requests a small result set; it does not replace an appropriate search base and filter.

## 5. Map privileged groups and nested membership

Choose groups that are relevant to the agreed assessment question. Recursively enumerate membership so that nested groups are visible. Group names can be localized or customized, so confirm the correct group object in the target domain before relying on a familiar label.

```powershell
$PrivilegedGroup = 'Domain Admins'

Get-ADGroup -Identity $PrivilegedGroup -Server $Server |
  Select-Object Name, SID, DistinguishedName, GroupScope, GroupCategory

Get-ADGroupMember -Identity $PrivilegedGroup -Server $Server |
  Select-Object Name, SamAccountName, ObjectClass, SID |
  Sort-Object ObjectClass, SamAccountName
```

Example output:

```text
Name             SamAccountName ObjectClass SID
----             -------------- ----------- ---
Identity Platform id-platform   group       S-1-5-21-111111111-222222222-333333333-2201
```

The direct result shows that the privileged group contains another group. Follow that edge explicitly so the report can show the actual path:

```powershell
Get-ADGroupMember -Identity 'id-platform' -Server $Server |
  Select-Object Name, SamAccountName, ObjectClass, SID
```

Example output:

```text
Name       SamAccountName ObjectClass SID
----       -------------- ----------- ---
Analyst 01 analyst01     user        S-1-5-21-111111111-222222222-333333333-1142
```

Avoid relying only on `-Recursive` when you need to document the intermediate groups, because it returns the nested leaf members without the full chain. An effective membership path may pass through several groups. Record each edge and confirm whether the account is enabled, whether the group is in the relevant administrative tier, and what systems that group can administer. A graph edge is a lead to validate, not proof that an application or host grants access.

For a named user, compare direct group membership with the recursive result:

```powershell
Get-ADPrincipalGroupMembership -Identity 'analyst01' -Server $Server |
  Select-Object Name, GroupScope, SID |
  Sort-Object Name
```

## 6. Inventory computers, organizational units, and policy links

Computer names and operating system attributes provide an initial directory inventory. They do not prove that a host is reachable, online, or still running that operating system. Corroborate important assets with the owner or an approved asset source.

```powershell
Get-ADComputer -Server $Server -SearchBase $SearchBase `
  -Filter 'Enabled -eq $true' `
  -Properties DNSHostName, OperatingSystem, OperatingSystemVersion, LastLogonDate |
  Select-Object Name, DNSHostName, OperatingSystem, OperatingSystemVersion, LastLogonDate |
  Sort-Object OperatingSystem, Name
```

Example output:

```text
Name        DNSHostName                    OperatingSystem       OperatingSystemVersion
----        -----------                    ---------------       ----------------------
APP-SRV-02  app-srv-02.northwind.example   Windows Server 2022    10.0 (20348)
NW-AD-01        nw-ad-01.northwind.example         Windows Server 2022    10.0 (20348)
WS-014      ws-014.northwind.example       Windows 11 Enterprise  10.0 (22631)
```

Next, review where policy is linked and which policy objects exist. A GPO link does not by itself prove that a setting applies to every computer in the OU. Security filtering, inheritance, enforced links, and WMI filters affect the result.

```powershell
$OUs = Get-ADOrganizationalUnit -Filter * -Server $Server `
  -SearchBase $SearchBase -Properties gPLink, gPOptions

$OUs | Select-Object Name, DistinguishedName, gPOptions, gPLink |
  Sort-Object DistinguishedName

Get-Module -ListAvailable GroupPolicy | Select-Object Name, Version
Import-Module GroupPolicy

Get-GPO -All -Domain $Domain |
  Select-Object DisplayName, Id, GpoStatus, ModificationTime |
  Sort-Object DisplayName
```

For an OU that is specifically in scope, inspect the effective inheritance view:

```powershell
Get-GPInheritance -Target 'OU=Member Servers,DC=northwind,DC=example' `
  -Domain $Domain |
  Select-Object -ExpandProperty GpoLinks |
  Select-Object DisplayName, Enabled, Enforced, Order
```

The Group Policy console and the target computer’s resultant policy are useful follow-up sources when application is disputed. Do not infer an exploitable setting from the existence of a GPO name alone.

## 7. Review service identities and delegation configuration

This phase identifies configuration that deserves owner review. It does not request service tickets for offline cracking, modify delegation, impersonate an account, or access a destination service.

```powershell
Get-ADUser -Server $Server -SearchBase $SearchBase `
  -Filter 'ServicePrincipalName -like "*"' `
  -Properties ServicePrincipalName, Enabled, PasswordLastSet, ManagedBy |
  Select-Object SamAccountName, Enabled, ManagedBy, PasswordLastSet,
    @{Name='SPNs'; Expression={$_.ServicePrincipalName -join '; '}} |
  Sort-Object SamAccountName
```

Review delegation flags as separate configuration types. Verify the attributes against Microsoft documentation and with the service owner before concluding that the setting is unnecessary.

```powershell
Get-ADComputer -Server $Server -SearchBase $SearchBase -Filter * `
  -Properties TrustedForDelegation, TrustedToAuthForDelegation,
    'msDS-AllowedToDelegateTo', PrincipalsAllowedToDelegateToAccount |
  Where-Object {
    $_.TrustedForDelegation -or $_.TrustedToAuthForDelegation -or
    $_.'msDS-AllowedToDelegateTo' -or $_.PrincipalsAllowedToDelegateToAccount
  } |
  Select-Object Name, TrustedForDelegation, TrustedToAuthForDelegation,
    @{Name='AllowedServices'; Expression={$_.'msDS-AllowedToDelegateTo'}},
    PrincipalsAllowedToDelegateToAccount
```

If a property is not returned, confirm that the attribute is valid for that object class and query the designated controller. Do not silently treat an empty result as proof that no delegation exists.

## Beacon LDAP quick run

When a Beacon is already authorized for directory discovery, the reviewed TrustedSec `ldapsearch` BOF can query a small set of attributes without switching to a PowerShell workflow. Confirm the BOF's source and version, use the approved domain controller and base DN, and set a result limit for each query.

```text
beacon> ldapsearch "(&(objectCategory=person)(objectClass=user))" --attributes sAMAccountName,department,memberOf --count 20 --hostname NW-AD-01.northwind.example --dn DC=northwind,DC=example
```

Example output:

```text
Entries returned: 2
sAMAccountName: analyst01
department: Security Operations
memberOf: CN=Assessment Readers,OU=Groups,DC=northwind,DC=example

sAMAccountName: svc_app01
department: Platform Services
memberOf: CN=Application Operators,OU=Groups,DC=northwind,DC=example
```

Query computers and service identities separately so the result is easy to validate:

```text
beacon> ldapsearch "(&(objectCategory=computer)(operatingSystem=Windows Server*))" --attributes sAMAccountName,dNSHostName,operatingSystem --count 20 --hostname NW-AD-01.northwind.example --dn DC=northwind,DC=example
beacon> ldapsearch "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" --attributes sAMAccountName,servicePrincipalName --count 20 --hostname NW-AD-01.northwind.example --dn DC=northwind,DC=example
beacon> ldapsearch "(&(objectCategory=group)(cn=Domain Admins))" --attributes cn,member --count 5 --hostname NW-AD-01.northwind.example --dn DC=northwind,DC=example
```

Sample result shape:

```text
sAMAccountName: APP-SRV-02$
dNSHostName: app-srv-02.northwind.example
operatingSystem: Windows Server 2022

sAMAccountName: svc_app01
servicePrincipalName: HTTP/app-srv-02.northwind.example
```

Use group membership results to identify the next object to review, then query that object explicitly. Do not turn a directory inventory into a password, ticket, session, or remote-execution sweep.

## 8. Use PowerView for focused LDAP review

PowerView is part of PowerSploit, whose upstream repository is archived. Treat it as a legacy assessment tool. Use only a reviewed, version controlled copy that the engagement permits. Do not fetch and execute a script directly from a network URL, and do not use obfuscated or modified variants to avoid security controls.

For an isolated lab or your team’s staging workstation, retrieve the public source as a review artifact. Record the exact commit and file hash, inspect the script, and compare the result with your team’s approved artifact record before transferring it to an assessment system.

```powershell
$SourceRepo = 'C:\Assessment\Source\PowerSploit'
git clone --depth 1 'https://github.com/PowerShellMafia/PowerSploit.git' $SourceRepo
git -C $SourceRepo rev-parse HEAD

$SourceScript = Join-Path $SourceRepo 'Recon\PowerView.ps1'
Get-FileHash -Algorithm SHA256 -Path $SourceScript
Get-Content -Path $SourceScript -TotalCount 20

$ToolDirectory = 'C:\Assessment\Tools'
New-Item -ItemType Directory -Path $ToolDirectory -Force | Out-Null
$PowerViewPath = Join-Path $ToolDirectory 'PowerView.ps1'
Copy-Item -LiteralPath $SourceScript -Destination $PowerViewPath
```

Do not treat a commit ID or hash as a safety guarantee by itself. Review provenance and content, and use the client’s approved software transfer process before loading the script in any target environment.

Verify the expected file and recorded digest before importing it:

```powershell
Test-Path $PowerViewPath
Get-FileHash -Algorithm SHA256 -Path $PowerViewPath
```

Compare the hash with the value recorded by your team through its approved software review process. Then load the script in the current session and confirm the expected read only commands are present:

```powershell
. $PowerViewPath
Get-Command Get-Domain, Get-DomainUser, Get-DomainGroupMember,
  Get-DomainComputer, Get-DomainTrust
```

Collect a small domain summary and selected account properties:

```powershell
Get-Domain -Domain $Domain |
  Select-Object Name, Forest, DomainControllers

Get-DomainUser -Domain $Domain -Properties samaccountname, department, useraccountcontrol |
  Select-Object SamAccountName, Department,
    @{Name='Enabled'; Expression={([int]$_.useraccountcontrol -band 2) -eq 0}} |
  Sort-Object SamAccountName |
  Select-Object -First 10

Get-DomainGroupMember -Identity 'Domain Admins' -Domain $Domain |
  Select-Object GroupName, MemberName, MemberObjectClass, MemberSID
```

Example output:

```text
Name              Forest             DomainControllers
----              ------             -----------------
northwind.example northwind.example {NW-AD-01.northwind.example}

SamAccountName Department     Enabled
-------------- ----------     -------
analyst01      IT Operations  True
svc_app01      Infrastructure True

GroupName   MemberName     MemberObjectClass
---------   ----------     -----------------
Domain Admins id-platform  group
```

Follow the nested group to show the next edge in the chain:

```powershell
Get-DomainGroupMember -Identity 'id-platform' -Domain $Domain |
  Select-Object GroupName, MemberName, MemberObjectClass, MemberSID
```

Example output:

```text
GroupName      MemberName   MemberObjectClass
---------      ----------   -----------------
id-platform    analyst01    user
```

PowerView parameter names can differ across forks. Check the help shipped with the exact reviewed copy using `Get-Help Get-DomainUser -Full` before adapting a command. Keep collection narrow and avoid the module’s write, credential access, ticket, session hunting, or multi host probing functions unless those exact actions are separately approved.

For an ACL review, start with one security group or computer object that is directly relevant to the assessment question. Filter the result to rights that deserve validation, then resolve the trustee SID and inspect inheritance before describing impact.

```powershell
$GroupDN = (Get-ADGroup -Identity 'Identity Platform' -Server $Server).DistinguishedName

Get-DomainObjectAcl -Identity $GroupDN -Domain $Domain -ResolveGUIDs |
  Where-Object {
    $_.ActiveDirectoryRights.ToString() -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty'
  } |
  Select-Object SecurityIdentifier, ActiveDirectoryRights,
    ObjectAceType, IsInherited
```

Example output:

```text
SecurityIdentifier                                      ActiveDirectoryRights ObjectAceType IsInherited
------------------                                      --------------------- ------------- -----------
S-1-5-21-111111111-222222222-333333333-2205             WriteProperty         member        False
```

This is a lead for review, not proof that the trustee can take control of the group. Resolve the SID, verify the exact object and attribute scope, and check whether inherited protection or a protected group policy changes the effective permission. Do not modify the ACL to prove impact.

## 9. Build a relationship graph with BloodHound Community Edition

BloodHound can make group membership, trusts, policy links, and object control relationships easier to inspect. A graph is only as complete as its source data, and it can contain highly sensitive information about an organization.

Use the collector version offered by the client’s BloodHound Community Edition instance. Start with a domain controller only collection when the assessment question is directory relationships. This sample deliberately omits session and local group collection, which query member computers and need separate scope approval.

```powershell
New-Item -ItemType Directory -Path $EvidencePath -Force | Out-Null

& 'C:\Assessment\Tools\SharpHound.exe' `
  --CollectionMethods Group,ACL,Trusts,Container,ObjectProps `
  --Domain $Domain `
  --OutputDirectory $EvidencePath `
  --OutputPrefix 'northwind-directory-review'
```

Expected output varies by collector release. A successful run creates collection data files, commonly packaged as a ZIP archive, in the designated evidence directory. Inspect the collector’s help for the exact flags of the version supplied by the BloodHound instance. Import only into the client approved BloodHound environment, then record the collector version, methods, timestamps, and any errors.

When reviewing a path, trace each edge to its underlying source object and permission. Note data age, unresolved principals, collection failures, and policy filters that the graph may not model. Do not run broad endpoint session collection merely to make the graph look more complete.

## 10. Save evidence and close collection cleanly

Export only what supports the assessment question. Keep raw collector archives, CSV files, and screenshots in the approved encrypted evidence location. Restrict access, record hashes when required by the evidence plan, and follow the retention and deletion schedule. Do not add real client exports to this public handbook.

```powershell
Get-ChildItem -Path $EvidencePath -File |
  Select-Object Name, Length, LastWriteTime

Get-ChildItem -Path $EvidencePath -File |
  Get-FileHash -Algorithm SHA256 |
  Select-Object Path, Algorithm, Hash
```

The final notes should answer four questions: what was queried, which identity and server performed the query, what relationship was observed, and what remains unproven. Report a configuration risk as a configuration risk. Reserve stronger language for a path whose permissions and effect were actually validated within the agreed boundary.

## Common errors and interpretation traps

| Symptom | Likely explanation | Safe next check |
| --- | --- | --- |
| Server cannot be found | DNS or domain context is wrong | Confirm the approved DNS resolver and domain controller with the client |
| Access denied | The current identity lacks an approved read right | Record the error and ask the engagement lead whether access should be expanded |
| Empty attribute | The value may be unset, not readable, or invalid for this object class | Query one known in scope object and check the attribute schema |
| Duplicate names | `Name` is not always unique | Use the distinguished name or object SID to identify the object |
| Graph shows a path | The edge may be stale, filtered, or not sufficient for destination authorization | Validate each edge and the target service’s effective access decision |
| Large query is slow | Search base, filter, attributes, or page size may be too broad | Narrow the base and return only fields needed for the question |

## Further reading

- [Microsoft Learn: Active Directory PowerShell module](https://learn.microsoft.com/en-us/powershell/module/activedirectory/)
- [Microsoft Learn: Creating an Active Directory query filter](https://learn.microsoft.com/en-us/windows/win32/ad/creating-a-query-filter)
- [OpenLDAP `ldapsearch` command reference](https://man7.org/linux/man-pages/man1/ldapsearch.1.html)
- [Microsoft Learn: Best practices for securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
- [PowerSploit Recon and PowerView reference, archived upstream](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/README.md)
- [SpecterOps: SharpHound](https://github.com/SpecterOps/SharpHound)
- [BloodHound CE: SharpHound collection](https://bloodhound.specterops.io/collect-data/ce-collection/sharphound)
