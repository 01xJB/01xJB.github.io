---
title: "Misconfigured 'Any Purpose' Templates"
date: 2026-09-25
weight: 3
type: docs
tags:
  - AD CS
  - Certificate Templates
  - ESC2
  - Active Directory
---

## What ESC2 is

ESC2 is a privilege-escalation condition that arises when an attacker can enrol for a certificate whose template carries the *Any Purpose* EKU, or one with no EKUs at all, which is interpreted as a Subordinate CA. In either case the resulting certificate is unconstrained: it can stand in for any EKU, with no restriction on how it is used.

Enumerating the templates surfaces the problem directly. Certify flags the Any Purpose EKU and shows that enrolment has been opened up to an over-broad group:

```powershell
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins --quiet

    Template Name                         : ESC2
    Enabled                               : True
    Publishing CAs                        : hq-ca-01.arcadia.local\ARCADIA Root CA
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    Certificate Name Flag                 : SUBJECT_REQUIRE_DIRECTORY_PATH
    Enrollment Flag                       : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Manager Approval Required             : False
    Authorized Signatures Required        : 0
    Extended Key Usage                    : Any Purpose
    Certificate Application Policies      : Any Purpose
    Vulnerabilities
      ESC2                                : The template has the 'Any Purpose' EKU.
    Permissions
      Enrollment Permissions
        Enrollment Rights           : ARCADIA\Domain Users               S-1-5-21-3926355307-1661546229-813047887-513
```

Here enrolment rights sit with *Domain Users*, so any authenticated principal in the domain can request an unrestricted certificate from this template.

## Abusing it

Because the certificate is valid for any purpose, ESC2 does not lock you into a single follow-on technique; it lets you borrow whichever one fits. The unrestricted certificate can be used to reproduce the ESC3 abuse, standing in for the enrolment-agent capability that technique relies on. Alternatively, if `ENROLLEE_SUPPLIES_SUBJECT` is set on the template, you can supply an arbitrary subject and reproduce the ESC1 flow instead, requesting a certificate directly as a privileged user. In practice, ESC2 is best thought of as a flexible stepping stone into those other paths rather than an escalation with a single fixed route.

## Defensive considerations

The Any Purpose EKU (and an empty EKU set) should be treated as a red flag on any template that low-privileged users can enrol for. Restrict such templates so that only a small, trusted group holds enrolment rights, and remove the Any Purpose application policy entirely unless there is a documented reason for it, replacing it with the specific EKUs the certificate genuinely needs. Broad principals such as *Domain Users* or *Authenticated Users* should not appear in the enrolment rights of a template this powerful. On the monitoring side, certificate requests against Any Purpose or Subordinate CA templates warrant scrutiny, as do the downstream ESC1 and ESC3 behaviours the resulting certificate enables, since those are where the actual escalation plays out.

## Further reading

- [SpecterOps: Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [GhostPack Certify](https://github.com/GhostPack/Certify)