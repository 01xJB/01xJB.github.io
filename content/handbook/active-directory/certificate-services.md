---
title: "Assessing Active Directory Certificate Services"
date: 2026-09-25
weight: 3
type: docs
tags:
  - AD CS
  - Certificates
  - Active Directory
---

Active Directory Certificate Services connects public key infrastructure to domain identity. Certificate authorities and templates can issue certificates used for authentication, encryption, and signing. A weak template or excessive permission can therefore have an impact well beyond the certificate service itself.

## Map the certificate environment

Identify enterprise certificate authorities, web enrollment services, published templates, and the principals that can enroll, manage, or change each object. For each template, review:

| Setting | Why it matters |
| --- | --- |
| Enrollment permissions | Determines which principals may request a certificate. |
| Subject name source | Determines whether identity fields are supplied by the directory or by the requester. |
| Extended key usage | Defines the purposes for which the certificate can be used. |
| Manager approval and authorized signatures | Adds review or authorization steps to issuance. |
| Template and CA permissions | Determines who can modify the template or manage issuance. |
| Certificate lifetime and revocation | Affects how long an issued certificate may remain useful. |
| Web enrollment transport protections | Affects whether authentication to the enrollment endpoint is adequately protected. |

Risk emerges from the combination of these settings and the rights of the requesting principal. A template name or a scanner label alone is not a finding.

## Validate a suspected exposure

Start with read only enumeration from an approved account. Preserve the CA name, template name, relevant flags, effective access control entries, and whether the template is actually published. Then trace the minimum path from an ordinary principal to the ability to request or modify a certificate that can authenticate as a more privileged identity.

For a production engagement, do not request a certificate for an administrator, extract a CA private key, relay authentication, or alter a template unless the authorization explicitly names that action and a rollback plan has been agreed. A configuration review can establish many risks without creating a privileged certificate.

## Remediation

Restrict enrollment to the teams and systems that need it. Remove unnecessary subject control from requester permissions. Separate template administration from enrollment, require approval where the workflow warrants it, and remove templates that are no longer used. Protect CA private keys and treat the CA as a high value identity asset. Review certificate issuance and template changes as security events.

When responding to suspected CA key compromise, revoking one issued certificate may not be sufficient. The incident response team should assess trust distribution, certificate validity, revocation behavior, and the recovery plan for the CA hierarchy.

## Reporting the result

Describe the template or CA setting, the affected principals, the shortest demonstrated path, and the potential business impact. Include the evidence that establishes scope and effective permissions. State clearly whether the assessment demonstrated issuance, authenticated access, or only a configuration risk.

## Read only inventory with the Active Directory module

Begin with the configuration naming context, then query the enterprise CA and certificate template containers. This keeps the search anchored to the directory partition that stores the public key infrastructure configuration.

```powershell
$Server = 'NW-AD-01.northwind.example'
$Root = (Get-ADRootDSE -Server $Server).configurationNamingContext
$CAContainer = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$Root"
$TemplateContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$Root"

Get-ADObject -Server $Server -SearchBase $CAContainer `
  -LDAPFilter '(objectClass=pKIEnrollmentService)' `
  -Properties dNSHostName, certificateTemplates |
  Select-Object Name, dNSHostName, certificateTemplates

Get-ADObject -Server $Server -SearchBase $TemplateContainer `
  -LDAPFilter '(objectClass=pKICertificateTemplate)' `
  -Properties displayName, 'msPKI-Enrollment-Flag',
    'msPKI-Certificate-Name-Flag', pKIExtendedKeyUsage |
  Select-Object Name, displayName, 'msPKI-Enrollment-Flag',
    'msPKI-Certificate-Name-Flag', pKIExtendedKeyUsage
```

Synthetic output:

```text
Name                  dNSHostName                    certificateTemplates
----                  -----------                    --------------------
Northwind Issuing CA  nw-pki-01.northwind.example        {User, Workstation, NorthwindVPN}

Name         displayName       msPKI-Enrollment-Flag msPKI-Certificate-Name-Flag pKIExtendedKeyUsage
----         -----------       --------------------- --------------------------- -------------------
NorthwindVPN Northwind VPN     0                     1                           {1.3.6.1.5.5.7.3.2}
Workstation  Workstation Auth  0                     0                           {1.3.6.1.5.5.7.3.2}
```

The numbers are raw bit fields, not a finding on their own. Decode each flag using the current Microsoft schema documentation or a maintained assessment tool, then verify the effective template ACL and whether the CA actually publishes the template. Record the CA and template names, object identifiers, relevant permissions, and evidence source.

## Confirm publication and ownership

Compare the template list on each CA object with the template objects in the directory. A template may exist but not be issued by a particular CA. Confirm the business owner, intended enrollment population, required approval, certificate purpose, and renewal path with the PKI team.

```powershell
$CAs = Get-ADObject -Server $Server -SearchBase $CAContainer `
  -LDAPFilter '(objectClass=pKIEnrollmentService)' `
  -Properties dNSHostName, certificateTemplates

foreach ($CA in $CAs) {
  [pscustomobject]@{
    CAName = $CA.Name
    Host = $CA.dNSHostName
    PublishedTemplates = ($CA.certificateTemplates -join ', ')
  }
}
```

This query reads directory metadata. It does not request a certificate or prove that a principal can enroll. Keep those assessment questions separate, and do not test issuance as a privileged identity without specific written approval.

## Further reading

- [Microsoft Learn: Manage certificate templates](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/manage-certificate-templates)
- [Microsoft Learn: PKI design considerations](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/pki-design-considerations)
- [SpecterOps: Certified Pre Owned](https://specterops.io/blog/2021/06/17/certified-pre-owned/)

## Step by step AD CS review with Certipy

Certipy's `find` command can collect CA and template configuration over LDAP and, depending on options and permissions, inspect CA configuration. Use a dedicated assessment identity with read access and an in-scope domain controller. This workflow stops at identifying and documenting a potential path. It does not request a certificate, impersonate an account, relay authentication, or modify CA/template settings.

First confirm the installed command and its supported options. Tool interfaces change, so save the version and help output with the engagement record:

```bash
certipy -h
certipy find -h
```

Set the target values from the rules of engagement. Confirm the version in Certipy's startup/help banner. Use a disposable lab credential and avoid putting a production password in shell history, screenshots, or shared command transcripts. The example addresses the documentation-only TEST-NET range:

```bash
certipy find \
  -u 'auditor@northwind.example' \
  -p '<LAB_ONLY_PASSWORD>' \
  -dc-ip 192.0.2.10 \
  -enabled -vulnerable -stdout
```

Illustrative output:

```text
Certificate Authorities
  CA Name             : Northwind-Issuing-CA
  DNS Name            : nw-pki-01.northwind.example
  Web Enrollment      : Disabled

Certificate Templates
  Template Name       : WorkstationAuth
  Enabled             : True
  Client Authentication : True
  Enrollee Supplies Subject : False
  Enrollment Rights   : NORTHWIND\Workstation Operators
  Vulnerabilities     : None

  Template Name       : LegacyUserAuth
  Enabled             : True
  Client Authentication : True
  Enrollee Supplies Subject : True
  Enrollment Rights   : NORTHWIND\Domain Users
  Vulnerabilities     : ESC1 (review required)
```

Treat the vulnerability label as a lead, not as proof of privilege escalation. Confirm each condition independently:

1. Is the template enabled and published by a reachable CA?
2. Does the assessment identity, directly or through nested groups, have effective enrollment rights?
3. Can the requester control an identity field, and does the certificate have an authentication-capable purpose?
4. Do manager approval or authorized-signature requirements change the issuance path?
5. Could a principal modify the template or CA configuration, and is that right genuinely effective after inheritance and deny entries?
6. Does the certificate mapping policy and domain configuration permit the claimed authentication use?

Capture the tool version, CA host, template name, group path, relevant flags, ACL evidence, and the owner who confirmed the template's purpose. Store the report in the approved evidence repository and remove local copies at closeout. Do not include PFX files, private keys, password values, or privileged certificate requests in a public article or ordinary assessment report.

### Validate remediation

Have the PKI owner review the minimum corrective change: restrict enrollment to the intended group, remove requester-controlled identity fields where unnecessary, require approval or authorized signatures when the workflow supports them, reduce template/CA management rights, and unpublish unused templates. After the approved change, rerun the same read-only `find` query and compare the before/after configuration. Confirm that legitimate enrollment workflows still function with an owner-approved test identity.

Do not disable a production template or alter CA policy as part of a scanner run. Changes to certificate issuance require the PKI change owner, a rollback plan, and a review of already issued certificates.

## Certificate issuance event review

Correlate the assessment window with CA issuance and template-change records. Preserve request identifiers and requester identities as evidence, then ask the CA owner to determine whether each request was expected. A configuration-only review should not produce a new privileged certificate. When no issuance test was authorized, report the exposure as a configuration finding rather than implying that certificate authentication was demonstrated.

For current Certipy options, use the [upstream usage guide](https://github.com/ly4k/Certipy/wiki/05-%E2%80%90-Usage) and [command reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference). For design and remediation, use Microsoft's [certificate template guidance](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/manage-certificate-templates) and the [Certified Pre-Owned research](https://specterops.io/blog/2021/06/17/certified-pre-owned/).
