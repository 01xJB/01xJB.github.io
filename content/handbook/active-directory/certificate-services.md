---
title: "Assessing Active Directory Certificate Services"
date: 2026-09-24
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

## Further reading

- [Microsoft Learn: Manage certificate templates](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/manage-certificate-templates)
- [Microsoft Learn: PKI design considerations](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/pki-design-considerations)
- [SpecterOps: Certified Pre Owned](https://specterops.io/blog/2021/06/17/certified-pre-owned/)
