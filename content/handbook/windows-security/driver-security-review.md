---
title: "Reviewing Windows Driver Security Controls"
date: 2026-09-25
weight: 7
type: docs
tags:
  - Windows
  - Drivers
  - Endpoint Security
---

Kernel drivers have broad access to the operating system. An assessment should establish which drivers are present, how they are signed, whether the device applies the current driver block policy, and who owns each exception. Do not load a test driver, disable code integrity, or alter boot configuration as an inventory technique.

## 1. Capture the driver inventory

Use built-in inventory on a representative endpoint and retain the host build with the output:

```powershell
Get-CimInstance Win32_SystemDriver |
  Select-Object Name, DisplayName, State, StartMode, ServiceType, PathName |
  Sort-Object StartMode, Name
```

For a specific driver approved for review, resolve its file path, hash it, and inspect its Authenticode status:

```powershell
$DriverPath = 'C:\Windows\System32\drivers\example.sys'
Get-FileHash -LiteralPath $DriverPath -Algorithm SHA256
Get-AuthenticodeSignature -FilePath $DriverPath |
  Select-Object Status, StatusMessage, SignerCertificate
```

An absent or invalid signature is a reason to investigate, not proof of malicious behavior. Some drivers are catalog signed, and signature validation depends on the correct catalog and operating system policy. Verify with the platform owner and trusted software source.

## 2. Confirm enforcement configuration

Check whether the organization's supported Windows security baseline enables the vulnerable-driver blocklist and related memory integrity controls. Record effective policy, device compatibility constraints, exceptions, and reboot state. Do not use an unsupported registry edit or boot flag to claim a control is enabled.

Review relevant Code Integrity and Defender event channels for driver policy decisions during the agreed time window. Correlate the driver file hash, signer, load time, device, and software owner. A catalog entry is a candidate for review; verify it against Microsoft's current blocklist and vendor advisories before making a finding.

## 3. Handle a suspected vulnerable driver

Use the vendor's supported update or removal procedure. Test compatibility with business applications, stage deployment, and document rollback. Where an exception is required, record its owner, reason, scope, expiry, and compensating monitoring. Confirm the updated driver version and hash after the change.

## Further reading

- [Microsoft Learn: Microsoft vulnerable driver blocklist](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)
- [Microsoft Learn: Memory integrity and virtualization-based security](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity)
- [Microsoft Learn: Code Integrity event log](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations)
