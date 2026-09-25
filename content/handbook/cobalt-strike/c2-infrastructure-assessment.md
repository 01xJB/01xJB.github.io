---
title: "Assessing Command and Control Infrastructure Safely"
date: 2026-09-25
weight: 3
type: docs
tags:
  - C2 Infrastructure
  - DNS
  - Operations
---

Command and control infrastructure for a red team exercise should be explicitly owned, narrowly scoped, monitored, and removable. A reliable assessment verifies the approved DNS name, certificate, network route, listener health, access logs, and retirement plan. This guide checks infrastructure ownership and availability; it does not build covert redirectors, disguise traffic, evade filtering, or deliver an agent.

## 1. Create an infrastructure record

For each hostname or IP address, record the registrant, cloud or hosting account owner, approved purpose, allowed source and destination ranges, expected ports, TLS certificate owner, log location, monitoring contact, and planned retirement date. Confirm that the rules of engagement explicitly include each domain, certificate, hosting provider, and callback port.

Keep provider credentials, private keys, and account recovery details in the organization's protected secrets system. Never store them in a public repository, shell transcript, or engagement report.

## 2. Confirm the DNS answer matches the asset register

```powershell
Resolve-DnsName 'c2-test.northwind.example' -Type A |
  Select-Object Name, Type, TTL, NameHost, IPAddress

Test-NetConnection 'c2-test.northwind.example' -Port 443 `
  -InformationLevel Detailed
```

Example output:

```text
Name                       Type TTL NameHost IPAddress
----                       ---- --- -------- ---------
c2-test.northwind.example  A    300          192.0.2.80

ComputerName     : c2-test.northwind.example
RemotePort       : 443
TcpTestSucceeded : True
```

The TEST-NET address is documentation-only. Compare every answer with the approved asset register. If the answer points to an unapproved host or shared provider endpoint, stop and resolve ownership before sending traffic. DNS resolution and an open TCP port show reachability, not authorization.

## 3. Validate the TLS endpoint

From an approved workstation, request only the designated health path. Do not follow redirects to an unapproved host and do not submit credentials:

```bash
curl --head --max-redirs 0 \
  --connect-timeout 5 --max-time 10 \
  https://c2-test.northwind.example/health
```

Record the status code, certificate subject and expiry, redirect behavior, and timestamp. A normal result should match the hosting team's documented configuration. Avoid embedding tokens or client data in the health request.

## 4. Check the managed service state

On a Linux host you administer, verify the web service configuration and health without changing it:

```bash
sudo nginx -t
systemctl is-active nginx
systemctl status nginx --no-pager --lines=20
```

`nginx -t` validates the local configuration syntax; it does not prove that the service is reachable from an approved test network. If Apache is used, apply the equivalent vendor-supported configuration test and status check. Do not reload, restart, or replace configuration during the assessment without the infrastructure owner's change approval.

## 5. Review request and firewall logs

Have the infrastructure owner query a narrow time range for the approved test source and health path. Check for unexpected methods, paths, source addresses, redirects, and error rates. Confirm that relevant logs reach the agreed central destination and that clock offsets are understood.

```bash
sudo journalctl -u nginx --since '2026-09-25 13:00:00' \
  --until '2026-09-25 13:30:00' --no-pager
```

Example record:

```text
2026-09-25T13:12:04Z health-check 198.51.100.25 GET /health 200
```

This is an example record. Do not copy raw request logs into a public writeup because they may contain client addresses, identifiers, or tokens.

## 6. Close out infrastructure

At the end of the approved window, reconcile listeners, DNS records, certificates, cloud instances, firewall rules, service accounts, and provider logs with the infrastructure ledger. Have the named owner confirm shutdown or transfer, then verify that public DNS no longer points to retired infrastructure when that is part of the agreed teardown. Preserve a signed closeout record.

## Further reading

- [Fortra: Listener management](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructue_listener_mgmnt.htm)
- [Fortra: HTTP and HTTPS Beacon listeners](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructue_beacon-http-https.htm)
- [NIST SP 800-115: Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final)
