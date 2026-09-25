---
title: "Reviewing Network Paths and Pivot Boundaries"
date: 2026-09-25
weight: 5
type: docs
tags:
  - Network Assessment
  - Pivoting
  - Operations
---

Network pivoting changes which systems can reach which services through an assessment workstation or relay. A safe review starts with the approved route map and passive state. It does not create a tunnel, proxy, port forward, or remote command channel.

## 1. Confirm the allowed path

From the rules of engagement, record the source host, permitted destination ranges, excluded networks, protocols, rate limits, and emergency contact. Resolve each system owner before testing a route that crosses a trust or production boundary.

## 2. Capture local interface and route state

On Windows, collect a bounded snapshot from the named workstation:

```powershell
Get-NetIPConfiguration |
  Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer

Get-NetRoute -AddressFamily IPv4 |
  Sort-Object DestinationPrefix, RouteMetric |
  Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric
```

On a Linux assessment host, use read-only route and socket inventory:

```bash
ip -brief address
ip route show
ss -tun state established
```

Example route output:

```text
DestinationPrefix NextHop       InterfaceAlias RouteMetric
----------------- -------       -------------- -----------
0.0.0.0/0         192.0.2.1     Ethernet                 25
10.40.0.0/16      192.0.2.254   VPN                       5
```

These commands report the local host's view. They do not establish that the route is approved or that the far side permits a connection.

## 3. Validate one approved service

After confirming the destination and port are in scope, perform one low-rate reachability check and record the source address and time:

```powershell
Test-NetConnection -ComputerName 'app-srv-02.northwind.example' `
  -Port 443 -InformationLevel Detailed
```

Do not run a broad scan to discover networks beyond the approved target list. A successful connection proves reachability only; it does not prove authentication or authorization.

## 4. Document any approved tunnel separately

If an exercise explicitly requires a tunnel or port forward, define its bind address, destination, port, operator, duration, logging, and teardown owner in the change record. Confirm that the forward cannot expose a service to an unintended interface. Keep the connection inventory before and after the exercise and verify removal at closeout.

## 5. Review network telemetry

Correlate the test timestamp with firewall, VPN, DNS, proxy, and endpoint network records. Compare source and destination, protocol, byte count, and duration with the expected route. Investigate unexpected egress or a destination that does not match the approved asset register before continuing.

## Further reading

- [NIST SP 800-115: Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final)
- [MITRE ATT&CK: Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
