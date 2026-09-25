---
title: Certificate Templates
type: docs
weight: 6
sidebar:
  open: true
---

AD CS certificate template misconfiguration review, expanding on the [certificate services overview](../certificate-services/): vulnerable access control (ESC4), enrollee-suppliable SAN and any-purpose templates, agent and client-auth template misuse, and NTLM relay to HTTP enrollment endpoints (ESC8).

{{< cards >}}
  {{< card link="introduction" title="ESC4: Vulnerable Template Access Control" icon="key" >}}
  {{< card link="misconfigured-any-purpose-templates" title="Misconfigured Any-Purpose Templates" icon="document-duplicate" >}}
  {{< card link="misconfigured-certificate-request-agent-template" title="Misconfigured Certificate Request Agent Templates" icon="user-add" >}}
  {{< card link="misconfigured-client-authentication-template" title="Misconfigured Client Authentication Templates" icon="identification" >}}
  {{< card link="golden-certificates" title="Golden Certificates" icon="sparkles" >}}
  {{< card link="ntlm-relay-to-adcs-http-endpoints" title="NTLM Relay to AD CS HTTP Endpoints (ESC8)" icon="server" >}}
{{< /cards >}}
