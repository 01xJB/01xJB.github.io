---
title: Red Team Handbook
type: docs
weight: 2
sidebar:
  open: true
---

Practical field guides for authorized security assessments. These articles focus on identity infrastructure, endpoint controls, command and control systems, and the operational decisions that keep an engagement safe and useful.

## Browse by assessment area

| Area | Guides |
| --- | --- |
| Identity and Active Directory | [Directory discovery](active-directory/discovery/), [Kerberos and ticket review](active-directory/kerberos-and-delegation/), [unconstrained delegation](active-directory/unconstrained-delegation/), [constrained delegation](active-directory/constrained-delegation/), [resource based delegation](active-directory/resource-based-delegation/), [certificate services](active-directory/certificate-services/), and [trusts](active-directory/trusts/) |
| Windows controls | [Application control and AppLocker](windows-security/application-control/), [credential protection](windows-security/credential-protection/), [endpoint telemetry](windows-security/endpoint-telemetry/), [privilege boundaries](windows-security/privilege-boundaries/), [service and task review](windows-security/service-and-task-audit/), [driver security](windows-security/driver-security-review/), and [SQL Server](windows-security/sql-server-assessment/) |
| Cobalt Strike and infrastructure | [Beacon operations](cobalt-strike/beacon-operations/), [command and control design](cobalt-strike/command-and-control-design/), and [infrastructure assessment](cobalt-strike/c2-infrastructure-assessment/) |
| Assessment operations | [Initial access validation](operations/initial-access-validation/), [network path review](operations/network-path-review/), [artifact handling](operations/artifact-handling/), [operational security](operations/operational-security/), [scenario design](operations/scenario-design/), and [reporting and cleanup](operations/reporting-and-cleanup/) |

Examples use synthetic names and reserved documentation addresses. Commands that change systems are marked as change-plan examples and belong in an owner-approved change window. Ticket impersonation, credential extraction, defense evasion, and privileged access demonstrations are outside the public walkthroughs; use configuration evidence, telemetry, and benign validation to document risk.

{{< cards >}}
  {{< card link="active-directory" title="Active Directory" icon="user-group" >}}
  {{< card link="windows-security" title="Windows Security" icon="desktop-computer" >}}
  {{< card link="cobalt-strike" title="Cobalt Strike" icon="terminal" >}}
  {{< card link="operations" title="Operations" icon="shield-check" >}}
  {{< card link="wifi-pineapple" title="WiFi Pineapple" icon="wifi" >}}
  {{< card link="radio-hacking" title="Radio Hacking" icon="rss" >}}
  {{< card link="mongodb" title="MongoDB" icon="database" >}}
{{< /cards >}}
