---
title: "Safe Initial Access Validation"
date: 2026-09-25
weight: 4
type: docs
tags:
  - Initial Access
  - Security Testing
  - Email Security
---

Initial access testing evaluates whether an organization can prevent, detect, and respond to an approved entry scenario. The value comes from measuring the control chain, not from maximizing user interaction or deploying a working implant.

## Agree on the simulation

Before testing, specify the authorized recipients, domains, delivery window, message content, tracking method, and emergency contacts. Decide whether the exercise may collect click events only or whether it may test a later stage. Name prohibited data collection, including passwords, session tokens, personal documents, and information from unrelated users.

Use a client controlled domain and a benign landing page. Do not collect real credentials. Where an authentication step is needed to test a control, use a simulated form that records only a non sensitive event such as that the page was reached.

## Use harmless artifacts

The client should approve any attachment, link, script, or test file before delivery. Use a benign marker that cannot execute destructive behavior, and verify it in a lab environment first. Confirm that mail security, endpoint controls, and analyst workflows can observe the event without exposing recipients to actual credential theft or malware.

## Measure more than clicks

Record the delivery result, user report rate, time to triage, alert quality, escalation path, and containment action. If a recipient reports the test, preserve that as a positive security outcome. Do not shame individual users or include personal performance details in a public report.

## Stop and notify

Pause if the campaign reaches an unapproved recipient, causes unexpected business impact, collects sensitive data, or appears to overlap with a real incident. Follow the named escalation process and resume only when the client authorizes it.

## Improve the control chain

Use results to improve reporting workflows, mail filtering, domain protections, endpoint coverage, and response playbooks. Provide aggregate metrics and actionable observations to the client. Retire test domains and remove temporary content after the agreed period.

## Run the exercise in stages

Use a small, pre approved recipient set and a client controlled test domain. Keep a copy of the approved message and landing page in the engagement record. Before delivery, confirm the campaign window, help desk notice, emergency contact, and stop authority.

1. Send a validation message only to the designated internal test mailbox.
2. Confirm that the message is delivered, quarantined, or rejected as expected.
3. Verify that the harmless landing page displays the approved content and records only a non sensitive event.
4. Ask the client to confirm the corresponding mail, proxy, identity, and endpoint telemetry.
5. Expand to the approved recipient cohort only after the test mailbox check succeeds.
6. End the campaign at the agreed time and reconcile delivery and reporting metrics.

Check that the owned landing page is reachable before the test window. This request uses a header check and does not submit credentials or follow a user action.

```powershell
Invoke-WebRequest -Uri 'https://awareness.northwind.example/marker' `
  -Method Head -MaximumRedirection 0 |
  Select-Object StatusCode, Headers
```

Example output:

```text
StatusCode Headers
---------- -------
200        {[Content-Type, text/html; charset=utf-8], [Cache-Control, no-store]}
```

The host and page are placeholders. Confirm DNS, certificate ownership, page content, and logging behavior with the campaign owner. Do not add credential fields, collect passwords, or deliver executable content as part of this validation workflow.

## Close out the recipient data

Keep campaign metrics aggregated. Restrict access to recipient level records and delete those records at the end of the approved retention period. Report mail delivery, user reporting, analyst response, and control improvements without publishing employee names or shaming individuals.
