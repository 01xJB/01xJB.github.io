---
title: "Legal and Privacy Checks for Security Assessments"
date: 2026-09-25
weight: 9
type: docs
tags:
  - Rules of Engagement
  - Privacy
  - Compliance
---

Use this checklist before collecting evidence or testing a system. The engagement lead should confirm applicable law and contractual terms with the client; this page is an operational checklist, not legal advice.

## 1. Confirm written authority and scope

Record the authorizing organization, named approver, assessment dates, source addresses, target names and ranges, permitted techniques, exclusions, and emergency contacts. Confirm that the client has authority over each target and has obtained any required third-party approvals. A domain name in a scope list does not automatically authorize every host or service behind it.

## 2. Set technique-specific boundaries

For each test objective, document the planned method, expected system impact, proof threshold, cleanup owner, and stop condition. Explicitly decide whether credential use, phishing, exploitation, persistence, remote execution, denial-of-service, or collection of personal data is allowed. If the technique is not named, pause and obtain written scope clarification before proceeding.

## 3. Minimize and protect evidence

Collect the smallest evidence set that proves the finding. Avoid opening user files or recording credential material. Restrict evidence access to named personnel, encrypt it in transit and at rest, track access, set a retention date, and record approved deletion. If personal information appears unexpectedly, stop collection, preserve only the minimum incident evidence, and notify the engagement contact through the agreed channel.

## 4. Keep a change and stop log

Log timestamps with timezone, operator, source host, target, action category, change ticket, result, and cleanup status. Stop on unexpected service impact, out-of-scope discovery, third-party infrastructure, exposed sensitive data, or a client stop request. Escalate through the named contact and resume only after written direction.

## 5. Close out access and data

At the end of the engagement, reconcile temporary accounts, approved test artifacts, firewall changes, scheduled actions, and evidence copies with the system owner. Confirm removal or handoff in writing. Keep the final report limited to evidence necessary to explain impact, reproduction scope, and remediation.

## References

- [Computer Misuse Act 1990, revised text](https://www.legislation.gov.uk/ukpga/1990/18/contents)
- [Data Protection Act 2018](https://www.legislation.gov.uk/ukpga/2018/12/contents)
- [Human Rights Act 1998](https://www.legislation.gov.uk/ukpga/1998/42/contents)
- [Information Commissioner's Office: A guide to data security](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/security/a-guide-to-data-security/)
