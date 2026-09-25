---
title: "Designing Safe Adversary Emulation Scenarios"
date: 2026-09-25
weight: 3
type: docs
tags:
  - Adversary Emulation
  - Exercise Design
  - Rules of Engagement
---

A useful adversary emulation scenario tests a business relevant threat while keeping the activity measurable and bounded. The scenario should describe what the organization wants to learn, what evidence demonstrates success, and which actions are outside the exercise.

## Choose the objective

Begin with a business concern such as access to a sensitive workflow, disruption of a critical service, or the ability to misuse a privileged identity. Define the security capabilities that the exercise will evaluate, including prevention, detection, triage, containment, and recovery.

Emulation follows a known threat behavior to measure specific coverage. A broader simulation can explore more possibilities, but it also needs clear stop conditions and stronger deconfliction. Select the model that answers the client’s question rather than maximizing the number of techniques used.

## Define evidence and limits

For each phase, specify:

1. The approved identity and target.
2. The minimum action required to test the control.
3. The evidence to capture.
4. The systems and data that must not be touched.
5. The expected side effects and rollback steps.
6. The person who can stop or change the exercise.

Use synthetic accounts, test files, and non production resources whenever they can demonstrate the same control. Sensitive data access, credential extraction, destructive actions, persistence, and control modification should each require separate explicit approval.

## Measure the response

Agree what the defenders know before the scenario begins. A collaborative exercise can test detection tuning and analyst workflow. A blind exercise can test broader response, but the control group must still be able to stop the activity immediately. Record detection time, investigation quality, escalation, containment, and recovery, not only whether a product generated an alert.

## Close the loop

At the end, reconcile operator records with defender records. Share the planned scenario, actual deviations, and any indicators that remain active. Turn each observation into an improvement that has an owner and a practical verification step.

## Build a scenario card

Write one compact card for every planned stage. This lets the operator, controller, and defender understand what is being tested and when to stop.

| Field | Example |
| --- | --- |
| Objective | Verify that directory discovery from a standard workstation is monitored |
| Test identity | Approved non privileged account |
| Source and target | `WS-014` to `NW-AD-01.northwind.example` |
| Action | Query a small list of computer names and operating systems |
| Expected result | Three in scope records returned |
| Expected telemetry | LDAP client activity and domain controller audit data where configured |
| Stop condition | Any out of scope object or unexpected service impact |
| Evidence | Query record, time, account, result count, defender event reference |
| Recovery | End the query, preserve minimum evidence, notify engagement lead |

Keep the action sequence explicit. Each step should have a preceding authorization check and a following result check. If a prerequisite fails, the next step should be to pause or use a pre approved alternative, not to improvise a higher impact technique.

## Score outcomes consistently

Use the same labels throughout the exercise:

| Outcome | Meaning |
| --- | --- |
| Prevented | The control blocked the approved action before its intended effect |
| Detected | Telemetry or alert identified the activity |
| Triaged | An analyst reviewed and classified the event |
| Contained | The response reduced further activity within the agreed objective |
| Not observed | No evidence was available to the team by the agreed review time |
| Not tested | The action was outside scope or stopped for safety |

Record evidence for each label. “Not observed” does not mean that no telemetry exists; it may mean that the team did not receive or retain it. Use that distinction in the final report.

## Further reading

- [NIST SP 800 115: Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final)
- [MITRE ATT&CK: Adversary emulation plans](https://attack.mitre.org/resources/adversary-emulation-plans/)
