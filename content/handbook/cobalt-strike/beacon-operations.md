---
title: "Cobalt Strike Beacon Operations"
date: 2026-09-25
weight: 1
type: docs
tags:
  - Cobalt Strike
  - Command and Control
  - Red Teaming
---

Cobalt Strike is a collaborative command and control platform used in authorized adversary emulation and security testing. A disciplined operator needs to understand the relationship between the team server, client, listeners, and Beacon sessions before sending any task to an endpoint.

## Know the components

The team server coordinates operator sessions and stores operation data. The client gives operators a shared interface to sessions, task queues, and reporting. Beacon is the agent that receives tasks and returns results. A listener defines the communication settings associated with a Beacon payload.

Some Beacon communication patterns reach the team server directly. Other patterns relay through an existing Beacon inside the environment. This distinction affects network paths, failure modes, and the evidence visible to defenders. A graph view can clarify which sessions depend on which parent session, but it should not replace operator notes.

## Treat every task as a change

Beacon commands differ in where they execute and what they affect. Some are client side housekeeping. Others invoke operating system APIs, load an object into the Beacon process, start a child process, or communicate with a remote host. Before using a command, review its help text and determine:

1. Whether it changes the endpoint or only queries it.
2. Which process and identity will perform the action.
3. Whether it creates files, services, network connections, or child processes.
4. What data it may collect or return.
5. How the action will be stopped or reversed.

In a training environment, begin with low impact situational awareness commands such as `help`, `getuid`, `pwd`, and `ls`. Use only the commands needed to support the approved objective. Avoid broad collection and do not treat an available command as permission to run it.

Fortra documents `getuid`, `pwd`, and `ls` as built in Beacon commands. Their implementation and telemetry differ, so consult the command behavior reference for the installed Cobalt Strike version before choosing an action. A command that uses an API rather than a child process can still create observable network or endpoint activity.

## A bounded Beacon survey

The following example assumes a Beacon already exists inside an authorized lab or engagement. It does not cover payload generation, delivery, persistence, or evasion. Confirm the Beacon identifier, host, user, parent relationship, and test window before interacting with it.

Begin with local context commands and record the result in the operator log:

```text
beacon> getuid
beacon> pwd
beacon> ls C:\ProgramData\Northwind\Test
```

Example output:

```text
Current identity: NORTHWIND\analyst01
Working directory: C:\Windows\System32
Directory listing: marker.txt
```

Exact console wording varies by version and command. Confirm the user context and target before every operation. If the identity, host, path, or Beacon parent is unexpected, stop and use the engagement escalation path.

### Query a small directory set

When the approved objective includes Active Directory discovery, a reviewed LDAP search Beacon Object File can issue a narrow query. The `ldapsearch` command below comes from TrustedSec’s separate situational awareness BOF project. It is not a built in command in every Cobalt Strike installation. Confirm the BOF’s provenance, version, approved scope, and expected telemetry with the tool owner first.

```text
beacon> ldapsearch "(objectClass=computer)" --attributes sAMAccountName,dNSHostName,operatingSystem --count 5 --hostname NW-AD-01.northwind.example --dn DC=northwind,DC=example
```

Example output:

```text
Search base: DC=northwind,DC=example
Filter: (objectClass=computer)
Entries returned: 3

sAMAccountName: APP-SRV-02$
dNSHostName: app-srv-02.northwind.example
operatingSystem: Windows Server 2022

sAMAccountName: NW-AD-01$
dNSHostName: nw-ad-01.northwind.example
operatingSystem: Windows Server 2022
```

The query returns only three selected attributes and is limited to five results. Start with the minimum set that answers the agreed question. Avoid requesting every attribute or security descriptor by default, because that increases collection volume and may include sensitive relationships.

For a user inventory, change only the LDAP filter and attribute list after confirming the exact query with the client:

```text
beacon> ldapsearch "(samAccountType=805306368)" --attributes sAMAccountName,department --count 10 --hostname NW-AD-01.northwind.example --dn DC=northwind,DC=example
```

The SAM account type filter identifies user objects. It does not identify which accounts are safe to target, and it is not a credential access step. Retain query timestamps, Beacon identity, domain controller, and result count. If query volume or output becomes unexpected, cancel the task and notify the engagement lead.

## Manage sessions deliberately

Name sessions consistently, note their owner and purpose, and record parent relationships. Keep task queues short and cancel work that is no longer required. For multi operator work, agree on deconfliction rules so that one operator does not interrupt or duplicate another operator’s action.

Listeners and payloads should be created only for an approved lab or engagement. Do not generate or distribute payloads for systems outside the written scope. Apply guardrails where available, secure access to the team server, restrict operator accounts, and protect logs and collected data as sensitive client information.

## Close out cleanly

At the end of testing, confirm that sessions are stopped, temporary infrastructure is removed, artifacts are accounted for, and the client has received any required indicators. Preserve the operation record long enough to support reporting and then follow the client’s retention and deletion requirements.

## Further reading

- [Fortra: Cobalt Strike Beacon documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as_beacon.htm)
- [Fortra: Session and target visualizations](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/ui_session-target-visualizations.htm)
- [Fortra: Post exploitation documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_main.htm)
- [Fortra: Beacon command behavior and OPSEC considerations](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm)
- [TrustedSec: Situational Awareness Beacon Object Files](https://github.com/trustedsec/CS-Situational-Awareness-BOF)
