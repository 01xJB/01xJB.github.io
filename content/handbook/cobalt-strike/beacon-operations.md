---
title: "Cobalt Strike Beacon Operations"
date: 2026-09-24
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

## Manage sessions deliberately

Name sessions consistently, note their owner and purpose, and record parent relationships. Keep task queues short and cancel work that is no longer required. For multi operator work, agree on deconfliction rules so that one operator does not interrupt or duplicate another operator’s action.

Listeners and payloads should be created only for an approved lab or engagement. Do not generate or distribute payloads for systems outside the written scope. Apply guardrails where available, secure access to the team server, restrict operator accounts, and protect logs and collected data as sensitive client information.

## Close out cleanly

At the end of testing, confirm that sessions are stopped, temporary infrastructure is removed, artifacts are accounted for, and the client has received any required indicators. Preserve the operation record long enough to support reporting and then follow the client’s retention and deletion requirements.

## Further reading

- [Fortra: Cobalt Strike Beacon documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as_beacon.htm)
- [Fortra: Session and target visualizations](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/ui_session-target-visualizations.htm)
- [Fortra: Post exploitation documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_main.htm)
