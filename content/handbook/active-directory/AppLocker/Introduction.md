---
title: "Introduction"
date: 2026-09-25
weight: 1
type: docs
tags:
  - AppLocker
  - Application Control
  - Active Directory
---

## AppLocker

AppLocker is an application control technology built into Windows. Its purpose is to stop users running applications, scripts, or packages that policy has not approved. A policy is made up of one or more enforcement rules, and each rule pairs a permission with a condition. The permission sets the action, allow or deny, and the user or group the rule applies to. The condition defines what the rule actually matches, and can be based on one of three things:

- **Publisher.** Matches on the publisher of a signed application.
- **Path.** Matches on a file or folder path.
- **File hash.** Matches on the hash of a specific file.

Policies are authored by system administrators and are typically pushed out to machines through Group Policy, Intune, or a similar mechanism. Windows ships a default set of rules that looks roughly like the following.

**Executable rules**, covering executable files such as `.exe` and `.com`:

- Allow | Everyone | Path | `%PROGRAMFILES%\*`
- Allow | Everyone | Path | `%WINDIR%\*`
- Allow | BUILTIN\Administrators | Path | `*`

**Windows Installer rules**, covering installer files such as `.msi`, `.msp`, and `.mst`:

- Allow | Everyone | Publisher | `*`
- Allow | Everyone | Path | `%WINDIR%\Installer\*`
- Allow | BUILTIN\Administrators | Path | `*`

**Script rules**, covering script files such as `.ps1`, `.bat`, `.cmd`, `.vbs`, and `.js`:

- Allow | Everyone | Path | `%PROGRAMFILES%\*`
- Allow | Everyone | Path | `%WINDIR%\*`
- Allow | BUILTIN\Administrators | Path | `*`

**Packaged app rules**, covering `.appx` packaged applications:

- Allow | Everyone | Publisher | `*`

These defaults can be deployed as they are or adjusted to suit business requirements. The common thread across the executable and script defaults is worth noting: standard users are permitted to run anything under the Program Files and Windows directories, while administrators are allowed to run anything anywhere. Those broad path allowances are exactly what later bypass techniques take advantage of.

When a user tries to launch something the policy does not permit, Windows blocks it and surfaces a message stating that the application has been prevented by a system administrator or group policy, rather than running the program.

It is also worth being aware that AppLocker can run in two modes. Under *Enforce* the rules are applied and violating actions are blocked, whereas under *Audit only* the same actions are allowed to proceed but are logged. A policy running in audit mode offers no real protection, so confirming which mode is in effect is a useful first step when assessing an environment.