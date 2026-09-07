---
title: "kirito"
type: docs
tags:
  - thm
  - koth
  - king-of-the-hill
  - tooling
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **Mode:** King of the Hill

</div>

<div class="callout callout-note">

**This is tooling, not a box writeup**

These are my working notes for an LKM rootkit I built and used to hold a King of the Hill box. I based the core kernel-module technique on [h0mbre's "Learn C By Creating A Rootkit"](https://h0mbre.github.io/Learn-C-By-Creating-A-Rootkit/) and adapted the trigger and hiding logic for KotH play, where the goal isn't stealth against a defender's EDR but persistence and a fast, low-noise way to reclaim a shell if I get knocked off the box mid-round.

</div>

<div class="callout callout-danger">

**Use only in private games**

Game-breaking. It **can and will break the machine** if not compiled with the GCC *on the box you run it on*, mismatched glibc / shared-object versions have killed SSH sessions and terminals. Statically compiling or bringing your own glibc can help; for KotH, compiling once on an old Ubuntu similar to the targets is usually enough.

</div>

## Install

Before running anything, I always set the callback IP and port inside the script itself, since I only get one clean compile per target and don't want to be editing it under pressure mid-round:

```bash
bash make.sh
```

On some distributions the build script's hardcoded `/lib/` path doesn't match where the kernel actually expects its modules, so I've had to change it to something like `/lib/x86_64-linux-gnu/` before the install would go through cleanly. Worth checking that path first if the build fails.

## Usage

| Action | How |
| --- | --- |
| Get a reverse shell | `touch __UNO & ls & rm __UNO` |
| Hide files | any name starting with `kir` or `asu` is hidden |
| Hide file content | add a line containing `hiro` at the end of the file |
|, | `ioctl` and `ps` are disabled automatically |

## Remove

Once I no longer need persistence, or before handing a box back, I pull the module out with the matching removal script:

```bash
bash remove.sh
```

<div class="callout callout-caution">

**Disclaimer**

No responsibility taken for any damage caused by this rootkit.

</div>
