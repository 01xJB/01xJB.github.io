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

Notes for an LKM rootkit used to hold a KotH box. Based on [h0mbre's "Learn C By Creating A Rootkit"](https://h0mbre.github.io/Learn-C-By-Creating-A-Rootkit/).

</div>

<div class="callout callout-danger">

**Use only in private games**

Game-breaking. It **can and will break the machine** if not compiled with the GCC *on the box you run it on*, mismatched glibc / shared-object versions have killed SSH sessions and terminals. Statically compiling or bringing your own glibc can help; for KotH, compiling once on an old Ubuntu similar to the targets is usually enough.

</div>

## Install

```bash
bash make.sh
```

You may need to change `/lib/` to something like `/lib/x86_64-linux-gnu/` depending on the distribution. Remember to set the callback IP/port in the script first.

## Usage

| Action | How |
| --- | --- |
| Get a reverse shell | `touch __UNO & ls & rm __UNO` |
| Hide files | any name starting with `kir` or `asu` is hidden |
| Hide file content | add a line containing `hiro` at the end of the file |
|, | `ioctl` and `ps` are disabled automatically |

## Remove

```bash
bash remove.sh
```

<div class="callout callout-caution">

**Disclaimer**

No responsibility taken for any damage caused by this rootkit.

</div>
