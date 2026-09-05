---
title: "kingkit"
type: docs
tags:
  - thm
  - koth
  - king-of-the-hill
  - tooling
  - rootkit
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **Mode:** King of the Hill

</div>

<div class="callout callout-note">

**Tooling, not a box writeup**

Notes for an `LD_PRELOAD` userland rootkit used to hold KotH boxes.

</div>

<div class="callout callout-danger">

**Compile on-target**

Because of conflicting glibc versions you must compile on a KotH machine. Easiest: compile on the **food** machine (available as its own room), then reuse that binary everywhere. Set the `KING_NAME` macro to your nickname first.

</div>

## Build & install

```bash
gcc kingkit.c -shared -fPIC -ldl -o kingkit.so
```

```bash
cp ./kingkit.so /lib/kingkit.so
echo "/lib/kingkit.so" > /etc/ld.so.preload
```

## Features

- Protect and write your name to `king.txt`
- Redirect writes to `/etc/ld.so.preload` to a `FAKE_PRELOAD`
- Protect the rootkit library and `FAKE_PRELOAD`
- Hide files/dirs starting with `HIDE_PREFIX` or with gid `HIDDEN_GID`
- Reverse-shell persistence (hooks `time()` in cron)
- Hide processes and connections from `netstat`, `ps`, `lsof`
- Automatic restoration of the library after deletion

## Usage notes

| Task | How |
| --- | --- |
| Hide a file | `chgrp HIDDEN_GID file` (default `HIDDEN_GID` = 5005); also any name starting with `HIDE_PREFIX` is hidden from `ls` (still accessible) |
| Un-hide | `chgrp root file` |
| Hidden shell | `python3 -c 'import os;os.setgid(HIDDEN_GID);os.system("/bin/bash")'` |
| Hidden connections | only IPv4 TCP/UDP to the `HOST` macro IP are hidden |
| Reverse shell | set `HOST`/`PORT` macros, then `systemctl restart cron` so cron loads the rootkit; fires every minute, process auto-hidden |
| Advanced persistence | set `ADVANCED_PERSISTENCE=1`, restores itself when deleted (hard to remove, even for you) |

## Removing an LD_PRELOAD rootkit

Static binaries are unaffected by `LD_PRELOAD`, so:

```bash
chmod +x remove && ./remove          # ships a static binary that clears /etc/ld.so.preload
# or build it:  gcc remove.c -static -o remove
unset LD_PRELOAD                      # also clear the env var
```

## References

- [Memory Malware Part 0x2, Crafting LD_PRELOAD Rootkits in Userland](https://compilepeace.medium.com/memory-malware-part-0x2-writing-userland-rootkits-via-ld-preload-30121c8343d5)
- [Creating a Rootkit to Learn C (h0mbre)](https://h0mbre.github.io/Learn-C-By-Creating-A-Rootkit/)
- [awesome-linux-rootkits](https://github.com/milabs/awesome-linux-rootkits)

<div class="callout callout-caution">

**Educational use only. No responsibility taken for damage caused.**


</div>
