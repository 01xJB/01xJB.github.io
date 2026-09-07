---
title: "Valley"
type: docs
tags:
  - thm
  - linux
  - easy
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Linux, **Difficulty:** Easy

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Web enumeration leads to credentials / access as **valleyDev**.
2. In `/home` there is a custom `auth` binary, pull it, run `strings` on it, recover the password for the **valley** user.
3. `/etc/crontab` shows root runs a scheduled task; our user is in the **valleyAdmin** group.
4. `valleyAdmin` owns a writable Python module (`/usr/lib/python3.8/base64.py`) that the root cron imports, poison it to `chmod u+s /bin/bash`.
5. `bash -p` → root.

</div>

<div class="callout callout-key">

**Credentials**

- Web / hint value: `ph0t0s1234`
- User: `valleyDev` → then `valley` (password from the `auth` binary)

</div>

## Foothold, the `auth` binary

Once I had a foothold as `valleyDev`, I started poking around the home directory rather than jumping straight to privilege escalation, and I noticed a custom compiled binary called `auth` sitting there. A standalone authentication binary is almost always worth reversing before anything else, since developers frequently hardcode credentials into these things during testing and forget to strip them out. Rather than reach for a disassembler right away, I started with the cheapest possible check and pulled the static strings out of it:

```bash
strings ./auth
```

That was enough on its own. The recovered password gave me a working credential for the **valley** user, no actual reverse engineering required, just a careful read through everything the binary embeds in plain text.

## Privilege Escalation, writable library imported by root cron

As `valley`, my next move was checking what root does on a schedule, since a scheduled task running with elevated privileges is one of the most common privilege escalation vectors on Linux boxes:

```bash
cat /etc/crontab
```

That confirmed root was running a cron job on a regular interval. What made this interesting was my own group membership: `valley` belonged to `valleyAdmin`, a group name specific enough to suggest it was granted write access to something deliberately. I went looking for exactly what that group could touch:

```bash
find / -group valleyAdmin -type f 2>/dev/null
```

The result was `/usr/lib/python3.8/base64.py`, a standard-library module rather than some custom application file, which immediately told me the root script must be importing `base64` somewhere in its own code. Python resolves imports by searching its module path, and since I had write access to a file sitting directly in that path, I could inject arbitrary code that would execute the moment root's script imported it. I appended a short payload to the end of the legitimate module rather than replacing it outright, so the module would still function normally for anything else that happened to import it:

```python
import os
os.system('chmod u+s /bin/bash')
```

With the payload in place, all that was left was waiting for the cron job to fire and import the poisoned module as root. Once it did, `/bin/bash` picked up the setuid bit, and dropping into a privileged shell was as simple as:

```bash
bash -p
```
