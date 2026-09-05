---
title: "shrek"
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

Rough KotH notes only.

</div>

## Port Scan

```console
Open 10.10.28.242:22
Open 10.10.28.242:21
Open 10.10.28.242:80
Open 10.10.28.242:3306
Open 10.10.28.242:8009
Open 10.10.28.242:8080
Open 10.10.28.242:9999
Open 10.10.28.242:65432
```

## Notes

- Interesting web path: `http://10.10.28.242/Cpxtpt2hWCee9VFa.txt`
- Foothold: recovered an `id_rsa` for the user **shrek**.
