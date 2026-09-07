---
title: "Mass MongoDB Scanning"
date: 2024-12-26
weight: 1
type: docs
tags:
  - Bug Bounty
  - MongoDB
  - Scanning
  - Authentication
  - Red Team Tooling
---

## What is MongoSmash

[MongoSmash](https://github.com/01xJB/mongosmash) is a multithreaded Python tool I built to scan a list of IPs (or CIDR ranges) for MongoDB instances exposed with no authentication, then recursively pull down whatever databases and collections it finds. It started as a quick script for confirming exposure during recon, and it's grown into something I now install as an actual CLI command rather than a one-off script.

## Features

- **Bulk IP and CIDR scanning**: feed it a plain list of targets, or drop a `10.0.0.0/24`-style range straight into the target file and it expands automatically
- **Single-host quick mode**: `-H <ip>` scans one target without needing a file at all, handy for a fast one-off check
- **Auth-bypass detection**: attempts a connection and flags instances that accept it with zero credentials
- **Weak-credential checks**: `--creds wordlist.txt` (`user:pass` per line) tries common credentials against instances that *do* require authentication, instead of just logging "requires auth" and moving on
- **Version fingerprinting**: pulls the MongoDB version off exposed instances via `buildInfo`, useful for matching against known CVEs afterward
- **Recursive, properly-serialized data pull**: walks every database and collection and dumps valid JSON (BSON types like `ObjectId` and dates included), with a per-collection document cap (`--limit`) so one huge collection can't hang the whole run
- **Detection-only mode**: `--no-dump` confirms exposure without pulling any data, for a lighter first pass before deciding what to pull
- **Configurable port, timeout, and pacing**: `-p/--port` for non-default setups, `--timeout`, and `--delay` for a gentler, stealthier scan
- **Multithreaded with a live progress bar**: configurable worker pool, graceful Ctrl+C handling instead of a raw traceback
- **Engagement-ready output**: every run writes both a `summary.json` and a `report.md` you can drop straight into a deliverable
- **Rich console output**: color-coded logging, including a dedicated `PWNED` log level for hits

## Installation

The easiest way is to grab the built wheel from the [latest release](https://github.com/01xJB/mongosmash/releases) and pip install it directly, which gives you a `mongosmash` command:

```bash
pip install https://github.com/01xJB/mongosmash/releases/latest/download/mongosmash-3.2.0-py3-none-any.whl
mongosmash --help
```

Or run it from source if you'd rather:

```bash
git clone https://github.com/01xJB/mongosmash.git
cd mongosmash
pip install -r requirements.txt
python3 mongosmash.py --help
```

## Scanning For MongoDB Servers 🥭

The most effective way to use `mongosmash` is to scan the internet for MongoDB servers to feed into it. Internet scanning itself is not illegal, but what you do with the results can absolutely be illegal depending on intent. **USE THIS ETHICALLY!**

### Port scan with **masscan**

There are a few ways to scan the internet with `masscan`: you can scan specific subnets, or you can scan the **ENTIRE INTERNET**. Never scan the entire internet from your home network, since your ISP will catch the traffic and shut you down fast, potentially with legal consequences. I recommend scanning from a `VPS` instead, but check your provider's policy on internet scanning first, since most disallow it. When a target catches your scan traffic, they can trace it back to your VPS's IP range and file an abuse report, which can get that range blacklisted.

#### Scanning the entire internet for MongoDB

The method below scans the entire internet at a max rate of `100000`, which uses significant bandwidth and sends a **LOT OF PACKETS**, giving you results the fastest. I'd recommend lowering `--max-rate` to `2000` or something well below `100000` for a less aggressive scan.

```bash
masscan 0.0.0.0/0 --exclude 255.255.255.255 -p 27017 --max-rate 100000 > 0.0.0.0-masscan.lst
```

## Using your IP list with mongosmash

Now that you have your list of IPs in `0.0.0.0-masscan.lst`, use `mongosmash` to mass-check them for unauthenticated access. This is especially useful on an actual pentest engagement, where you'd point it at your target's IP range instead.

```bash
masscan 172.15.14.0/0 --exclude 255.255.255.255 -p 27017 --max-rate 100000 > 172.15.14.0-masscan.lst
```

After you scan something it's going to look like this: `Discovered open port 27017/tcp on 172.15.14.15`. We need a list of just IP addresses, which we can get with `sed`:

```bash
sed -i 's@Discovered open port 27017/tcp on @@g' 172.15.14.0-masscan.lst
sed -i 's/ //g' 172.15.14.0-masscan.lst
```

Now it's just a plain IP list (or you could've skipped straight to `172.15.14.0/24` in the target file and let mongosmash expand the CIDR itself). Feed it in:

```bash
mongosmash -i 172.15.14.0-masscan.lst -t 25
```

### Quick single-host checks

If I just need to confirm one box without building a target file:

```bash
mongosmash -H 172.15.14.15
```

### Checking weak credentials, not just no-auth

A lot of real-world MongoDB exposure isn't "no auth at all", it's "auth enabled with a default or trivially weak password". `--creds` tries a wordlist of `user:pass` pairs against anything that comes back requiring authentication, instead of stopping at "requires auth" and losing that finding:

```bash
mongosmash -i targets.txt --creds common-mongo-creds.txt
```

### Fingerprinting for CVE matching

Every exposed instance now reports its MongoDB version (pulled via `buildInfo`), which I use to quickly cross-reference against known MongoDB CVEs for that version rather than guessing at what's patched.

### Keeping a lower profile

`--delay` adds a pause before each connection attempt, and `--no-dump` skips pulling data entirely, useful for an initial detection-only pass before deciding what's worth actually pulling:

```bash
mongosmash -i targets.txt --no-dump --delay 0.5
```

### Reading the results

Every run writes two files alongside the dumped data: `.mongosmash/summary.json` (machine-readable counts and per-host results) and `.mongosmash/report.md` (a Markdown table of every exposed instance, its version, and how it was accessed) that I paste straight into an engagement report.

## Mitigation Strategies

To defend against threat actors accessing your `mongodb` servers, make sure you have proper authentication enabled, use credentials that aren't in any common wordlist, and either set up a whitelist for authorized IP addresses or make your database only accessible through a private VPN. Keep MongoDB patched, since an outdated, exposed instance is a fingerprintable, easy target.

## Conclusion

Secure your MongoDB servers, and make sure to **ONLY** hack ethically and responsibly!
