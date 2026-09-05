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
---

## What is Mongosmash

MongoSmash is a Python tool designed to scan a list of IP addresses, attempt to authenticate with MongoDB instances, and recursively download their databases if access is granted without authentication.

## Features

- **IP Address Scanning**: Efficiently scans a list of provided IP addresses.
- **MongoDB Authentication Attempts**: Tries to authenticate with each IP address.
- **Recursive Database Download**: Downloads databases recursively upon successful authentication.
- **Logging**: Detailed logging with Rich for better readability.
- **Multithreading**: Uses multiple threads to speed up the scanning process.

## Installation 🤖

1. **Clone the Repository**:

   ```
   git clone https://github.com/01xJB/mongosmash.git
   cd mongosmash
   ```
2. **Install Dependencies**:

   ```
   pip install -r requirements.txt
   ```

## Scanning For MongoDB Servers 🥭

The most effective way to use `mongosmash` is to scan the internet for MongoDB servers to feed into `mongosmash`. Internet scanning itself is not illegal, but what you do with the results can absolutely be illegal depending on intent. **USE THIS ETHICALLY!**

### Port scan with **masscan**

There are a few ways to scan the internet with `masscan`: you can scan specific subnets, or you can scan the **ENTIRE INTERNET**. Never scan the entire internet from your home network, since your ISP will catch the traffic and shut you down fast, potentially with legal consequences. I recommend scanning from a `VPS` instead, but check your provider's policy on internet scanning first, since most disallow it. When a target catches your scan traffic, they can trace it back to your VPS's IP range and file an abuse report, which can get that range blacklisted.

#### Scanning the entire internet for MongoDB

The method below scans the entire internet at a max rate of `100000`, which uses significant bandwidth and sends a **LOT OF PACKETS**, giving you results the fastest. I'd recommend lowering `--max-rate` to `2000` or something well below `100000` for a less aggressive scan.

```
masscan 0.0.0.0/0 --exclude 255.255.255.255 -p 27017 --max-rate 100000 > 0.0.0.0-masscan.lst
```

## Using your IP list with mongosmash

Now that you have your list of IP addresses in `0.0.0.0-masscan.lst` you can now use `mongosmash` to mass authenticate with them to locate unauthenticated mongodb servers, this can be really useful if you are in a pentest engagement, you could use the IP range of your target.

Here is an example of scanning with your target subnet range.

```
masscan 172.15.14.0/0 --exclude 255.255.255.255 -p 27017 --max-rate 100000 > 172.15.14.0-masscan.lst
```

After you scan something it is going to look like this `Discovered open port 27017/tcp on 172.15.14.15`. We need a list of just IP addresses and we can parse the IP addresses by using the `sed` command on linux.

```
sed -i 's@Discovered open port 27017/tcp on @@g' 172.15.14.0-masscan.lst
```

This will now give you a list of just IP addresses now we need to parse out all of the spaces that are in the file we can do that with `sed` once more.

```
sed -i 's/ //g' 172.15.14.0-masscan.lst
```

Now it really is just IP addresses. From here we can now just `mongosmash` by doing the following.

```
python3 mongosmash.py -i 172.15.14.0-masscan.lst --threads=25
```

## Mitigation Strategies

To defend against threat actors accessing your `mongodb` servers, make sure you have proper authentication enabled, and either set up a whitelist for authorized IP addresses or make your database only accessible through a private VPN.

## Conclusion

Secure your MongoDB servers, and make sure to **ONLY** hack ethically and responsibly!
