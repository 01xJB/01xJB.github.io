---
title: "WiFi Pineapple DNS Spoofing"
date: 2024-12-24
weight: 2
type: docs
tags:
  - WiFi Pineapple
  - Penetration Testing
  - WiFi Security
---

DNS spoofing (or DNS cache poisoning) is a potent technique often used in penetration testing to intercept network traffic by redirecting DNS queries. This method allows attackers to manipulate the Domain Name System (DNS) by tricking machines into resolving domain names to incorrect IP addresses.

In this guide, we will explore how to **redirect traffic** from a target domain to another machine (such as one running a phishing server) using the `/etc/hosts` file and `dnsmasq`. This is an essential tactic for **red teaming** and penetration testing, helping security professionals understand how attackers might exploit DNS vulnerabilities.

---

## What is DNS Spoofing? 🔍

**DNS Spoofing** involves manipulating DNS queries to resolve domain names to malicious IP addresses. This can lead to a variety of attacks, such as phishing, man-in-the-middle (MITM), or malware distribution. In this specific method, we are going to **redirect a domain** to a different IP address (the phishing server’s IP address) by modifying the local machine’s DNS resolution.

### Why Use /etc/hosts for DNS Spoofing?

The `/etc/hosts` file is a simple configuration file on Unix-like systems used to map domain names to IP addresses. This file takes precedence over DNS queries, allowing users to specify custom IP addresses for specific domains. By editing this file, you can reroute traffic destined for a legitimate domain to your phishing server or any other malicious service.

This technique is **useful** in environments where DNS is not centrally managed or where an attacker has control over the local machine’s DNS settings.

---

## Prerequisites 📦

- A **target machine** that you can modify the `/etc/hosts` file on (this could be your own machine or a test target).
- A **phishing server** set up on another machine, listening on a specific IP address. This is where you want to redirect the traffic.
- **dnsmasq** installed and running to handle DNS queries locally.

---

## Step-by-Step Guide: Redirecting Traffic with DNS Spoofing 🎯

### Step 1: Set Up the Phishing Server 🖥️

Before proceeding, ensure you have a **phishing server** running on your machine. For example, you can use **Social Engineering Toolkit (SET)** or **Evilginx2** to set up a phishing server that mimics a login page for a specific website (e.g., Facebook, Gmail).

Make sure the phishing server is accessible and running on a specific IP address, which we’ll use in the next steps.

---

### Step 2: Modify the /etc/hosts File ✍️

1. Open the `/etc/hosts` file on your `Wifi Pineapple`:

   ```bash
    nano /etc/hosts
   ```bash
2. Add the following line to redirect a domain to the IP address of your phishing server. For instance, if your phishing server is running on IP `172.16.42.15`, and the target domain is `memes.com`, the entry would look like:

   ```text
   192.168.1.100   memes.com
   ```
3. Save the file and exit the editor (`CTRL + X` + `Y` + `ENTER`).
   By doing this, you’ve told the `Wifi Pineapple` to resolve `memes.com` to the IP address of your phishing server.

---

## Step 3: Restart dnsmasq for DNS to Take Effect 🔄

`dnsmasq` is a lightweight DNS forwarder and DHCP server. It’s used to cache DNS queries and route DNS requests locally. To make sure the changes take effect, you’ll need to restart `dnsmasq`.

1. Restart the `dnsmasq` service:

   ```bash
   /etc/init.d/dnsmasq stop
   /etc/init.d/dnsmasq start
   ```
2. Verify that `dnsmasq` is running properly:

   ```bash
   /etc/init.d/dnsmasq status
   ```

You should see a message indicating that `dnsmasq` is active and running.

---

## Step 4: Test the DNS Spoofing 🧪

After modifying the `/etc/hosts` file and restarting dnsmasq, you can test the DNS spoofing:

1. Open a browser or use `curl` to access the domain you’ve targeted (in this case, `memes.com`):

   ```bash
   curl -vv -k memes.com
   ```

The request should be redirected to your phishing server’s landing page.

2. Alternatively, you can use `nslookup` or `dig` to check the DNS resolution:

   ```bash
   nslookup memes.com
   ```

---

## Key Features of DNS Spoofing with `/etc/hosts` and `dnsmasq` ✨

- **Local DNS Resolution**: Modifying the `/etc/hosts` file overrides DNS queries for specific domains, allowing you to redirect traffic to any IP address locally.
- **dnsmasq for DNS Caching**: By restarting `dnsmasq`, you ensure the local DNS cache is refreshed, applying the changes immediately.
- **No Need for Root DNS Control**: This method does not require control over a remote DNS server, making it effective for local redirection.

## Ethical Considerations ⚖️

While `DNS spoofing` can be a powerful tool in penetration testing and security research, it’s essential to use it ethically and responsibly:

- **Always have explicit permission** before performing any penetration testing or DNS spoofing on networks or systems you do not own.
- **Educate users** about the dangers of phishing and the importance of DNS security to prevent such attacks in the real world.

## Conclusion 🌟

DNS spoofing, particularly using `/etc/hosts` and `dnsmasq`, is a simple yet effective way to hijack DNS queries and redirect traffic to a phishing server or malicious IP. While the technique is incredibly useful for penetration testers and red teams, it must always be performed ethically and with consent.

By mastering DNS spoofing, you can gain deeper insights into network security and how attackers exploit DNS vulnerabilities. Understanding these techniques enables you to better defend against them and improve overall network security.

Stay ethical, stay vigilant, and keep learning!

P.S. Stay tuned for advanced phishing and DNS spoofing with the WiFi Pineapple!
