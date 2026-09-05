---
title: "WiFi Pineapple Capturing WiFi Handshakes"
date: 2024-12-24
weight: 4
type: docs
tags:
  - WiFi Pineapple
  - Penetration Testing
  - WiFi Security
---

One of the most common tasks in wireless penetration testing is capturing WiFi handshakes. This is a critical step for **cracking WiFi passwords** and evaluating the strength of the encryption protocols protecting the network. The **WiFi Pineapple mk7** is an incredibly effective tool that simplifies this process.

In this article, we’ll dive into how you can use the **WiFi Pineapple** to capture WiFi handshakes, an essential skill for any penetration tester or security enthusiast.

### What is a WiFi Handshake?

A **WiFi handshake** occurs when a device connects to a WiFi network, and the access point authenticates the device using encryption protocols like WPA2 or WPA3. Capturing this handshake is crucial because it contains information about the network and encrypted credentials that can later be cracked.

By capturing a **handshake**, penetration testers can **attempt to crack the WiFi password** offline, using techniques like brute-forcing or dictionary attacks.

### Why Use WiFi Pineapple to Capture Handshakes?

The **WiFi Pineapple** is an all-in-one device designed to simplify penetration testing tasks. When capturing handshakes, it’s essential to have a tool that can easily perform a **deauthentication attack** on nearby devices to force them to reconnect to the network, thereby generating a new handshake.

The **WiFi Pineapple** makes this process straightforward, with features that allow users to perform targeted attacks while monitoring the WiFi environment.

---

## How WiFi Pineapple Captures Handshakes 📡

### Step-by-Step Guide:

1. **Set Up Your WiFi Pineapple**:  
   First, ensure your **WiFi Pineapple** is set up and connected to your computer or network. You can use Kali Linux, Parrot Security OS, or any penetration testing environment to interact with the WiFi Pineapple via SSH or web interface.
2. **Select the Target Network**:  
   Use the **Recon Mode** on your WiFi Pineapple to scan nearby wireless networks. Once you’ve identified the network you want to target, select it for further actions.
3. **Enable Deauthentication Attack**:  
   To capture the handshake, you’ll need to force clients to disconnect and reconnect to the WiFi network. This can be done using the **Deauth Attack** feature available on the WiFi Pineapple. By sending a deauthentication packet to connected clients, the Pineapple can cause them to drop their connection and reconnect, generating a new handshake.
4. **Capture the Handshake**:  
   Once the deauthentication is successful, the client will attempt to reconnect to the access point. The WiFi Pineapple captures this handshake, which can then be used to try and crack the password offline.
5. **Save the Handshake File**:  
   The captured handshake will be saved as a `.cap` or `.hccapx` file. This file contains the encrypted credentials of the WiFi network, which can later be passed through a password-cracking tool, such as **Hashcat** or **John the Ripper**.

---

## Key Features for Capturing WiFi Handshakes with the WiFi Pineapple ✨

### 1. **Recon Mode**

The **Recon Mode** scans all nearby WiFi networks and devices, making it easy to identify the target network.

### 2. **Deauthentication Attack**

This feature allows the WiFi Pineapple to send deauthentication packets to disconnect clients and trigger the handshake process.

### 3. **Packet Capture**

Once a client reconnects, the WiFi Pineapple automatically captures the handshake and stores it in a readable format for further analysis.

### 4. **Automatic Handshake Capture**

The WiFi Pineapple is capable of automatically capturing handshakes when the appropriate conditions are met, saving time and effort in the process.

---

## Cracking the Handshake 🔓

After capturing the handshake, it’s time to use your favorite password-cracking tool to **crack the password**. Tools like **Hashcat** and **John the Ripper** are popular for this task, as they can use wordlists or brute-force attacks to try and guess the password.

To get started:

1. **Convert the Handshake File**:  
   If the handshake is in `.cap` format, you can convert it to `.hccapx` format for Hashcat using tools like **cap2hccapx**.
2. **Run a Cracking Tool**:  
   Use **Hashcat** or **John the Ripper** to run a dictionary attack or brute-force method on the handshake file.

   Example with Hashcat:

   ```
   hashcat -m 2500 -a 0 handshake.hccapx wordlist.txt
   ```
3. **Check the Results**:
   If the tool successfully cracks the password, you’ll have access to the WiFi network. If not, you can try different techniques or `wordlists` to improve your chances.

---

## Start Pineapple Handshake Capture

![PineappleHandshakre](https://i.imgur.com/3SMW7Im.png)

Navigate to the `Recon` Tab under the `Wifi Pineapple` Web-ui, after a few seconds you should start to see `Access Points` populate your list as well as your `Clients` List. Select your **CONTROLLED TARGET NETWORK** that you clearly have permission to execute this attack on and once you start to see `clients` populate in your list that are connected to your **CONTROLLED TARGET NETWORK** you can click `Capture WPA Handshakes`. This will `deauthenticate` all clients connected to this **Access Point** and once one of the clients attempts to connect back to the wifi access point it will capture the wifi handshake `pcap` file and store it for you to crack later.

- Clients List
  - Consists of Clients connected to various accesspoints.
  - Shows Information of clients such as `MAC Address`, `Vendor`, `Time Seen`, `BSSID` (Access Point) they are associated with.
- Access Points List
  - Displays Nearby `Access Points`
  - Shows Information of nearby `Access Points` such as `MAC Address`, `Vendor`, `Clients Connected`, `WPS Protocol`, `Signal Strength`

## Ethical Considerations ⚖️

`WiFi Pineapple` is an incredibly powerful tool, and with great power comes great responsibility. Always remember that ethical hacking is the key to becoming a successful penetration tester. Only use the `WiFi Pineapple` for legitimate purposes, such as testing networks you own or have explicit permission to test.

Unauthorized access to WiFi networks is illegal and punishable under laws in many regions. Always ensure you have written consent before conducting any penetration tests on third-party networks.

---

## Conclusion 🌟

Capturing `WiFi handshakes` with the `WiFi Pineapple` is a crucial skill for penetration testers and security professionals. Whether you’re testing your own network or participating in bug bounty programs, the `WiFi Pineapple` provides a streamlined approach to capturing and analyzing `handshakes`.

By leveraging its powerful features, you can enhance your penetration testing skills, gain deeper insights into WiFi security, and contribute to making the digital world a safer place.

Stay ethical, stay curious, and keep hacking!
