---
title: "Using Evil Portal with the WiFi Pineapple"
date: 2024-12-24
weight: 3
type: docs
tags:
  - Hacking
  - Phishing
  - WiFi Pineapple
  - Network Security
---

**Phishing** is one of the most effective and widely used methods for cyber attacks. Among the tools used for phishing, the **WiFi Pineapple** stands out as a versatile and powerful device designed specifically for security testing and penetration testing. This article explores how the WiFi Pineapple can be utilized in phishing attacks and discusses its key features.

The WiFi Pineapple is capable of executing **Man-in-the-Middle (MITM)** attacks, one of which is phishing. By impersonating legitimate Wi-Fi networks, the WiFi Pineapple tricks unsuspecting users into connecting to a rogue access point. Once connected, attackers can inject malicious content or steal sensitive data such as login credentials.

### How Phishing Works with the WiFi Pineapple

Phishing with the WiFi Pineapple is straightforward. The device acts as a rogue access point, broadcasting fake Wi-Fi networks that appear legitimate. When users attempt to connect to the internet, the WiFi Pineapple intercepts their connections.

1. **Rogue Access Point Creation**: The attacker sets up the WiFi Pineapple to broadcast a fake Wi-Fi network. The SSID (network name) can be chosen to resemble a public hotspot or a home network, making it more likely that victims will connect.
2. **Client Connection**: When a victim connects to the rogue network, the WiFi Pineapple automatically intercepts the connection, providing internet access through its own network.
3. **Phishing Pages**: Once the victim is connected, the attacker can use the WiFi Pineapple’s built-in features to inject phishing pages into the victim’s browser. These pages often mimic legitimate websites, such as login portals for social media or banking sites, and deceive users into entering their credentials.
4. **Data Harvesting**: The WiFi Pineapple can capture sensitive data such as usernames, passwords, and other personal information that users input into these fraudulent pages.

### Key Features of the WiFi Pineapple for Phishing

The **WiFi Pineapple mk7** is specifically designed for security testing, offering several features that make phishing attacks easier to execute:

- **Rogue AP Attack**: This feature allows attackers to impersonate legitimate access points, intercepting connections from unsuspecting victims.
- **Evil Portal**: The Evil Portal feature enables attackers to redirect users to custom, malicious landing pages. These pages can be designed to resemble legitimate login forms, social media platforms, or online banking websites.
- **Karma**: Karma is a feature that causes devices to automatically connect to the WiFi Pineapple without user interaction, making it easier to lure victims.

### Setting Up Phishing with the WiFi Pineapple

To perform a phishing attack with the WiFi Pineapple, follow these steps:

1. **Install the WiFi Pineapple**: Set up your WiFi Pineapple device, ensuring it is connected to a computer running Kali Linux or another penetration testing OS for full functionality.
2. **Configure a Rogue AP**: Use the WiFi Pineapple’s user interface to configure a fake access point. Select an SSID that is likely to attract victims, such as the name of a popular public network.
3. **Enable Evil Portal**: Activate the Evil Portal feature to redirect users to a phishing page. You can create a fake login page or use pre-configured phishing templates from sources like [GitHub](https://github.com/kleo/evilportals).
4. **Launch the Attack**: Once the rogue AP and phishing page are ready, launch the attack. Monitor the connected clients and capture any credentials or sensitive information they provide.

### Legal and Ethical Considerations

It is crucial to note that using the WiFi Pineapple for phishing without explicit permission is illegal. Phishing attacks violate privacy laws and can result in severe legal consequences. Always use these techniques for ethical hacking purposes, such as penetration testing with the consent of the target organization.

While the `WiFi Pineapple` is an excellent tool for identifying vulnerabilities in Wi-Fi networks, it can also be misused for malicious purposes. Understanding how these attacks work can help individuals and organizations better defend against them.

---

## Features of the WiFi Pineapple for Phishing

In addition to its standard Wi-Fi sniffing and MITM capabilities, the WiFi Pineapple includes several unique features that make phishing attacks more effective.

### Evil Portal

The **Evil Portal** is one of the most powerful tools for phishing. It allows attackers to redirect all users connecting to the rogue access point to a custom, malicious landing page. These pages can resemble login forms for popular services like Google, Facebook, or banking sites, enabling attackers to capture sensitive user data.

### Karma

The **Karma** feature automatically responds to probe requests from nearby devices, causing them to connect to the rogue access point without any user interaction. This increases the likelihood of success in phishing attacks, as devices looking for known networks will automatically attempt to connect to the WiFi Pineapple.

### Recon Mode

The `WiFi Pineapple’s` **Recon Mode** helps identify nearby Wi-Fi networks and the devices connected to them. This allows attackers to target specific individuals or networks, making phishing attacks more precise and efficient.

### Honeypot Detection

`WiFi Pineapple` includes features that simulate a honeypot, luring attackers into a trap where their malicious activities can be detected. This can be useful for ethical hackers who want to test the security of their systems by observing how attackers behave.

### Legal Concerns

While the `WiFi Pineapple` is a powerful tool for penetration testing, it is important to remember that phishing, spoofing, and unauthorized access are illegal activities in many regions. Always ensure you have the proper permissions before using such tools in a live environment.

---

## Evil Portal Installation and Setup

Once you have fully set up your `WiFi Pineapple`, follow these steps to configure the Evil Portal for phishing attacks.

### Installation

1. **SSH into your `WiFi Pineapple`**:

```
ssh root@172.16.42.1  # Enter the password set during setup
```

2. **Install `Git` (if not already installed)**:

```
root@172.16.42.1~# opkg update && opkg install git
```

3. **Clone the Evil Portals repository into the /root directory**:

```
git clone https://github.com/kleo/evilportals.git
```

4. **Navigate to the portals directory to view available portal templates**:

```
cd evilportals/portals/
```

### Configuring Evil Portal

![image1](https://i.imgur.com/n8xSRlY.png)

- Once you’ve cloned the repository, navigate to the Evil Portal module on the `WiFi Pineapple` interface.
- Click Install to install the Evil Portal.
- Activate Evil Portal on Boot and select a pre-configured phishing template or create your own.
  ![image2](https://i.imgur.com/xDtkjwN.png)

---

### Conclusion

Phishing with the `WiFi Pineapple` is an effective technique for testing the security of Wi-Fi networks. By setting up rogue access points and injecting malicious content, attackers can harvest sensitive data from unsuspecting users. However, it is critical to follow ethical hacking practices and obtain explicit permission before using these techniques in a live environment.

By understanding how phishing attacks with the `WiFi Pineapple` work, security professionals can better defend against these threats and secure their networks from potential breaches.
