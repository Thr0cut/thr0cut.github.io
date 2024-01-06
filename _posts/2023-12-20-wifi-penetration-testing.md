---
title: "Wi-Fi Penetration Testing: WPA2/3 Attack Methodology"
excerpt: "A comprehensive secondary research dedicated to Wi-Fi security assessment."
header:
  teaser: /assets/images/wifi-penetration-testing-teaser.png
  og_image: /assets/images/wifi-penetration-testing-teaser.png
author_profile: true
share: false
tags:
  - wireless_networks
  - wifi
categories:
  - research
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

## Description

This secondary research is a collection of theoretical and practical materials gathered from various external sources (which will be listed in the "Resources" section) as well as the author's lab exercises. It is dedicated to attacks against WPA2 & WPA3 protocols as well as the general methodology of conducting Wi-Fi Penetration Testing. The article will be maintained and updated.

## Research Objective

Examine modern Wi-Fi security protocols, their flaws and possible attacks against them. Develop a knowledgebase and practical skills necessary to conduct Wi-Fi Penetration Testing.

## Wi-Fi Security Protocols

Wireless security is the prevention of unauthorized access or damage to computers or data using wireless networks, which include Wi-Fi networks. The term may also refer to the protection of the wireless network itself from adversaries seeking to damage the confidentiality, integrity, or availability of the network. As of today, there are 4 Wi-Fi Security Protocols available:

* Wired Equivalent Privacy (WEP)
(Now is obsolete due to major weaknesses in the encryption process)
* Wi-Fi Protected Access (WPA) / WPA Enterprise
* WPA2 / WPA2 Enterprise
* WPA3 / WPA3 Enterprise

## General Differences Between Protocols

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/DifferencesTable.png" alt="">
  <figcaption>Wi-FI Security Protocols differences table.</figcaption>
</figure>


## Wi-Fi Penetration Testing Methodology

Broadly, we can break up a wireless penetration testing exercise into the following phases:
* Planning
* Reconnaissance
* Attack
* Reporting

### Planning Phase

On this stage, we need to understand the following:

**Scope of the assessment**: the penetration tester should work with the client to define a scope that is achievable and will also provide the greatest amount of insight into the security of a network. Typically, the following information is gathered:

* Location of the penetration test
* Total coverage area of the premises
* Approximate number of access points and wireless clients deployed
* Which wireless networks are included in the assessment?
* Is exploitation in scope?
* Are attacks against users in scope?
* Is denial of service in scope?

**Effort estimation**: Based on the scope defined, the tester will then have to estimate how much time is required. Bear in mind that re-scoping may occur following this estimate, as organizations may have limited resources available in terms of both time and money.

**Legality**: Prior to performing a test, the client must give consent. This should explain the testing to be covered and clearly define the level of indemnity, insurance, and the limitations of the scope. If you are unsure, you will need to speak to a professional in these areas. Most organizations will have their own versions that will likely also incorporate a Non-Disclosure Agreement (NDA).

### Reconnaissance Phase

In this phase, the aim is to identify and apply characteristics to the wireless devices and wireless networks within the scope.

All the techniques to perform these briefly are:
* Enumerate visible and hidden wireless networks in the area;
* Enumerate devices in the area, along with those connected to the targeted networks;
* Map the range of the networks, where they are reachable from and whether there are places a malicious individual could operate from to perform an attack, for example, a café.

### Attack Phase

Once reconnaissance has been performed, exploitation must be performed for proof of concept. If the attack is being performed as part of a red team or wider assessment, then exploitation should be performed to gain access to the network as surreptitiously as possible.

### Reporting Phase

Finally, at the end of testing, it is necessary to report your findings to the client. It's important to ensure that the report matches the quality of your testing. As the client will only see the report, you have to give it as much love and attention as you do to your testing. The following is a guideline to the layout of the report:
* Management summary
* Technical summary
* Findings
* Remediation

## Attacks Against WPA2-PSK

In this research, the following attacks against the aforementioned protocol are reviewed:
* Cracking the 4-way handshake
* WPS PIN Bruteforce
* PMKID Dump

### WPA2-PSK: cracking the 4-way handshake

WPA/WPA2 PSK is vulnerable to a dictionary attack. The inputs required for this attack are the four-way WPA handshake between client and access point, and a wordlist that contains common passphrases. Then, using tools such as **Aircrack-ng**, we can try to crack the WPA/WPA2 PSK passphrase.

**WPA2-PSK: Authentication**

The goal of 4-way handshake is to generate a per-session key, called the Pairwise Transient Key **(PTK)**, using the **Pre-Shared Key** and five other parameters — **SSID** of Network, Authenticator Nounce (**ANounce**), Supplicant Nounce (**SNounce**), Authenticator MAC address (**Access Point MAC**), and Suppliant MAC address (**Wi-Fi Client MAC**). This key is then used to encrypt all data between the access point and client.

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/howhandshakeworks.png" alt="">
  <figcaption>4-way handshake illustration.</figcaption>
</figure>

**WPA2-PSK: PTK creation / cracking process**

WPA-PSK passphrase supplied by the user, along with the SSID, is sent through Password-Based Key Derivation Function (**PBKDF2**), which outputs the 256-bit shared key (also called **PMK** – Pairwise Master Key). The PTK will be used to verify the Message Integrity Check (**MIC**) in one of  the handshake packets. If it matches, then the guessed passphrase from the dictionary was correct.

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/crackingprocess.png" alt="">
  <figcaption>PTK creation / cracking illustration.</figcaption>
</figure>

**Attack steps:**

1. Put wireless card in monitor mode:

```bash
airmon-ng check kill && airmon-ng start wlan0
#=> kill interfering processes and enable monitor mode on the specified wireless interface
```

{:start="2"}
2. Identify the target:

```bash
wash -i wlan0
#=> scan for targets
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/recon.png" alt="">
  <figcaption>Available targets.</figcaption>
</figure>

{:start="3"}
3. Start capturing traffic for the target network:

```bash
airodump-ng –c 1 –bssid [AP MAC] –w capture wlan0
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/capturefornetwork.png" alt="">
  <figcaption>Traffic capture identified clients connected to our target network.</figcaption>
</figure>

{:start="4"}
4. De-authenticate / wait for a client to connect to capture a handshake:

```bash
aireplay-ng -0 1 -a [AP MAC] -v [CLIENT MAC] wlan0
#=> start de-authentication attack against a client connected to a network
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/deauth.png" alt="">
  <figcaption>Executing de-authentication attack.</figcaption>
</figure>

{:start="5"}
5. Crack the handshake:

If we succeed with de-authenticating a client, it will attempt to reconnect, which should enable us to capture the handshake (aireplay-ng would notify us of handshake capture by outputting "WPA handshake: [AP MAC]"). The following command was used to bruteforce the network’s password with a dictionary:

```bash
aircrack-ng –w /usr/share/wordlists/wifite.txt –b [AP MAC] capture-10.cap
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/aircrack-ng-bruteforce.png" alt="">
  <figcaption>Handshake cracked successfully.</figcaption>
</figure>

### WPA2-PSK: cracking WPS

Wireless Protected Setup (WPS) was introduced in 2006 to help users without wireless knowledge to have secure networks. The idea was that their Wi-Fi device would have a single hidden hardcoded value that would allow access with key memorization.

Why WPS is vulnerable:

- The WPS pin is only eight characters between 0-9. To start with, this provides
only 100,000,000 possibilities;

- Of the eight characters of the WPS pin, the last character is a checksum of the
previous seven and therefore predictable, leaving a maximum of 10,000,000 options;

- In addition, the first four and the following three of the remaining characters are
checked separately, which means that there are 11,000 options.

**Attack steps:**
(skipping 1&2 as they have been demonstrated previously)

1. Put wireless card in monitor mode;

2. Identify a target with WPS enabled;

3. Attempt to bruteforce WPS PIN (**Reaver**):

```bash
reaver -i <interface> -b <mac> -vv
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/reaverwpsbruteforce.png" alt="">
  <figcaption>Executing WPS bruteforce attack with Reaver.</figcaption>
</figure>

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/reaverwpscrackresult.png" alt="">
  <figcaption>WPS PIN cracked successfully.</figcaption>
</figure>

```bash
reaver -i <interface> -b <mac> -vv <PIN>
#=> Authenticate to the network using the cracked WPS PIN
```

### WPA2-PSK: PMKID Dump

\
**PMK Caching and PMKID**

**Access Point roaming** refers to a scenario where a client or a supplicant moves outside the range of an AP and/or connects to another AP. Very similar to handoffs in cellular networks, this roaming can often take a toll on connectivity given every time a client moves out from the range of an AP and moves to other, 4-way handshake will be done again. To make this handoff lag-free, we have a feature called **PMK caching**. Many routers cache **PMKID** so that the next time client re-authenticates without the handshake. Routers with this feature enabled advertise PMKID in the **EAPOL** frame. An attacker can dump it and perform a bruteforce attack against it to guess the **PMK** required to authenticate in the network.

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/PMKID.png" alt="">
  <figcaption>PMKID generation process.</figcaption>
</figure>

**Attack steps:**
(skipping 1&2 as they have been demonstrated previously)

1. Put wireless card in monitor mode;

2. Identify a target with PMKID caching enabled;

3. Attempt to dump PMKID (**hcxdumptool**):

```bash
hcxdumptool –o <filename> <interface> --enable_status=1 –filterlist_ap=<file with target MAC> --filtermode=2
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/hcxdumptool.png" alt="">
  <figcaption>Dump PMKID from target AP.</figcaption>
</figure>

{:start="4"}
4. Crack PMKID (**hcxpcaptool**, **Hashcat**):

```bash
hcxdumptool –o <filename> <interface> --enable_status=1 –filterlist_ap=<file with target MAC> --filtermode=2
#=> Convert dumped hash to Hashcat-readable format
```

```bash
hashcat -m 16800 --force <hashfile> <wordlist> –show
#=> Crack the hash with Hashcat
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/hashcat.png" alt="">
  <figcaption>Result of the commands above, the passphrase is cracked.</figcaption>
</figure>

## Attacks Against WPA2-Enterprise

In this research, the following attacks against the aforementioned protocol are reviewed:

* Evil Twin (Stealing Credentials);
* Online Bruteforce.

**WPA2-Enterprise: Authentication:**

WPA-Enterprise, also referred to as WPA-EAP or WPA-802.1X, uses EAP to delegate the authentication to a RADIUS server. **Extensible Authentication Protocol** provides a standardized set of functions and rules to specific authentication protocol implementations known as EAP methods (can be **certificate-based** and **credential-based**):

* EAP-TLS - the original IETF open standard EAP authentication protocol, widely supported, only allows certificate-based authentication;
* PEAP - encapsulates EAP within a TLS tunnel (rather an encapsulation than a method), developed by Microsoft, Cisco and RSA Security);
* EAP-TTLS - TLS extension to provide EAP over a TLS tunnel, widely supported (except by Microsoft);
* LEAP - developed by Cisco prior to the standard, no native Microsoft support, deprecated;
* EAP-FAST - Cisco replacement for LEAP.

The most commonly used EAP implementations are EAP-PEAP and EAP-TTLS. Since they’re very similar to one another from a technical standpoint, we’ll be focusing primarily on EAP-PEAP. PEAP uses server-side certificates for validation of the RADIUS server. Almost all attacks on PEAP leverage misconfigurations in certificate validation.

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/PEAP.png" alt="">
  <figcaption>EAP-PEAP authentication process.</figcaption>
</figure>

### WPA2-Enterprise: Evil Twin (Stealing Credentials)

The attack consists of creating a rogue access point mimicking the targeted ESSID in order to get clients to perform the phase 2 authentication process with your rogue RADIUS server. Thus, allowing you to capture the cleartext credentials or challenge-response used during inner authentication.

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/evil-twin.png" alt="">
  <figcaption>Attack illustration.</figcaption>
</figure>

**Will not work** against clients configured to:
- use a certificate-based authentication (s.a. EAP-TLS or PEAP with EAP-TLS), since there is no credentials to steal;
- validate the server certificate during phase 1 authentication, which prevents phase 2 authentication to happen.

**Attack steps:**
(skipping 1&2 as they have been demonstrated previously)

1. Put wireless card in monitor mode;
2. Identify a target;
3. Create an Evil Twin (**eaphammer**):

```bash
./eaphammer --cert-wizard
#=> Create a self-signed certificate
./eaphammer --bssid [MAC] --essid <Name> --channel 2 --wpa 2 --auth peap --interface wlan0 –creds
#=> Create an Evil Twin for the target network
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/evil-twin-creation.png" alt="">
  <figcaption>Result of the commands above.</figcaption>
</figure>

{:start="4"}
4. Capture RADIUS credentials (challenge / response):

Provided you can overpower the signal strength of the target access point (or due to DoS), clients will begin to disconnect from the target network and connect to your access point. Unless the affected client devices are configured to reject invalid certificates, the victims of the attack will be presented with a message similar to the one below:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/evil-twin-certificate.png" alt="">
</figure>

{:start="5"}
5. Crack received credentials (**asleap**):

Fortunately, it’s usually possible to find at least one enterprise employee who will blindly accept your certificate. It’s also common to encounter devices that are configured to accept invalid certificates automatically. In either case, you’ll soon see usernames, challenges, and responses shown in your terminal as shown below:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/evil-twin-creds.png" alt="">
</figure>

```bash
asleap –C <challenge> -R <response> -W <wordlist>
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/evil-twin-cracked.png" alt="">
  <figcaption>Recovered password.</figcaption>
</figure>

To harvest credentials in clear text, we could use other techniques of Evil Twin attacks, for example, **EAP-downgrade** or **Captive Portal**.

### WPA2-Enterprise: Online Bruteforce

Online bruteforce attacks against WPA-Enterprise appear to be overlooked, if not unheard of, in the current literature on wireless network security and in the security community in general. Although WPA-Enterprise is often considered “more secure” than WPA-PSK, it also has a much larger attack surface. While WPA-PSK networks have only one valid password, there may be thousands of valid username and password combinations which grant access to a single WPA-Enterprise network. Further, passwords used to access WPA Enterprise networks are commonly selected by end users, many of whom select extremely common passwords.

For this attack, we can use a tool called **Airhammer**.

**Attack steps:**
(skipping 1,2&3)

1. Put wireless card in monitor mode;
2. Identify a target;
3. Generate lists with usernames / passwords;
4. Discover valid credentials:

```bash
./air-hammer.py -i wlan0 -e <ESSID> -u <username / list> -P <password /list> -1
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/airhammer-bruteforce.png" alt="">
  <figcaption>Valid credentials found.</figcaption>
</figure>

Since WPA-Enterprise credentials are often Domain User credentials, use the discovered credentials to access additional systems on the internal network and begin additional attacks.

## WPA3 Overview

In January 2018, the Wi-Fi Alliance announced WPA3 as a replacement to WPA2. The new standard uses 128-bit encryption in WPA3-Personal mode (WPA-SAE, pre-shared key) or 192-bit in WPA3 – Enterprise (RADIUS authentication server).

WPA3 is much harder to attack because of its modern key establishment protocol called “Simultaneous Authentication of Equals” (**SAE**) or the **Dragonfly** Key Exchange. SAE improves security of the initial key exchange and offers better protection against offline dictionary-based attacks. Other notable security features of WPA3 include **Management Frame Protection** or MFP (encrypts management frames and prevents unauthorized communication from external sources), **Perfect Forward Secrecy** (new session keys are generated continuously, preventing decryption of previous communications) and DPP (**Device Provisioning Protocol**, a replacement to WPS) which enables new devices to connect using QR codes.

**WPA3 Flaws**

So far, deep technical details regarding discovered WPA3 vulnerabilities are shared strictly with the developer (Wi-Fi Alliance) and vendors. As consequence, professional tools for WPA3 assessment have not yet been developed; only PoC scripts provided by the researchers exist (can be found on Mathy Vanhoef’s page: https://wpa3.mathyvanhoef.com).

### WPA3-Transition Downgrade Attack

Though it appears to be difficult finding detailed materials covering WPA3 attacks online, in scope of this research I was able to find a detailed article featuring the Downgrade attack on a router with enabled **WPA3-Transition** (backwards compatibility) feature.

The attack is based on **Evil Twin** technique. If a client is connected to a wireless router via WPA3, and the router has **WPA3-Transition** feature enabled, an attacker can create a fake WPA2 access point, force the client to connect to it via WPA2, capture the handshake and crack the Wi-Fi network’s password.

**Attack demonstration:**

1. Configure a Wireless Access Point to use WPA3-Personal with WPA3-Transition feature (backwards compatibility):

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/wpa3-downgrade-confirm.png" alt="">
  <figcaption>Creating an AP with required config and confirming with Airmon-ng.</figcaption>
</figure>

{:start="2"}
2. Wait for a client to connect:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/wpa3-client-connected.png" alt="">
</figure>

{:start="3"}
3. Start a rogue AP with hostapd with the following configuration file:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/wpa3-rogue-ap.png" alt="">
  <figcaption>Creating a rogue AP with hostapd and verifying with airodump-ng.</figcaption>
</figure>

{:start="4"}
4. De-authenticate a client and capture WPA2-handshake:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/wpa3-handshake.png" alt="">
</figure>

{:start="5"}
5. Crack the handshake:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/wifi-penetration-testing/wpa3-cracked.png" alt="">
  <figcaption>Password cracked with aircrack-ng.</figcaption>
</figure>

## Mitigation

For wireless attacks reviewed in this research, the following mitigation recommendations are available:


1. Use WPA3 as your Wi-Fi network security protocol, avoiding mixed (WPA3+WPA2) modes / WPA3-Transition feature;

2. Regularly **update firmware** on routers/APs and network clients;

3. Implement **strong password / credentials** policy;

4. Disable vulnerable features (i.e. **WPS & PMKID caching** for WPA2, **WPA3-Transition** for WPA3);

5. Disable **autoconnect** on client devices.

## Conclusions

Over the course of this research, Wi-Fi security concepts and common attacks against Wi-Fi networks were analyzed. The presented materials should enable the reader to build the knowledgebase and practical skills necessary to conduct wireless security assessments.
Wi-Fi networks are a dangerous attack surface that can provide an adversary with a solid foothold in an organization’s infrastructure, yet wireless security is often neglected by business owners (and by people overall). As we conduct penetration tests, it is our responsibility to highlight the importance of this topic as well as educate our clients on implementing the best security practices in order to mitigate wireless attacks and improve the overall defense of their infrastructure.

## Resources

**Books:**

* Kali Linux  Wireless Penetration Testing – Beginner’s Guide
* Mastering Kali Linux Wireless Penetration Testing
* Mastering Kali Linux for Advanced Penetration Testing
* Advanced Wireless Attacks Against Enterprise Networks

**Articles:**

* Wi-Fi Pentesting Guide - [(https://github.com/ricardojoserf/wifi-pentesting-guide](https://github.com/ricardojoserf/wifi-pentesting-guide)
* Pentesting Wi-Fi (Hacktricks) - [https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-wifi](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-wifi)
* Wireless Penetration Testing: PMKID Attack -  [https://www.hackingarticles.in/wireless-penetration-testing-pmkid-attack/](https://www.hackingarticles.in/wireless-penetration-testing-pmkid-attack/)
* DRAGONBLOOD - Analysing WPA3's Dragonfly Handshake (Mathy Vanhoef) - [https://wpa3.mathyvanhoef.com/#intro](https://wpa3.mathyvanhoef.com/#intro)
* WPA3 Downgrade Attack - [http://www.netprojnetworks.com/wpa3-downgrade-attack/](http://www.netprojnetworks.com/wpa3-downgrade-attack/)

**Presentations:**
* Attacking WPA3: New Vulnerabilities and Exploit Framework (Mathy Vanhoef) - [link](https://conference.hitb.org/hitbsecconf2022sin/materials/D1T1%20-%20Attacking%20WPA3%20-%20New%20Vulnerabilities%20and%20Exploit%20Framework%20-%20Mathy%20Vanhoef.pdf)





**Thank you for your attention and happy hacking!**
{: .notice--primary}
