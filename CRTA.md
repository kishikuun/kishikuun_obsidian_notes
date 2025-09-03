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
