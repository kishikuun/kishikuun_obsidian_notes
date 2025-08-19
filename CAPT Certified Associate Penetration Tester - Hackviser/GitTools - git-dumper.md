> [!important] Git Source Leak là khi dev do quên hoặc lỗi mà không xóa .git folder khi deploy web, hoặc đặt .git/ ở sai nơi (public webroot). Dẫn đến attacker có thể tải về toàn bộ repo, xem lịch sử commit, file đã xóa, …

> [!important]
> 
> ## Tổng kết các bước exploit qua lab hackviser:
> 
> Phát hiện .git bị lộ ⇒ Dùng git-dumper tải toàn bộ repo của target ⇒ Phân tích ⇒ Phát hiện file id rsa, kết hợp với bước phân tích mã nguồn, nmap thì ssh vào được target với root ⇒ Trích xuất password hash ⇒ Thỏa mãn đề.
> 
> > ***Lưu ý thêm**: có thể kiểm tra cả git logs, git diff, git show để tìm thông tin nhạy cảm.

**Dấu hiệu**: http://target.com/.git
/.git/config
/.git/HEAD
/.git/index
⇒ Có trả về Git (plaintext, binary, config, ...)

---
# GitTools
## Install
```Bash
git clone https://github.com/internetwache/GitTools.git
```
```Bash
cd GitTools/Dumper
```

## Syntax
```Bash
./gitdumper.sh http://target.com/.git ~ /Desktop/dumper
```
> **Lưu ý**: file gitdumper.sh có thể bị đổi tên