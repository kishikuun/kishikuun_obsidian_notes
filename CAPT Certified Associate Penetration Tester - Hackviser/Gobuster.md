
| **vhost**                                    | **DNS**                                   |
| -------------------------------------------- | ----------------------------------------- |
| - Tìm vhost ẩn                               | - Tìm subdomain có trong DNS              |
| - Webserver hỗ trợ vhost (Apach, Nginx, ...) | - Có DNS phân giải domain                 |
| - http/s (80/443)                            | - DNS (53)                                |
| - Có IP  <br>- Biết server có vhost ẩn       | - Có domain thật  <br>- Cần tìm subdomain |

# Directory & File Scanning (Dir mode)

```Bash
gobuster dir -u http://example.com -w /path/to/wordlist.txt -x php,html -s 200,403
```

- **Các options**:
    - -x : mở rộng quét file
    - -s : status code
    - -t : luồng
    - --exclude-length 1542 : loại bỏ các phản hồi có kích thước khác nhau

> Tips: + Quét từ “**/**” sẽ tốt hơn  
> + Đọc robots.txt và sitemap.xml

---

# Subdomain Enumeration (DNS)

```Bash
gobuser dns -d example.com -w /path/to/wordlist.txt
```

> **Lưu ý**: Cần domain cụ thể (không dùng IP)

---

# vhost

```Bash
gobuser VHOST -u http://example.com -w /path/to/wordlist.txt
```

> **Lưu ý**: Cần IP