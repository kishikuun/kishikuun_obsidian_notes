```Bash
wfuzz -u "https://example.com/index.php?key=FUZZ" -w /path/ --hc 404 -t 10
```
- **Các options**:
    - --hc : ẩn status code (404, 403, ...)
    - --hl : ẩn các nội dung có length không ok
    - --sc : chỉ hiển thị
    - -t : số luồng (1 là default)